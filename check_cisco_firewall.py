#!/opt/rh/rh-python38/root/usr/bin/python3

#
# Nagios plugin to check a Cisco firewall (ASA / FTD / Secure Firewall 3100) via SNMP.
#
# Usage: check_cisco_firewall.py -H/--hostname <network-component>
#            ( -C/--community <snmp-community> | --user <snmpv3-user> [--seclevel noAuthNoPriv|authNoPriv|authPriv]
#              [--auth <auth-protocol>] [--authpw <auth-password>] [--priv <priv-protocol>] [--privpw <priv-password>] )
#            [ -t/--timeout <seconds> ] [ -v/--verbose ] [ --html-table ]
#            --mode ha_summary|ha_pair|cpu|memory|connections|uptime|primary_state|secondary_state|sysinfo|hardware|interfaces
#            [ --peer-hostname <network-component> ]
#            [ -w/--warning <threshold> ] [ -c/--critical <threshold> ]
#
# Modes:
#   ha_summary          - HA state of the primary/secondary hardware units (cfwHardwareStatusValue)
#   ha_pair             - dual-query reachability check: queries both --hostname and --peer-hostname and
#                          requires both to respond, agree with each other, and report a failover-safe
#                          numeric state (9=Active or 10=Standby Ready) for the pair. If --peer-hostname
#                          is omitted, the peer is guessed from --hostname using the +/-2-last-octet IPv4
#                          convention observed in this environment (e.g. .226/.228) and confirmed by
#                          querying it; if no candidate can be confirmed, exits WARNING rather than
#                          guessing blindly - pass --peer-hostname explicitly in that case. Output
#                          best-effort labels which IP is Primary/Secondary using cfwHardwareInformation's
#                          self-referential "(this device)" text, when the platform populates it
#   cpu                 - average CPU load (5s/1m/5m); --warning/--critical are percent (default 80/90)
#   memory              - system/data-plane memory pool usage; --warning/--critical are percent (default 80/90)
#   connections         - current in-use connections; --warning/--critical are connection counts
#   uptime              - sysUpTime since last reboot; --warning/--critical are minimum seconds (optional)
#   primary_state       - combined text role and numeric HA state of the primary unit (cfwHardwareStatusDetail/Value index 6);
#                          same result regardless of which paired unit's IP is queried
#   secondary_state      - combined text role and numeric HA state of the secondary unit (cfwHardwareStatusDetail/Value index 7);
#                          same result regardless of which paired unit's IP is queried
#   sysinfo             - hardware description, hostname and chassis model (sysDescr, sysName, entPhysicalModelName)
#   hardware            - fan tray / power supply operational status (cefcFanTrayOperStatus, cefcFRUPowerOperStatus)
#   interfaces          - admin/oper status, link speed and error/discard counters of all real
#                          interfaces, excluding ASA-internal pseudo-interfaces (ifName, ifAdminStatus,
#                          ifOperStatus, ifHighSpeed, ifIn/OutErrors, ifIn/OutDiscards)

import argparse
import copy
import html
import os
import re
import sys
from ves_snmp_utils import OIDS, NAGIOS_STATUS, pysnmp_get, pysnmp_walk_indexed, pysnmp_walk_multi_indexed, snmp_value_to_str

IPV4_PATTERN = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

# Observed convention in this environment: paired HA units' management IPs differ by 2 in the
# last octet (e.g. .226/.228, .227/.229). Used only as a best-effort fallback for --mode ha_pair
# when --peer-hostname isn't supplied - any guessed candidate is always confirmed via a live SNMP
# cross-query before being trusted, never assumed blindly.
PEER_IP_OFFSET_CANDIDATES = (2, -2)

# CISCO-FIREWALL-MIB Hardware textual convention indices used by cfwHardwareStatusTable
HW_INDEX_PRIMARY = 6
HW_INDEX_SECONDARY = 7

# CISCO-FIREWALL-MIB HardwareStatus textual convention
HARDWARE_STATUS_MAP = {
    1: "other", 2: "up", 3: "down", 4: "error", 5: "overTemp",
    6: "busy", 7: "noMedia", 8: "backup", 9: "active", 10: "standby",
}

# Peer HA state machine values reported on the secondary/peer cfwHardwareStatusValue instance
# (platform-specific extension beyond the base HardwareStatus textual convention)
PEER_NUMERIC_STATE_MAP = {
    9: ("Active", True),
    10: ("Standby Ready", True),
    11: ("Standby Cold", False),
    12: ("Failed", False),
}

# ENTITY-MIB PhysicalClass values used to identify fan / power supply / chassis entries
# (more reliable than matching keywords in entPhysicalDescr, which is inconsistent/truncated
# across platforms, e.g. Secure Firewall 3100 PSU descr doesn't contain "psu"/"power supply")
ENT_PHYSICAL_CLASS_CHASSIS = 3
ENT_PHYSICAL_CLASS_POWER_SUPPLY = 6
ENT_PHYSICAL_CLASS_FAN = 7

# CISCO-ENTITY-FRU-CONTROL-MIB cefcFanTrayOperStatus (ENTITY-STATE-MIB's entStateOper is not
# populated on ASA/FTD/Secure Firewall platforms, so this MIB is used for fan tray status instead)
FAN_TRAY_STATUS_MAP = {1: "unknown", 2: "up", 3: "down", 4: "warning"}
# NOTE: production Secure Firewall 3100 / FTD 7.4.2 units have been observed consistently
# reporting "down" for the fan tray even when the hardware is otherwise healthy, so it's
# treated as WARNING rather than CRITICAL here to avoid a permanently-alerting check.
FAN_TRAY_STATUS_SEVERITY = {1: 1, 2: 0, 3: 1, 4: 2}

# CISCO-ENTITY-FRU-CONTROL-MIB cefcFRUPowerOperStatus (PowerOperType)
FRU_POWER_OPER_STATUS_MAP = {
    1: "offEnvOther", 2: "on", 3: "offAdmin", 4: "offDenied", 5: "offEnvPower",
    6: "offEnvTemp", 7: "offEnvFan", 8: "failed", 9: "onButFanFail", 10: "offCooling",
    11: "offConnectorRating", 12: "onButInlinePowerFail",
}
FRU_POWER_OPER_STATUS_OK = 2  # "on"

# ASA/FTD-internal pseudo-interfaces present on every unit regardless of configuration; excluded
# since they're not real monitored links. Interface naming for everything else (nameif) varies
# significantly across firewall pairs/models, so a fixed named interface list isn't practical -
# every other interface reported by SNMP is monitored dynamically instead.
NOISE_IFNAME_PATTERNS = ("internal-data", "nlp_int_tap", "ccl_ha_nlp_int_tap", "ha_ctl_nlp_int_tap", "ethernet1/4")


def _is_missing(value):
    """True if an SNMP GET returned a 'no such instance/object' style value."""
    return "no such" in snmp_value_to_str(value).lower()


def _snmp_get_or_exit(args, oid):
    """pysnmp_get(), printing the Nagios status line and exiting the process on failure."""
    value, rc = pysnmp_get(args, oid)
    if rc != 0:
        print(value)
        sys.exit(rc)
    return value


def _snmp_walk_or_exit(args, oid):
    """pysnmp_walk_indexed(), printing the Nagios status line and exiting the process on failure."""
    result, rc = pysnmp_walk_indexed(args, oid)
    if rc != 0:
        print(result)
        sys.exit(rc)
    return result


def _snmp_walk_multi_or_exit(args, oid):
    """pysnmp_walk_multi_indexed(), printing the Nagios status line and exiting the process on failure."""
    result, rc = pysnmp_walk_multi_indexed(args, oid)
    if rc != 0:
        print(result)
        sys.exit(rc)
    return result


def _render_table(args, headers, rows, bad_row_mask=None):
    """Render a headers/rows table as plain ljust+pipe-delimited text (default, CLI/SSH-friendly) or
    as an HTML <table> when --html-table is set (for Thruk instances with cgi.cfg escape_html_tags=0).
    Values are html-escaped in the HTML branch since they may originate from device-supplied SNMP data
    (ifAlias, entPhysicalDescr, etc.), which isn't a trusted source. bad_row_mask, if given, marks rows
    (e.g. DOWN interfaces, not-OK components) to highlight in the HTML table."""
    if not args.html_table:
        widths = [max(len(header), *(len(row[i]) for row in rows)) for i, header in enumerate(headers)]
        table = [" | ".join(h.ljust(w) for h, w in zip(headers, widths))]
        table += [" | ".join(v.ljust(w) for v, w in zip(row, widths)) for row in rows]
        return "\n".join(table)

    bad_row_mask = bad_row_mask or [False] * len(rows)
    lines = ['<table border="1" cellpadding="3" cellspacing="0">',
             "<tr>" + "".join(f"<th>{html.escape(h)}</th>" for h in headers) + "</tr>"]
    for row, bad in zip(rows, bad_row_mask):
        style = ' style="background-color:#f8d7da"' if bad else ""
        lines.append(f"<tr{style}>" + "".join(f"<td>{html.escape(v)}</td>" for v in row) + "</tr>")
    lines.append("</table>")
    return "\n".join(lines)


def _chunk_evenly(values, n):
    """Split a list into n roughly-equal contiguous chunks (extra items go to the earliest chunks)."""
    if n <= 0:
        return []
    size, remainder = divmod(len(values), n)
    chunks, start = [], 0
    for i in range(n):
        end = start + size + (1 if i < remainder else 0)
        chunks.append(values[start:end])
        start = end
    return chunks


def _group_sensor_readings(sensor_types, sensor_values, sensor_scales):
    """Best-effort grouping of CISCO-ENTITY-SENSOR-MIB readings on this platform.
    entPhysicalContainedIn does not extend to the sensor indices here, so there is no
    MIB-guaranteed way to attribute a reading to a specific named fan/PSU. Empirically,
    each PSU's electrical block starts with a voltsAC/voltsDC reading (amps/watts/temp/
    internal-fan-rpm follow); RPM readings found outside of a PSU block are chassis fan
    tachometers. Returns (chassis_fan_rpms, psu_voltages), both ascending-index-ordered
    lists to be distributed across the fan tray / PSU rows found via
    cefcFanTrayOperStatus / cefcFRUPowerOperStatus.
    """
    items = sorted(
        (idx, int(sensor_types[idx]), int(sensor_values[idx]), int(sensor_scales.get(idx, 9)))
        for idx in sensor_types if idx in sensor_values
    )

    def actual(raw, scale):
        return raw * (10 ** ((scale - 9) * 3))

    consumed_rpm_idx = set()
    psu_voltages = []
    i = 0
    while i < len(items):
        idx, sensor_type, raw, scale = items[i]
        if sensor_type in (3, 4):  # voltsAC / voltsDC starts a new PSU electrical block
            psu_voltages.append(actual(raw, scale))
            i += 1
            while i < len(items) and items[i][1] not in (3, 4, 12):
                if items[i][1] == 10:
                    consumed_rpm_idx.add(items[i][0])
                i += 1
        else:
            i += 1

    chassis_fan_rpms = [
        actual(raw, scale) for idx, sensor_type, raw, scale in items
        if sensor_type == 10 and idx not in consumed_rpm_idx
    ]
    return chassis_fan_rpms, psu_voltages


def _hw_status_label(numeric):
    """Resolve a cfwHardwareStatusValue reading to a display label, preferring the more
    specific peer HA state machine labels (11=Standby Cold, 12=Failed) over generic "unknown"."""
    if numeric in (11, 12):
        return PEER_NUMERIC_STATE_MAP[numeric][0].lower()
    return HARDWARE_STATUS_MAP.get(numeric, "unknown")


def check_ha_summary(args):
    oid = OIDS["cfwHardwareStatusValue"]

    primary = _snmp_get_or_exit(args, f"{oid}.{HW_INDEX_PRIMARY}")
    secondary = _snmp_get_or_exit(args, f"{oid}.{HW_INDEX_SECONDARY}")

    if _is_missing(primary) and _is_missing(secondary):
        print("UNKNOWN - Failover is not configured on this unit (standalone)")
        sys.exit(3)

    primary_state = "not present" if _is_missing(primary) else _hw_status_label(int(primary))
    secondary_state = "not present" if _is_missing(secondary) else _hw_status_label(int(secondary))
    states = [primary_state, secondary_state]

    bad_states = {"down", "error", "overTemp", "noMedia", "unknown", "not present", "standby cold", "failed"}
    active_count = states.count("active")
    standby_count = states.count("standby")

    if any(s in bad_states for s in states):
        exit_code, label = 2, "CRITICAL"
    elif active_count == 0:
        exit_code, label = 2, "CRITICAL - No active unit"
    elif active_count > 1 or standby_count > 1:
        exit_code, label = 2, "CRITICAL - Split-brain detected"
    elif "backup" in states or "busy" in states or "other" in states:
        exit_code, label = 1, "WARNING"
    else:
        exit_code, label = 0, "OK"

    perf = f"primary_state={int(primary) if not _is_missing(primary) else 99};;;; " \
           f"secondary_state={int(secondary) if not _is_missing(secondary) else 99};;;;"

    # both slots' states are already known from this one query, so the queried IP's own
    # active/standby status can be read off directly once its slot is identified
    queried_role = _determine_unit_role(args, args.hostname)
    queried_state = primary_state if queried_role == "primary" else secondary_state if queried_role == "secondary" else None
    role_note = f" [{args.hostname} = {queried_role} unit, currently {queried_state}]" if queried_role else ""

    print(f"{label} - Primary: {primary_state}, Secondary: {secondary_state}{role_note} | {perf}")
    sys.exit(exit_code)


def _query_pair_state(args, host):
    """GET cfwHardwareStatusValue for both primary(6)/secondary(7) indices from a specific host,
    reusing the same SNMP credentials as args. Returns (primary, secondary, rc, error_message)."""
    host_args = copy.copy(args)
    host_args.hostname = host

    primary, rc = pysnmp_get(host_args, f"{OIDS['cfwHardwareStatusValue']}.{HW_INDEX_PRIMARY}")
    if rc != 0:
        return None, None, rc, primary

    secondary, rc = pysnmp_get(host_args, f"{OIDS['cfwHardwareStatusValue']}.{HW_INDEX_SECONDARY}")
    if rc != 0:
        return None, None, rc, secondary

    return primary, secondary, 0, None


def _guess_peer_candidates(hostname):
    """Best-effort peer IP candidates from the +/-2-last-octet convention observed in this
    environment. Returns [] if hostname isn't a plain IPv4 address (heuristic doesn't apply)."""
    match = IPV4_PATTERN.match(hostname)
    if not match:
        return []
    octets = [int(o) for o in match.groups()]
    candidates = []
    for offset in PEER_IP_OFFSET_CANDIDATES:
        last = octets[3] + offset
        if 0 <= last <= 255:
            candidates.append(".".join(str(o) for o in octets[:3]) + f".{last}")
    return candidates


def _discover_peer(args, local_primary, local_secondary):
    """Try each IP-heuristic candidate in turn, returning (peer_host, peer_primary, peer_secondary)
    for the first one that is reachable AND agrees with the local unit's reported state, or None
    if no candidate could be confirmed."""
    for candidate in _guess_peer_candidates(args.hostname):
        peer_primary, peer_secondary, rc, _ = _query_pair_state(args, candidate)
        if rc != 0 or any(_is_missing(v) for v in (peer_primary, peer_secondary)):
            continue
        peer_primary, peer_secondary = int(peer_primary), int(peer_secondary)
        if peer_primary == local_primary and peer_secondary == local_secondary:
            return candidate, peer_primary, peer_secondary
    return None


def _determine_unit_role(args, host):
    """Best-effort: identify whether `host` itself is the primary or secondary unit by checking
    cfwHardwareInformation (free text) at the primary(6)/secondary(7) instances for the literal
    "(this device)" marker Cisco includes only on the row matching the unit that actually answered
    the query - unlike cfwHardwareStatusValue/Detail, this text is not mirrored pair-wide. Returns
    "primary"/"secondary", or None if undeterminable (OID not populated on this platform, unreachable,
    or neither instance is self-marked)."""
    host_args = copy.copy(args)
    host_args.hostname = host
    for hw_index, role in ((HW_INDEX_PRIMARY, "primary"), (HW_INDEX_SECONDARY, "secondary")):
        info, rc = pysnmp_get(host_args, f"{OIDS['cfwHardwareInformation']}.{hw_index}")
        if rc == 0 and not _is_missing(info) and "this device" in snmp_value_to_str(info).lower():
            return role
    return None


def check_ha_pair(args):
    """Cross-check HA state by independently querying both paired units' IPs, requiring both to
    be reachable, agree on the pair's state, and report a failover-safe numeric state (9/10).
    If --peer-hostname isn't given, the peer is guessed via _discover_peer() and confirmed by a
    live query before being trusted; if no candidate can be confirmed, exits WARNING instead of
    guessing blindly."""
    local_primary, local_secondary, rc, err = _query_pair_state(args, args.hostname)
    if rc != 0:
        print(f"CRITICAL - Unit {args.hostname} unreachable via SNMP: {err}")
        sys.exit(2)
    if any(_is_missing(v) for v in (local_primary, local_secondary)):
        print(f"UNKNOWN - Failover is not configured on {args.hostname}")
        sys.exit(3)
    local_primary, local_secondary = int(local_primary), int(local_secondary)

    auto_detected = False
    peer_hostname = args.peer_hostname
    if peer_hostname:
        peer_primary, peer_secondary, rc, err = _query_pair_state(args, peer_hostname)
        if rc != 0:
            print(f"CRITICAL - Peer unit {peer_hostname} unreachable via SNMP: {err}")
            sys.exit(2)
        if any(_is_missing(v) for v in (peer_primary, peer_secondary)):
            print(f"UNKNOWN - Failover is not configured on peer unit {peer_hostname}")
            sys.exit(3)
        peer_primary, peer_secondary = int(peer_primary), int(peer_secondary)
    else:
        discovered = _discover_peer(args, local_primary, local_secondary)
        if discovered is None:
            candidates = _guess_peer_candidates(args.hostname)
            tried = f"tried {', '.join(candidates)}" if candidates else \
                "no candidates - hostname is not a plain IPv4 address"
            print(
                f"WARNING - Could not auto-detect an HA peer for {args.hostname} ({tried} via the "
                "+/-2 last-octet convention); pass --peer-hostname explicitly to enable this check"
            )
            sys.exit(1)
        peer_hostname, peer_primary, peer_secondary = discovered
        auto_detected = True

    if local_primary != peer_primary or local_secondary != peer_secondary:
        print(
            f"CRITICAL - HA pair state mismatch: {args.hostname} reports primary={local_primary}/"
            f"secondary={local_secondary}, {peer_hostname} reports primary={peer_primary}/"
            f"secondary={peer_secondary} (units do not see each other consistently)"
        )
        sys.exit(2)

    primary_label, primary_safe = PEER_NUMERIC_STATE_MAP.get(local_primary, ("Forming/Unknown", False))
    secondary_label, secondary_safe = PEER_NUMERIC_STATE_MAP.get(local_secondary, ("Forming/Unknown", False))

    exit_code = 0 if (primary_safe and secondary_safe) else 2
    status = NAGIOS_STATUS[exit_code]
    perf = f"primary_state={local_primary};;;; secondary_state={local_secondary};;;;"
    peer_note = f" (peer {peer_hostname} auto-detected via IP heuristic)" if auto_detected else ""

    hostname_role = _determine_unit_role(args, args.hostname)
    peer_role = _determine_unit_role(args, peer_hostname)
    primary_ip = args.hostname if hostname_role == "primary" else peer_hostname if peer_role == "primary" else None
    secondary_ip = args.hostname if hostname_role == "secondary" else peer_hostname if peer_role == "secondary" else None
    primary_ip_note = f" [{primary_ip}]" if primary_ip else ""
    secondary_ip_note = f" [{secondary_ip}]" if secondary_ip else ""

    print(
        f"{status} - Both units reachable and agree: Primary{primary_ip_note}: {primary_label} ({local_primary}), "
        f"Secondary{secondary_ip_note}: {secondary_label} ({local_secondary}){peer_note} | {perf}"
    )
    sys.exit(exit_code)


def check_cpu(args, warning, critical):
    cpu_oids = {
        "5s": OIDS["cpmCPUTotal5secRev"],
        "1m": OIDS["cpmCPUTotal1minRev"],
        "5m": OIDS["cpmCPUTotal5minRev"],
    }

    averages = {}
    for label, oid in cpu_oids.items():
        result = _snmp_walk_or_exit(args, oid)
        if not result:
            print(f"UNKNOWN - No CPU data returned for {label} average")
            sys.exit(3)
        values = [int(v) for v in result.values()]
        averages[label] = round(sum(values) / len(values), 1)

    if averages["5m"] >= critical:
        exit_code = 2
    elif averages["5m"] >= warning:
        exit_code = 1
    else:
        exit_code = 0

    status = NAGIOS_STATUS[exit_code]
    summary = f"{status} - CPU usage: 5s={averages['5s']}%, 1m={averages['1m']}%, 5m={averages['5m']}%"
    perf = (
        f"cpu_5s={averages['5s']}%;;;0;100 "
        f"cpu_1m={averages['1m']}%;;;0;100 "
        f"cpu_5m={averages['5m']}%;{warning};{critical};0;100"
    )
    print(f"{summary} | {perf}")
    sys.exit(exit_code)


def check_memory(args, warning, critical):
    # CISCO-MEMORY-POOL-MIB (single-indexed by pool type) is used on classic ASA;
    # newer ASA/FTD/Secure Firewall platforms only populate CISCO-ENHANCED-MEMPOOL-MIB instead.
    names = _snmp_walk_or_exit(args, OIDS["ciscoMemPoolName"])
    used = _snmp_walk_or_exit(args, OIDS["ciscoMemPoolUsed"])
    free = _snmp_walk_or_exit(args, OIDS["ciscoMemPoolFree"])

    if not names:
        names = _snmp_walk_multi_or_exit(args, OIDS["cempMemPoolName"])
        used = _snmp_walk_multi_or_exit(args, OIDS["cempMemPoolUsed"])
        free = _snmp_walk_multi_or_exit(args, OIDS["cempMemPoolFree"])

    # Prefer the overall system/data-plane memory pool; fall back to the first pool reported
    preferred = ("dp system", "system memory", "processor")
    pool_idx = None
    for keyword in preferred:
        pool_idx = next(
            (idx for idx, name in names.items() if keyword in snmp_value_to_str(name).lower()),
            None
        )
        if pool_idx is not None:
            break
    if pool_idx is None:
        pool_idx = next(iter(names), None)

    if pool_idx is None or pool_idx not in used or pool_idx not in free:
        print("UNKNOWN - Could not retrieve memory pool statistics")
        sys.exit(3)

    used_bytes = int(used[pool_idx])
    free_bytes = int(free[pool_idx])
    total_bytes = used_bytes + free_bytes
    usage_pct = round((used_bytes / total_bytes) * 100, 1) if total_bytes else 0.0

    if usage_pct >= critical:
        exit_code = 2
    elif usage_pct >= warning:
        exit_code = 1
    else:
        exit_code = 0

    status = NAGIOS_STATUS[exit_code]
    pool_name = snmp_value_to_str(names[pool_idx])
    used_mb = round(used_bytes / (1024 * 1024), 1)
    total_mb = round(total_bytes / (1024 * 1024), 1)

    summary = f"{status} - {pool_name} memory usage: {usage_pct}% ({used_mb}MB / {total_mb}MB)"
    perf = f"memory_used={usage_pct}%;{warning};{critical};0;100"
    print(f"{summary} | {perf}")
    sys.exit(exit_code)


def check_connections(args, warning, critical):
    active = _snmp_get_or_exit(args, OIDS["connActiveConnections"])
    if _is_missing(active):
        print("UNKNOWN - Connection statistics are not available on this device")
        sys.exit(3)
    active_val = int(active)

    if critical is not None and active_val >= critical:
        exit_code = 2
    elif warning is not None and active_val >= warning:
        exit_code = 1
    else:
        exit_code = 0

    status = NAGIOS_STATUS[exit_code]
    summary = f"{status} - Current connections in use: {active_val}"

    peak, rc_peak = pysnmp_get(args, OIDS["connPeakConnections"])
    peak_val = int(peak) if rc_peak == 0 and not _is_missing(peak) else None

    if args.verbose and peak_val is not None:
        summary += f", peak: {peak_val}"

    perf = f"connections_in_use={active_val};{warning if warning is not None else ''};{critical if critical is not None else ''};;"
    if peak_val is not None:
        perf += f" connections_peak={peak_val};;;;"

    print(f"{summary} | {perf}")
    sys.exit(exit_code)


def check_uptime(args, warning, critical):
    value = _snmp_get_or_exit(args, OIDS["sysUpTime"])

    total_seconds = int(value) // 100  # sysUpTime is in hundredths of a second
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    uptime_str = f"{days}d {hours}h {minutes}m {seconds}s"

    if critical is not None and total_seconds < critical:
        exit_code = 2
    elif warning is not None and total_seconds < warning:
        exit_code = 1
    else:
        exit_code = 0

    status = NAGIOS_STATUS[exit_code]
    summary = f"{status} - Uptime: {uptime_str}"
    if exit_code != 0:
        summary += " (recent reboot detected)"

    perf = f"uptime={total_seconds}s;{warning if warning is not None else ''};{critical if critical is not None else ''};0;"
    print(f"{summary} | {perf}")
    sys.exit(exit_code)


def _check_combined_state(args, hw_index, label):
    detail = _snmp_get_or_exit(args, f"{OIDS['cfwHardwareStatusDetail']}.{hw_index}")
    value = _snmp_get_or_exit(args, f"{OIDS['cfwHardwareStatusValue']}.{hw_index}")

    text = snmp_value_to_str(detail)
    if (_is_missing(text) or not text.strip()) and _is_missing(value):
        print("UNKNOWN - No role/state information available (failover not configured?)")
        sys.exit(3)

    if _is_missing(text) or not text.strip():
        role_exit, role = 3, "unknown"
    else:
        lower = text.lower()
        if "active" in lower:
            role_exit, role = 0, "Active unit"
        elif "standby" in lower and "cold" not in lower:
            role_exit, role = 0, "Standby unit"
        else:
            role_exit, role = 2, text

    if _is_missing(value):
        state_exit, state_label, numeric = 3, "unknown", None
    else:
        numeric = int(value)
        state_label, failover_safe = PEER_NUMERIC_STATE_MAP.get(numeric, ("Forming/Unknown", False))
        state_exit = 0 if failover_safe else 2

    exit_code = max(role_exit, state_exit)
    status = NAGIOS_STATUS[exit_code]
    numeric_str = str(numeric) if numeric is not None else "n/a"

    # hw_index (6=primary, 7=secondary) is a fixed configured role shared by the whole HA pair,
    # so querying either paired unit's IP returns identical output - the label makes that explicit
    # instead of implying "local"/"peer" relative to the queried hostname.
    hw_role = "primary" if hw_index == HW_INDEX_PRIMARY else "secondary"
    queried_role = _determine_unit_role(args, args.hostname)
    if queried_role and role in ("Active unit", "Standby unit"):
        if queried_role == hw_role:
            role_note = f" [{args.hostname} = {queried_role} unit, currently {role}]"
        else:
            # this hw_index's slot isn't the queried IP's own slot, so flip to the queried IP's
            # actual state (a healthy pair always has exactly one active and one standby unit)
            queried_state = "Standby unit" if role == "Active unit" else "Active unit"
            role_note = (f" [{args.hostname} = {queried_role} unit, currently {queried_state}; "
                         f"this result reflects the {hw_role}/peer unit]")
    else:
        role_note = f" [queried unit is {queried_role}]" if queried_role else ""

    print(f"{status} - {label}: {role}, State: {state_label} ({numeric_str}){role_note} | state={numeric_str if numeric is not None else ''};;;;")
    sys.exit(exit_code)


def check_primary_state(args):
    _check_combined_state(args, HW_INDEX_PRIMARY, "Primary unit")


def check_secondary_state(args):
    _check_combined_state(args, HW_INDEX_SECONDARY, "Secondary unit")


def check_sysinfo(args):
    descr = _snmp_get_or_exit(args, OIDS["sysDescr"])
    name = _snmp_get_or_exit(args, OIDS["sysName"])

    model = _chassis_model_name(args)
    model_note = f", Model: {model}" if model else ""

    print(f"OK - Hostname: {snmp_value_to_str(name)}, Description: {snmp_value_to_str(descr)}{model_note}")
    sys.exit(0)


def _chassis_model_name(args):
    """Best-effort entPhysicalModelName of the chassis entry (entPhysicalClass=chassis).
    Returns None if the walk fails or no chassis entry is found - not every platform populates
    this MIB, so callers should degrade gracefully rather than treat this as an error."""
    classes, rc = pysnmp_walk_indexed(args, OIDS["entPhysicalClass"])
    if rc != 0:
        return None
    models, rc = pysnmp_walk_indexed(args, OIDS["entPhysicalModelName"])
    if rc != 0:
        return None
    for idx, value in classes.items():
        if int(value) == ENT_PHYSICAL_CLASS_CHASSIS and idx in models:
            model = snmp_value_to_str(models[idx]).strip()
            if model and not _is_missing(model):
                return model
    return None


def check_hardware(args):
    classes = _snmp_walk_or_exit(args, OIDS["entPhysicalClass"])
    descrs = _snmp_walk_or_exit(args, OIDS["entPhysicalDescr"])
    fan_status = _snmp_walk_or_exit(args, OIDS["cefcFanTrayOperStatus"])
    psu_status = _snmp_walk_or_exit(args, OIDS["cefcFRUPowerOperStatus"])

    # CISCO-ENTITY-SENSOR-MIB voltage/RPM readings. Best-effort: not every platform
    # populates this MIB, so a failed walk here just means readings show as "-".
    sensor_types, rc_sensors = pysnmp_walk_indexed(args, OIDS["entSensorType"])
    if rc_sensors != 0:
        sensor_types = {}
    sensor_values, rc_sensors = pysnmp_walk_indexed(args, OIDS["entSensorValue"])
    if rc_sensors != 0:
        sensor_values = {}
    sensor_scales, rc_sensors = pysnmp_walk_indexed(args, OIDS["entSensorScale"])
    if rc_sensors != 0:
        sensor_scales = {}

    chassis_fan_rpms, psu_voltages = _group_sensor_readings(sensor_types, sensor_values, sensor_scales)
    fan_rpm_chunks = _chunk_evenly(chassis_fan_rpms, len(fan_status))
    psu_voltage_chunks = _chunk_evenly(psu_voltages, len(psu_status))

    components = []  # (name, state_label, severity, voltage_str, rpm_str)

    fan_i = 0
    for idx, value in fan_status.items():
        # entPhysicalClass filter also guards against a walk drifting into an unrelated OID subtree
        if int(classes.get(idx, -1)) != ENT_PHYSICAL_CLASS_FAN:
            continue
        state_num = int(value)
        state_label = FAN_TRAY_STATUS_MAP.get(state_num, f"unknown({state_num})")
        severity = FAN_TRAY_STATUS_SEVERITY.get(state_num, 2)
        name = snmp_value_to_str(descrs.get(idx, f"Fan tray {idx}")).strip() or f"Fan tray {idx}"
        rpm_values = fan_rpm_chunks[fan_i] if fan_i < len(fan_rpm_chunks) else []
        fan_i += 1
        rpm = "/".join(f"{v:.0f}" for v in rpm_values) if rpm_values else "-"
        components.append((name, state_label, severity, "-", rpm))

    psu_i = 0
    for idx, value in psu_status.items():
        if int(classes.get(idx, -1)) != ENT_PHYSICAL_CLASS_POWER_SUPPLY:
            continue
        state_num = int(value)
        state_label = FRU_POWER_OPER_STATUS_MAP.get(state_num, f"unknown({state_num})")
        severity = 0 if state_num == FRU_POWER_OPER_STATUS_OK else 2
        name = snmp_value_to_str(descrs.get(idx, f"Power supply {idx}")).strip() or f"Power supply {idx}"
        voltage_values = psu_voltage_chunks[psu_i] if psu_i < len(psu_voltage_chunks) else []
        psu_i += 1
        voltage = "/".join(f"{v:.1f}V" for v in voltage_values) if voltage_values else "-"
        components.append((name, state_label, severity, voltage, "-"))

    if not components:
        # Some logical FTD instances (e.g. a secondary container sharing chassis with another
        # instance) never expose entPhysicalClass fan/PSU rows at all - that's expected, not a fault.
        print("OK - No fan tray/power supply components reported by this unit (expected on a secondary/non-primary logical instance)")
        sys.exit(0)

    exit_code = max(sev for _, _, sev, _, _ in components)
    status = NAGIOS_STATUS[exit_code]

    bad = [(name, state) for name, state, sev, _, _ in components if sev != 0]
    if bad:
        detail = ", ".join(f"{name}={state}" for name, state in bad)
        summary = f"{status} - {len(bad)} of {len(components)} fan/PSU component(s) not OK: {detail}"
    else:
        summary = f"{status} - All {len(components)} fan/PSU components OK"

    perf = f"components_total={len(components)};;;; components_bad={len(bad)};;;;"
    print(f"{summary} | {perf}")

    headers = ("Device Name", "Device Voltage", "Device RPM", "Device Status")
    hw_rows = [(name, voltage, rpm, state_label) for name, state_label, _, voltage, rpm in components]
    bad_mask = [sev != 0 for _, _, sev, _, _ in components]
    print(_render_table(args, headers, hw_rows, bad_mask))
    sys.exit(exit_code)


def check_interfaces(args):
    names = _snmp_walk_or_exit(args, OIDS["ifName"])
    admin = _snmp_walk_or_exit(args, OIDS["ifAdminStatus"])
    oper = _snmp_walk_or_exit(args, OIDS["ifOperStatus"])
    aliases = _snmp_walk_or_exit(args, OIDS["ifAlias"])

    # Best-effort: speed/error/discard counters are purely informational and never fail the check
    speeds, rc_extra = pysnmp_walk_indexed(args, OIDS["ifHighSpeed"])
    if rc_extra != 0:
        speeds = {}
    in_errors, rc_extra = pysnmp_walk_indexed(args, OIDS["ifInErrors"])
    if rc_extra != 0:
        in_errors = {}
    out_errors, rc_extra = pysnmp_walk_indexed(args, OIDS["ifOutErrors"])
    if rc_extra != 0:
        out_errors = {}
    in_discards, rc_extra = pysnmp_walk_indexed(args, OIDS["ifInDiscards"])
    if rc_extra != 0:
        in_discards = {}
    out_discards, rc_extra = pysnmp_walk_indexed(args, OIDS["ifOutDiscards"])
    if rc_extra != 0:
        out_discards = {}

    down = []
    rows = []  # (name, alias, status, speed, errors, discards), in index order
    monitored = 0
    total_errors = total_discards = 0
    for idx in sorted(names):
        name = snmp_value_to_str(names[idx])
        if any(p in name.lower() for p in NOISE_IFNAME_PATTERNS):
            continue
        monitored += 1
        admin_status = int(admin.get(idx, 2))
        oper_status = int(oper.get(idx, 2))
        alias = snmp_value_to_str(aliases.get(idx, "")).strip() or "-"

        speed = int(speeds[idx]) if idx in speeds else None
        in_err, out_err = int(in_errors.get(idx, 0)), int(out_errors.get(idx, 0))
        in_disc, out_disc = int(in_discards.get(idx, 0)), int(out_discards.get(idx, 0))
        total_errors += in_err + out_err
        total_discards += in_disc + out_disc

        if admin_status == 1 and oper_status != 1:
            down.append(f"{name} ({alias})" if alias != "-" else name)
            status_label = "DOWN"
        else:
            status_label = "UP"

        errors_str = f"{in_err}/{out_err}" if (in_err or out_err) else "-"
        discards_str = f"{in_disc}/{out_disc}" if (in_disc or out_disc) else "-"
        rows.append((name, alias, status_label, f"{speed}Mbps" if speed else "-",
                     errors_str, discards_str))

    if monitored == 0:
        print("UNKNOWN - No interfaces found to monitor")
        sys.exit(3)

    exit_code = 2 if down else 0
    status = NAGIOS_STATUS[exit_code]

    summary = f"{status} - All {monitored} interfaces are up" if not down \
        else f"{status} - {len(down)} of {monitored} down: {', '.join(down)}"

    perf = (f"interfaces_total={monitored};;;; interfaces_down={len(down)};;;; "
            f"errors_total={total_errors};;;; discards_total={total_discards};;;;")
    print(f"{summary} | {perf}")

    rows.sort(key=lambda row: row[2] != "DOWN")  # DOWN interfaces surface at the top of the table

    headers = ("Interface", "Alias", "Status", "Speed", "Errors(in/out)", "Discards(in/out)")
    bad_mask = [row[2] == "DOWN" for row in rows]
    print(_render_table(args, headers, rows, bad_mask))
    sys.exit(exit_code)


def main():
    usage = (
        "%(prog)s -H/--hostname <host>\n"
        "           ( -C/--community <community> | --user <user> [--seclevel noAuthNoPriv|authNoPriv|authPriv]\n"
        "             [--auth <auth-protocol>] [--authpw <auth-password>] [--priv <priv-protocol>] [--privpw <priv-password>] )\n"
        "           [-t/--timeout <seconds>] [-v/--verbose] [--html-table]\n"
        "           --mode MODE\n"
        "           [-w/--warning <threshold>] [-c/--critical <threshold>]"
    )
    parser = argparse.ArgumentParser(
        usage=usage,
        description="Nagios plugin to check a Cisco firewall (ASA/FTD/Secure Firewall) via SNMP",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-H", "--hostname", required=True, help="Firewall hostname or IP")
    parser.add_argument("--peer-hostname",
                        help="Paired unit's hostname or IP for --mode ha_pair. If omitted, the peer is "
                             "guessed from --hostname via the +/-2 last-octet IPv4 convention and confirmed "
                             "by a live query; exits WARNING if no candidate can be confirmed.")
    parser.add_argument("-C", "--community", help="SNMPv2c community string")
    parser.add_argument("--user", help="SNMPv3 username")
    parser.add_argument("--seclevel", default="authPriv",
                        choices=["noAuthNoPriv", "authNoPriv", "authPriv"])
    parser.add_argument("--auth", default="sha")
    parser.add_argument("--authpw", help="SNMPv3 auth password (or set SNMP_AUTHPW env var instead, to avoid exposing it in the process list)")
    parser.add_argument("--priv", default="aes")
    parser.add_argument("--privpw", help="SNMPv3 priv password (or set SNMP_PRIVPW env var instead, to avoid exposing it in the process list)")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="SNMP timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print additional detail in the output")
    parser.add_argument("--html-table", action="store_true",
                        help="Render the hardware/interfaces detail table as an HTML <table> instead of "
                             "plain ljust+pipe-delimited text. Only useful for a frontend that renders raw "
                             "HTML in plugin output (e.g. Thruk with cgi.cfg escape_html_tags=0) - leave "
                             "unset for CLI/SSH testing, where plain text stays readable.")
    parser.add_argument("--mode", required=True, metavar="MODE",
                        choices=["ha_summary", "ha_pair", "cpu", "memory", "connections",
                                 "uptime", "primary_state",
                                 "secondary_state", "sysinfo", "hardware", "interfaces"],
                        help="A keyword which tells the plugin what to do\n"
                             "    ha_summary            (Check the HA failover status of the primary/secondary units)\n"
                             "    ha_pair               (Cross-check HA state via --hostname and --peer-hostname: both must be\n"
                             "                           reachable, agree with each other, and report a failover-safe state.\n"
                             "                           --peer-hostname is optional - if omitted, the peer is guessed via the\n"
                             "                           +/-2 last-octet IPv4 convention and confirmed by a live query. Output\n"
                             "                           best-effort labels which IP is Primary/Secondary when the platform\n"
                             "                           populates cfwHardwareInformation's self-referential text)\n"
                             "    cpu                   (Check the average CPU load of the device)\n"
                             "    memory                (Check the memory pool usage of the device)\n"
                             "    connections           (Check the current in-use connection count)\n"
                             "    uptime                (Check the uptime since the last reboot)\n"
                             "    primary_state         (Check the combined text role and numeric HA state of the primary unit - same result on either paired IP)\n"
                             "    secondary_state       (Check the combined text role and numeric HA state of the secondary unit - same result on either paired IP)\n"
                             "    sysinfo               (Report the hardware description, hostname and chassis model)\n"
                             "    hardware              (Check the fan tray / power supply operational status)\n"
                             "    interfaces            (Check the admin/oper status of the monitored named interfaces; also\n"
                             "                           reports link speed and error/discard counters, informational only)")
    parser.add_argument("-w", "--warning", type=float,
                        help="Warning threshold (percent for cpu/memory, connection count for connections, seconds for uptime)")
    parser.add_argument("-c", "--critical", type=float,
                        help="Critical threshold (percent for cpu/memory, connection count for connections, seconds for uptime)")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(3)

    args = parser.parse_args()

    # prefer explicit CLI flags but fall back to env vars so secrets don't have to appear in the process list
    args.authpw = args.authpw or os.environ.get("SNMP_AUTHPW")
    args.privpw = args.privpw or os.environ.get("SNMP_PRIVPW")

    if not args.community and not args.user:
        print("UNKNOWN - No SNMP credentials provided (use --community or --user)")
        sys.exit(3)

    if args.mode == "ha_summary":
        check_ha_summary(args)
    elif args.mode == "ha_pair":
        check_ha_pair(args)
    elif args.mode == "cpu":
        check_cpu(args, args.warning if args.warning is not None else 80.0,
                  args.critical if args.critical is not None else 90.0)
    elif args.mode == "memory":
        check_memory(args, args.warning if args.warning is not None else 80.0,
                     args.critical if args.critical is not None else 90.0)
    elif args.mode == "connections":
        check_connections(args, args.warning, args.critical)
    elif args.mode == "uptime":
        check_uptime(args, args.warning, args.critical)
    elif args.mode == "primary_state":
        check_primary_state(args)
    elif args.mode == "secondary_state":
        check_secondary_state(args)
    elif args.mode == "sysinfo":
        check_sysinfo(args)
    elif args.mode == "hardware":
        check_hardware(args)
    elif args.mode == "interfaces":
        check_interfaces(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("UNKNOWN - Check interrupted")
        sys.exit(3)
    except Exception as e:
        print(f"UNKNOWN - Unexpected error: {e}")
        sys.exit(3)
