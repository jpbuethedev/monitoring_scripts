#!/opt/rh/rh-python38/root/usr/bin/python3

#
# Nagios plugin to check a Cisco firewall (ASA / FTD / Secure Firewall 3100) via SNMP.
#
# Usage: check_cisco_firewall.py -H/--hostname <network-component>
#            ( -C/--community <snmp-community> | --user <snmpv3-user> [--seclevel noAuthNoPriv|authNoPriv|authPriv]
#              [--auth <auth-protocol>] [--authpw <auth-password>] [--priv <priv-protocol>] [--privpw <priv-password>] )
#            [ -t/--timeout <seconds> ] [ -v/--verbose ]
#            --mode ha_summary|cpu|memory|connections|uptime|primary_state|secondary_state|sysinfo|hardware|interfaces
#            [ -w/--warning <threshold> ] [ -c/--critical <threshold> ]
#
# Modes:
#   ha_summary          - HA state of the primary/secondary hardware units (cfwHardwareStatusValue)
#   cpu                 - average CPU load (5s/1m/5m); --warning/--critical are percent (default 80/90)
#   memory              - system/data-plane memory pool usage; --warning/--critical are percent (default 80/90)
#   connections         - current in-use connections; --warning/--critical are connection counts
#   uptime              - sysUpTime since last reboot; --warning/--critical are minimum seconds (optional)
#   primary_state       - combined text role and numeric HA state of the primary unit (cfwHardwareStatusDetail/Value index 6);
#                          same result regardless of which paired unit's IP is queried
#   secondary_state      - combined text role and numeric HA state of the secondary unit (cfwHardwareStatusDetail/Value index 7);
#                          same result regardless of which paired unit's IP is queried
#   sysinfo             - hardware description and hostname (sysDescr, sysName)
#   hardware            - fan tray / power supply operational status (cefcFanTrayOperStatus, cefcFRUPowerOperStatus)
#   interfaces          - admin/oper status of all real interfaces, excluding ASA-internal pseudo-interfaces (ifName, ifAdminStatus, ifOperStatus)

import argparse
import sys
from ves_snmp_utils import OIDS, NAGIOS_STATUS, pysnmp_get, pysnmp_walk_indexed, pysnmp_walk_multi_indexed, snmp_value_to_str

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

# ENTITY-MIB PhysicalClass values used to identify fan / power supply entries
# (more reliable than matching keywords in entPhysicalDescr, which is inconsistent/truncated
# across platforms, e.g. Secure Firewall 3100 PSU descr doesn't contain "psu"/"power supply")
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
NOISE_IFNAME_PATTERNS = ("internal-data", "nlp_int_tap", "ccl_ha_nlp_int_tap", "ha_ctl_nlp_int_tap")


def _is_missing(value):
    """True if an SNMP GET returned a 'no such instance/object' style value."""
    return "no such" in snmp_value_to_str(value).lower()


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


def check_ha_summary(args):
    oid = OIDS["cfwHardwareStatusValue"]

    primary, rc = pysnmp_get(args, f"{oid}.{HW_INDEX_PRIMARY}")
    if rc != 0:
        print(primary)
        sys.exit(rc)

    secondary, rc = pysnmp_get(args, f"{oid}.{HW_INDEX_SECONDARY}")
    if rc != 0:
        print(secondary)
        sys.exit(rc)

    if _is_missing(primary) and _is_missing(secondary):
        print("UNKNOWN - Failover is not configured on this unit (standalone)")
        sys.exit(3)

    primary_state = "not present" if _is_missing(primary) else HARDWARE_STATUS_MAP.get(int(primary), "unknown")
    secondary_state = "not present" if _is_missing(secondary) else HARDWARE_STATUS_MAP.get(int(secondary), "unknown")
    states = [primary_state, secondary_state]

    bad_states = {"down", "error", "overTemp", "noMedia", "unknown", "not present"}
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

    print(f"{label} - Primary: {primary_state}, Secondary: {secondary_state} | {perf}")
    sys.exit(exit_code)


def check_cpu(args, warning, critical):
    cpu_oids = {
        "5s": OIDS["cpmCPUTotal5secRev"],
        "1m": OIDS["cpmCPUTotal1minRev"],
        "5m": OIDS["cpmCPUTotal5minRev"],
    }

    averages = {}
    for label, oid in cpu_oids.items():
        result, rc = pysnmp_walk_indexed(args, oid)
        if rc != 0:
            print(result)
            sys.exit(rc)
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
    names, rc = pysnmp_walk_indexed(args, OIDS["ciscoMemPoolName"])
    if rc != 0:
        print(names)
        sys.exit(rc)
    used, rc = pysnmp_walk_indexed(args, OIDS["ciscoMemPoolUsed"])
    if rc != 0:
        print(used)
        sys.exit(rc)
    free, rc = pysnmp_walk_indexed(args, OIDS["ciscoMemPoolFree"])
    if rc != 0:
        print(free)
        sys.exit(rc)

    if not names:
        names, rc = pysnmp_walk_multi_indexed(args, OIDS["cempMemPoolName"])
        if rc != 0:
            print(names)
            sys.exit(rc)
        used, rc = pysnmp_walk_multi_indexed(args, OIDS["cempMemPoolUsed"])
        if rc != 0:
            print(used)
            sys.exit(rc)
        free, rc = pysnmp_walk_multi_indexed(args, OIDS["cempMemPoolFree"])
        if rc != 0:
            print(free)
            sys.exit(rc)

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
    active, rc = pysnmp_get(args, OIDS["connActiveConnections"])
    if rc != 0:
        print(active)
        sys.exit(rc)
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
    failed, rc_failed = pysnmp_get(args, OIDS["connFailedConnections"])
    failed_val = int(failed) if rc_failed == 0 and not _is_missing(failed) else None

    if args.verbose:
        if peak_val is not None:
            summary += f", peak: {peak_val}"
        if failed_val is not None:
            summary += f", failed: {failed_val}"

    perf = f"connections_in_use={active_val};{warning if warning is not None else ''};{critical if critical is not None else ''};;"
    if peak_val is not None:
        perf += f" connections_peak={peak_val};;;;"
    if failed_val is not None:
        perf += f" connections_failed={failed_val};;;;"

    print(f"{summary} | {perf}")
    sys.exit(exit_code)


def check_uptime(args, warning, critical):
    value, rc = pysnmp_get(args, OIDS["sysUpTime"])
    if rc != 0:
        print(value)
        sys.exit(rc)

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
    detail, rc = pysnmp_get(args, f"{OIDS['cfwHardwareStatusDetail']}.{hw_index}")
    if rc != 0:
        print(detail)
        sys.exit(rc)

    value, rc = pysnmp_get(args, f"{OIDS['cfwHardwareStatusValue']}.{hw_index}")
    if rc != 0:
        print(value)
        sys.exit(rc)

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
    print(f"{status} - {label}: {role}, State: {state_label} ({numeric_str}) | state={numeric_str if numeric is not None else ''};;;;")
    sys.exit(exit_code)


def check_primary_state(args):
    _check_combined_state(args, HW_INDEX_PRIMARY, "Primary unit")


def check_secondary_state(args):
    _check_combined_state(args, HW_INDEX_SECONDARY, "Secondary unit")


def check_sysinfo(args):
    descr, rc = pysnmp_get(args, OIDS["sysDescr"])
    if rc != 0:
        print(descr)
        sys.exit(rc)

    name, rc = pysnmp_get(args, OIDS["sysName"])
    if rc != 0:
        print(name)
        sys.exit(rc)

    print(f"OK - Hostname: {snmp_value_to_str(name)}, Description: {snmp_value_to_str(descr)}")
    sys.exit(0)


def check_hardware(args):
    classes, rc = pysnmp_walk_indexed(args, OIDS["entPhysicalClass"])
    if rc != 0:
        print(classes)
        sys.exit(rc)

    descrs, rc = pysnmp_walk_indexed(args, OIDS["entPhysicalDescr"])
    if rc != 0:
        print(descrs)
        sys.exit(rc)

    fan_status, rc = pysnmp_walk_indexed(args, OIDS["cefcFanTrayOperStatus"])
    if rc != 0:
        print(fan_status)
        sys.exit(rc)

    psu_status, rc = pysnmp_walk_indexed(args, OIDS["cefcFRUPowerOperStatus"])
    if rc != 0:
        print(psu_status)
        sys.exit(rc)

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
        print("UNKNOWN - No fan tray/power supply status available (not populated on this unit, e.g. HA standby)")
        sys.exit(3)

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

    table = [f"{'Device Name':<20}{'Device Voltage':>16}{'Device RPM':>12}{'Device Status':>15}"]
    for name, state_label, _, voltage, rpm in components:
        table.append(f"{name:<20}{voltage:>16}{rpm:>12}{state_label:>15}")
    print("\n".join(table))
    sys.exit(exit_code)


def check_interfaces(args):
    names, rc = pysnmp_walk_indexed(args, OIDS["ifName"])
    if rc != 0:
        print(names)
        sys.exit(rc)

    admin, rc = pysnmp_walk_indexed(args, OIDS["ifAdminStatus"])
    if rc != 0:
        print(admin)
        sys.exit(rc)

    oper, rc = pysnmp_walk_indexed(args, OIDS["ifOperStatus"])
    if rc != 0:
        print(oper)
        sys.exit(rc)

    aliases, rc = pysnmp_walk_indexed(args, OIDS["ifAlias"])
    if rc != 0:
        print(aliases)
        sys.exit(rc)

    down = []
    lines = []  # per-interface "name: UP/DOWN" detail lines, in index order
    monitored = 0
    for idx in sorted(names):
        name = snmp_value_to_str(names[idx])
        if any(p in name.lower() for p in NOISE_IFNAME_PATTERNS):
            continue
        monitored += 1
        admin_status = int(admin.get(idx, 2))
        oper_status = int(oper.get(idx, 2))
        alias = snmp_value_to_str(aliases.get(idx, "")).strip()
        label = f"{name} ({alias})" if alias else name
        if admin_status == 1 and oper_status != 1:
            down.append(label)
            lines.append(f"{label}: DOWN")
        else:
            lines.append(f"{label}: UP")

    if monitored == 0:
        print("UNKNOWN - No interfaces found to monitor")
        sys.exit(3)

    exit_code = 2 if down else 0
    status = NAGIOS_STATUS[exit_code]

    summary = f"{status} - All {monitored} interfaces are up" if not down \
        else f"{status} - {len(down)} of {monitored} down: {', '.join(down)}"

    perf = f"interfaces_total={monitored};;;; interfaces_down={len(down)};;;;"
    print(f"{summary} | {perf}")
    print("\n".join(lines))
    sys.exit(exit_code)


def main():
    usage = (
        "%(prog)s -H/--hostname <host>\n"
        "           ( -C/--community <community> | --user <user> [--seclevel noAuthNoPriv|authNoPriv|authPriv]\n"
        "             [--auth <auth-protocol>] [--authpw <auth-password>] [--priv <priv-protocol>] [--privpw <priv-password>] )\n"
        "           [-t/--timeout <seconds>] [-v/--verbose]\n"
        "           --mode MODE\n"
        "           [-w/--warning <threshold>] [-c/--critical <threshold>]"
    )
    parser = argparse.ArgumentParser(
        usage=usage,
        description="Nagios plugin to check a Cisco firewall (ASA/FTD/Secure Firewall) via SNMP",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-H", "--hostname", required=True, help="Firewall hostname or IP")
    parser.add_argument("-C", "--community", help="SNMPv2c community string")
    parser.add_argument("--user", help="SNMPv3 username")
    parser.add_argument("--seclevel", default="authPriv",
                        choices=["noAuthNoPriv", "authNoPriv", "authPriv"])
    parser.add_argument("--auth", default="sha")
    parser.add_argument("--authpw")
    parser.add_argument("--priv", default="aes")
    parser.add_argument("--privpw")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="SNMP timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print additional detail in the output")
    parser.add_argument("--mode", required=True, metavar="MODE",
                        choices=["ha_summary", "cpu", "memory", "connections",
                                 "uptime", "primary_state",
                                 "secondary_state", "sysinfo", "hardware", "interfaces"],
                        help="A keyword which tells the plugin what to do\n"
                             "    ha_summary            (Check the HA failover status of the primary/secondary units)\n"
                             "    cpu                   (Check the average CPU load of the device)\n"
                             "    memory                (Check the memory pool usage of the device)\n"
                             "    connections           (Check the current in-use connection count)\n"
                             "    uptime                (Check the uptime since the last reboot)\n"
                             "    primary_state         (Check the combined text role and numeric HA state of the primary unit - same result on either paired IP)\n"
                             "    secondary_state       (Check the combined text role and numeric HA state of the secondary unit - same result on either paired IP)\n"
                             "    sysinfo               (Report the hardware description and hostname)\n"
                             "    hardware              (Check the fan tray / power supply operational status)\n"
                             "    interfaces            (Check the admin/oper status of the monitored named interfaces)")
    parser.add_argument("-w", "--warning", type=float,
                        help="Warning threshold (percent for cpu/memory, connection count for connections, seconds for uptime)")
    parser.add_argument("-c", "--critical", type=float,
                        help="Critical threshold (percent for cpu/memory, connection count for connections, seconds for uptime)")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(3)

    args = parser.parse_args()

    if not args.community and not args.user:
        print("UNKNOWN - No SNMP credentials provided (use --community or --user)")
        sys.exit(3)

    if args.mode == "ha_summary":
        check_ha_summary(args)
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
