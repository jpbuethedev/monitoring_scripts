#!/opt/rh/rh-python38/root/usr/bin/python3

#
# Nagios plugin to check a Cisco firewall (ASA / FTD / Secure Firewall 3100) via SNMP.
#
# Usage: check_cisco_firewall.py -H/--hostname <network-component>
#            ( -C/--community <snmp-community> | --user <snmpv3-user> [--seclevel noAuthNoPriv|authNoPriv|authPriv]
#              [--auth <auth-protocol>] [--authpw <auth-password>] [--priv <priv-protocol>] [--privpw <priv-password>] )
#            [ -t/--timeout <seconds> ] [ -v/--verbose ]
#            --mode failover|cpu|memory|connections|uptime|role|numeric_state|peer_role|peer_numeric_state|sysinfo|hardware|interfaces
#            [ --warning <threshold> ] [ --critical <threshold> ]
#
# Modes:
#   failover            - HA state of the primary/secondary hardware units (cfwHardwareStatusValue)
#   cpu                 - average CPU load (5s/1m/5m); --warning/--critical are percent (default 80/90)
#   memory              - system/data-plane memory pool usage; --warning/--critical are percent (default 80/90)
#   connections         - current in-use connections; --warning/--critical are connection counts
#   uptime              - sysUpTime since last reboot; --warning/--critical are minimum seconds (optional)
#   role                - text HA role of the primary/local unit (cfwHardwareStatusDetail)
#   numeric_state       - numeric HA state of the primary/local unit (cfwHardwareStatusValue)
#   peer_role           - text HA role of the peer unit (cfwHardwareStatusDetail)
#   peer_numeric_state  - numeric HA state of the peer unit (cfwHardwareStatusValue)
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

# CISCO-FIREWALL-MIB ConnectionStat type indices (the service index varies by platform)
CONN_TYPE_CURRENT_OPEN = 3
CONN_TYPE_CURRENT_IN_USE = 6
CONN_TYPE_HIGH = 7

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


def check_failover(args):
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
    # cfwConnectionStatTable is indexed by (service, statType). The service index used for
    # the whole-firewall aggregate varies by platform (e.g. otherFWService=1 on classic ASA,
    # protoIp=40 on FTD/Secure Firewall), so discover it by walking the table instead of
    # assuming a fixed service index.
    stats, rc = pysnmp_walk_multi_indexed(args, OIDS["cfwConnectionStatValue"])
    if rc != 0:
        print(stats)
        sys.exit(rc)

    in_use_rows = {service: val for (service, stat_type), val in stats.items()
                   if stat_type == CONN_TYPE_CURRENT_IN_USE}
    if not in_use_rows:
        print("UNKNOWN - Connection statistics are not available on this device")
        sys.exit(3)

    # The whole-firewall aggregate row reports the largest in-use count
    service = max(in_use_rows, key=lambda s: int(in_use_rows[s]))
    in_use_val = int(in_use_rows[service])

    if critical is not None and in_use_val >= critical:
        exit_code = 2
    elif warning is not None and in_use_val >= warning:
        exit_code = 1
    else:
        exit_code = 0

    status = NAGIOS_STATUS[exit_code]
    summary = f"{status} - Current connections in use: {in_use_val}"

    if args.verbose:
        open_count = stats.get((service, CONN_TYPE_CURRENT_OPEN))
        high = stats.get((service, CONN_TYPE_HIGH))
        if open_count is not None:
            summary += f", currently open: {int(open_count)}"
        if high is not None:
            summary += f", high watermark: {int(high)}"

    perf = f"connections_in_use={in_use_val};{warning if warning is not None else ''};{critical if critical is not None else ''};;"
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


def check_peer_role(args):
    _check_role(args, HW_INDEX_SECONDARY, "Peer role")


def check_role(args):
    _check_role(args, HW_INDEX_PRIMARY, "Role")


def _check_role(args, hw_index, label):
    detail, rc = pysnmp_get(args, f"{OIDS['cfwHardwareStatusDetail']}.{hw_index}")
    if rc != 0:
        print(detail)
        sys.exit(rc)

    text = snmp_value_to_str(detail)
    if _is_missing(text) or not text.strip():
        print(f"UNKNOWN - No {label.lower()} information available (failover not configured?)")
        sys.exit(3)

    lower = text.lower()
    if "active" in lower:
        exit_code, role = 0, "Active unit"
    elif "standby" in lower and "cold" not in lower:
        exit_code, role = 0, "Standby unit"
    else:
        exit_code, role = 2, text

    status = NAGIOS_STATUS[exit_code]
    print(f"{status} - {label}: {role}")
    sys.exit(exit_code)


def check_peer_numeric_state(args):
    _check_numeric_state(args, HW_INDEX_SECONDARY, "Peer state", "peer_state")


def check_numeric_state(args):
    _check_numeric_state(args, HW_INDEX_PRIMARY, "State", "state")


def _check_numeric_state(args, hw_index, label, perf_label):
    value, rc = pysnmp_get(args, f"{OIDS['cfwHardwareStatusValue']}.{hw_index}")
    if rc != 0:
        print(value)
        sys.exit(rc)

    if _is_missing(value):
        print(f"UNKNOWN - No {label.lower()} information available (failover not configured?)")
        sys.exit(3)

    numeric = int(value)
    state_label, failover_safe = PEER_NUMERIC_STATE_MAP.get(numeric, ("Forming/Unknown", False))
    exit_code = 0 if failover_safe else 2

    status = NAGIOS_STATUS[exit_code]
    print(f"{status} - {label}: {state_label} ({numeric}) | {perf_label}={numeric};;;;")
    sys.exit(exit_code)


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

    components = []  # (name, state_label, severity)

    for idx, value in fan_status.items():
        # entPhysicalClass filter also guards against a walk drifting into an unrelated OID subtree
        if int(classes.get(idx, -1)) != ENT_PHYSICAL_CLASS_FAN:
            continue
        state_num = int(value)
        state_label = FAN_TRAY_STATUS_MAP.get(state_num, f"unknown({state_num})")
        severity = FAN_TRAY_STATUS_SEVERITY.get(state_num, 2)
        name = snmp_value_to_str(descrs.get(idx, f"Fan tray {idx}")).strip() or f"Fan tray {idx}"
        components.append((name, state_label, severity))

    for idx, value in psu_status.items():
        if int(classes.get(idx, -1)) != ENT_PHYSICAL_CLASS_POWER_SUPPLY:
            continue
        state_num = int(value)
        state_label = FRU_POWER_OPER_STATUS_MAP.get(state_num, f"unknown({state_num})")
        severity = 0 if state_num == FRU_POWER_OPER_STATUS_OK else 2
        name = snmp_value_to_str(descrs.get(idx, f"Power supply {idx}")).strip() or f"Power supply {idx}"
        components.append((name, state_label, severity))

    if not components:
        print("UNKNOWN - No fan tray/power supply status available (not populated on this unit, e.g. HA standby)")
        sys.exit(3)

    exit_code = max(sev for _, _, sev in components)
    status = NAGIOS_STATUS[exit_code]

    bad = [(name, state) for name, state, sev in components if sev != 0]
    if bad:
        detail = ", ".join(f"{name}={state}" for name, state in bad)
        summary = f"{status} - {len(bad)} of {len(components)} fan/PSU component(s) not OK: {detail}"
    else:
        summary = f"{status} - All {len(components)} fan/PSU components OK"

    perf = f"components_total={len(components)};;;; components_bad={len(bad)};;;;"
    print(f"{summary} | {perf}")
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
    parser = argparse.ArgumentParser(
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
                        choices=["failover", "cpu", "memory", "connections",
                                 "uptime", "role", "numeric_state",
                                 "peer_role", "peer_numeric_state", "sysinfo", "hardware", "interfaces"],
                        help="A keyword which tells the plugin what to do\n"
                             "    failover              (Check the HA failover status of the primary/secondary units)\n"
                             "    cpu                   (Check the average CPU load of the device)\n"
                             "    memory                (Check the memory pool usage of the device)\n"
                             "    connections           (Check the current in-use connection count)\n"
                             "    uptime                (Check the uptime since the last reboot)\n"
                             "    role                  (Check the text HA role of the primary/local unit)\n"
                             "    numeric_state         (Check the numeric HA state of the primary/local unit)\n"
                             "    peer_role             (Check the text HA role of the peer unit)\n"
                             "    peer_numeric_state    (Check the numeric HA state of the peer unit)\n"
                             "    sysinfo               (Report the hardware description and hostname)\n"
                             "    hardware              (Check the fan tray / power supply operational status)\n"
                             "    interfaces            (Check the admin/oper status of the monitored named interfaces)")
    parser.add_argument("--warning", type=float,
                        help="Warning threshold (percent for cpu/memory, connection count for connections, seconds for uptime)")
    parser.add_argument("--critical", type=float,
                        help="Critical threshold (percent for cpu/memory, connection count for connections, seconds for uptime)")
    args = parser.parse_args()

    if not args.community and not args.user:
        print("UNKNOWN - No SNMP credentials provided (use --community or --user)")
        sys.exit(3)

    if args.mode == "failover":
        check_failover(args)
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
    elif args.mode == "role":
        check_role(args)
    elif args.mode == "numeric_state":
        check_numeric_state(args)
    elif args.mode == "peer_role":
        check_peer_role(args)
    elif args.mode == "peer_numeric_state":
        check_peer_numeric_state(args)
    elif args.mode == "sysinfo":
        check_sysinfo(args)
    elif args.mode == "hardware":
        check_hardware(args)
    elif args.mode == "interfaces":
        check_interfaces(args)


if __name__ == "__main__":
    main()
