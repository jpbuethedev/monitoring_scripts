#!/opt/rh/rh-python38/root/usr/bin/python3

#
# Nagios plugin to check a Cisco Secure Firewall Management Center (FMC) via SNMP.
#
# Usage: check_cisco_fmc.py -H/--hostname <network-component>
#            ( -C/--community <snmp-community> | --user <snmpv3-user> [--seclevel noAuthNoPriv|authNoPriv|authPriv]
#              [--auth <auth-protocol>] [--authpw <auth-password>] [--priv <priv-protocol>] [--privpw <priv-password>] )
#            [ -t/--timeout <seconds> ] [ -v/--verbose ]
#            --mode cpu|memory|swap|disk
#            [ -w/--warning <percent> ] [ -c/--critical <percent> ]
#
# Modes (all via HOST-RESOURCES-MIB, since FMC is a Linux-based appliance rather than an
# IOS/ASA platform - CISCO-PROCESS-MIB / CISCO-MEMORY-POOL-MIB are not applicable here).
# --warning/--critical default to different values per mode (see MODE_DEFAULT_THRESHOLDS
# below) since FMC's bursty CPU and by-design high RAM usage aren't fault indicators on
# their own, while swap usage is a much more meaningful memory-pressure signal:
#   cpu     - average hrProcessorLoad across all reported CPUs; default 85/95. Also
#             escalates if any single core is at/above the thresholds even when the
#             average isn't, so one pegged core can't hide behind an otherwise-idle
#             fleet of cores.
#   memory  - physical RAM usage from the hrStorageTable entry of type hrStorageRam;
#             default 90/97
#   swap    - virtual memory/swap usage from the hrStorageTable entry of type
#             hrStorageVirtualMemory; default 5/20; reports OK if no swap is configured
#             (size 0)
#   disk    - usage of every hrStorageTable entry of type hrStorageFixedDisk; the worst
#             mount determines the overall status; default 80/90. --exclude-mounts
#             drops named mounts from consideration.

import argparse
import os
import sys
from ves_snmp_utils import OIDS, NAGIOS_STATUS, pysnmp_walk_indexed, snmp_value_to_str

# HOST-RESOURCES-TYPES hrStorageType values used to pick out RAM / swap / fixed-disk table rows
HR_STORAGE_TYPE_RAM = "1.3.6.1.2.1.25.2.1.2"
HR_STORAGE_TYPE_VIRTUAL_MEMORY = "1.3.6.1.2.1.25.2.1.3"
HR_STORAGE_TYPE_FIXED_DISK = "1.3.6.1.2.1.25.2.1.4"

# Default --warning/--critical percent per --mode, used when not given explicitly on the CLI.
# cpu/memory are looser since FMC's bursty CPU and by-design high RAM usage (page cache/event
# buffers) aren't fault indicators on their own; swap is tighter since FMC avoids swapping
# until RAM is genuinely exhausted, making it the more meaningful memory-pressure signal.
MODE_DEFAULT_THRESHOLDS = {
    "cpu": (85.0, 95.0),
    "memory": (90.0, 97.0),
    "swap": (5.0, 20.0),
    "disk": (80.0, 90.0),
}


def _snmp_walk_or_exit(args, oid):
    """pysnmp_walk_indexed(), printing the Nagios status line and exiting the process on failure."""
    result, rc = pysnmp_walk_indexed(args, oid)
    if rc != 0:
        print(result)
        sys.exit(rc)
    return result


def _threshold_exit_code(value, warning, critical):
    if critical is not None and value >= critical:
        return 2
    if warning is not None and value >= warning:
        return 1
    return 0


def _resolve_thresholds(args):
    default_warning, default_critical = MODE_DEFAULT_THRESHOLDS[args.mode]
    warning = args.warning if args.warning is not None else default_warning
    critical = args.critical if args.critical is not None else default_critical

    if not 0 <= warning <= 100:
        raise ValueError(f"--warning must be between 0 and 100 for --mode {args.mode} (got {warning})")
    if not 0 <= critical <= 100:
        raise ValueError(f"--critical must be between 0 and 100 for --mode {args.mode} (got {critical})")
    if warning >= critical:
        raise ValueError(f"--warning ({warning}) must be lower than --critical ({critical})")

    return warning, critical


def check_cpu(args, warning, critical):
    loads = _snmp_walk_or_exit(args, OIDS["hrProcessorLoad"])
    if not loads:
        print("UNKNOWN - No CPU data returned (HOST-RESOURCES-MIB hrProcessorLoad not populated)")
        sys.exit(3)

    values = {idx: int(v) for idx, v in loads.items()}
    average = round(sum(values.values()) / len(values), 1)
    worst_idx = max(values, key=values.get)
    worst_core = values[worst_idx]

    avg_exit = _threshold_exit_code(average, warning, critical)
    core_exit = _threshold_exit_code(worst_core, warning, critical)
    exit_code = max(avg_exit, core_exit)
    status = NAGIOS_STATUS[exit_code]
    per_cpu = ", ".join(f"cpu{idx}={values[idx]}%" for idx in sorted(values))

    summary = f"{status} - Average CPU usage: {average}% ({per_cpu})"
    if core_exit > avg_exit:
        summary += f" (cpu{worst_idx} at {worst_core}% drives status)"
    perf = f"cpu_avg={average}%;{warning if warning is not None else ''};{critical if critical is not None else ''};0;100"
    print(f"{summary} | {perf}")
    sys.exit(exit_code)


def _read_storage_table(args):
    """Walk hrStorageTable and return dict: idx -> (type_oid_str, descr, used_bytes, size_bytes)."""
    types = _snmp_walk_or_exit(args, OIDS["hrStorageType"])
    descrs = _snmp_walk_or_exit(args, OIDS["hrStorageDescr"])
    alloc_units = _snmp_walk_or_exit(args, OIDS["hrStorageAllocationUnits"])
    sizes = _snmp_walk_or_exit(args, OIDS["hrStorageSize"])
    used = _snmp_walk_or_exit(args, OIDS["hrStorageUsed"])

    entries = {}
    for idx, type_val in types.items():
        if idx not in sizes or idx not in used:
            continue
        unit = int(alloc_units[idx]) if idx in alloc_units else 1
        entries[idx] = (
            snmp_value_to_str(type_val),
            snmp_value_to_str(descrs.get(idx, f"storage {idx}")).strip(),
            int(used[idx]) * unit,
            int(sizes[idx]) * unit,
        )
    return entries


def check_memory(args, warning, critical):
    entries = _read_storage_table(args)
    ram = next((v for v in entries.values() if v[0] == HR_STORAGE_TYPE_RAM), None)
    if ram is None:
        print("UNKNOWN - No physical memory entry found (HOST-RESOURCES-MIB hrStorageTable not populated)")
        sys.exit(3)

    _, descr, used_bytes, size_bytes = ram
    usage_pct = round((used_bytes / size_bytes) * 100, 1) if size_bytes else 0.0

    exit_code = _threshold_exit_code(usage_pct, warning, critical)
    status = NAGIOS_STATUS[exit_code]
    used_mb = round(used_bytes / (1024 * 1024), 1)
    total_mb = round(size_bytes / (1024 * 1024), 1)

    summary = f"{status} - {descr} usage: {usage_pct}% ({used_mb}MB / {total_mb}MB)"
    perf = f"memory_used={usage_pct}%;{warning if warning is not None else ''};{critical if critical is not None else ''};0;100"
    print(f"{summary} | {perf}")
    sys.exit(exit_code)


def check_swap(args, warning, critical):
    entries = _read_storage_table(args)
    # hrStorageVirtualMemory can label TWO rows: a combined "Virtual memory" (RAM+swap)
    # total and the actual "Swap space" partition - only the latter is wanted here.
    candidates = [v for v in entries.values() if v[0] == HR_STORAGE_TYPE_VIRTUAL_MEMORY]
    swap = next((v for v in candidates if "swap" in v[1].lower()), None)
    if swap is None:
        print("UNKNOWN - No swap entry found (HOST-RESOURCES-MIB hrStorageTable not populated)")
        sys.exit(3)

    _, descr, used_bytes, size_bytes = swap
    if size_bytes == 0:
        print("OK - No swap configured")
        sys.exit(0)
    usage_pct = round((used_bytes / size_bytes) * 100, 1)

    exit_code = _threshold_exit_code(usage_pct, warning, critical)
    status = NAGIOS_STATUS[exit_code]
    used_mb = round(used_bytes / (1024 * 1024), 1)
    total_mb = round(size_bytes / (1024 * 1024), 1)

    summary = f"{status} - {descr} usage: {usage_pct}% ({used_mb}MB / {total_mb}MB)"
    perf = f"swap_used={usage_pct}%;{warning if warning is not None else ''};{critical if critical is not None else ''};0;100"
    print(f"{summary} | {perf}")
    sys.exit(exit_code)


def check_disk(args, warning, critical):
    entries = _read_storage_table(args)
    all_disks = [v for v in entries.values() if v[0] == HR_STORAGE_TYPE_FIXED_DISK and v[3] > 0]

    include_set = {m.strip() for m in args.include_mounts.split(",") if m.strip()}
    exclude_set = {m.strip() for m in args.exclude_mounts.split(",") if m.strip()}

    if include_set:
        known_mounts = {v[1] for v in all_disks}
        missing_includes = sorted(include_set - known_mounts)
        if missing_includes and args.verbose:
            print(f"WARNING - Ignoring unknown --include-mounts entries: {', '.join(missing_includes)}")
        all_disks = [v for v in all_disks if v[1] in include_set]

    missing_excludes = sorted(exclude_set - {v[1] for v in all_disks})
    disks = [v for v in all_disks if v[1] not in exclude_set]
    if not disks:
        print("UNKNOWN - No fixed disk entries found (HOST-RESOURCES-MIB hrStorageTable not populated, or all excluded)")
        sys.exit(3)

    if missing_excludes and args.verbose:
        print(f"WARNING - Ignoring unknown --exclude-mounts entries: {', '.join(missing_excludes)}")

    mounts = []  # (descr, usage_pct, used_mb, total_mb)
    for _, descr, used_bytes, size_bytes in disks:
        usage_pct = round((used_bytes / size_bytes) * 100, 1)
        used_mb = round(used_bytes / (1024 * 1024), 1)
        total_mb = round(size_bytes / (1024 * 1024), 1)
        mounts.append((descr, usage_pct, used_mb, total_mb))
    mounts.sort(key=lambda m: m[1], reverse=True)

    worst_pct = mounts[0][1]
    exit_code = _threshold_exit_code(worst_pct, warning, critical)
    status = NAGIOS_STATUS[exit_code]

    summary = f"{status} - Disk usage (worst: {mounts[0][0]}={worst_pct}%)"

    def perfdata_name(descr):
        return "".join(c if c.isalnum() else "_" for c in descr).strip("_") or "disk"

    perf = " ".join(
        f"{perfdata_name(descr)}={pct}%;{warning if warning is not None else ''};"
        f"{critical if critical is not None else ''};0;100"
        for descr, pct, _, _ in mounts
    )
    print(f"{summary} | {perf}")
    for descr, pct, used_mb, total_mb in mounts:
        if args.verbose:
            print(f"{descr}={pct}% ({used_mb}MB/{total_mb}MB)")
        else:
            print(f"{descr}={pct}%")
    sys.exit(exit_code)


def main():
    usage = (
        "%(prog)s -H/--hostname <host>\n"
        "           ( -C/--community <community> | --user <user> [--seclevel noAuthNoPriv|authNoPriv|authPriv]\n"
        "             [--auth <auth-protocol>] [--authpw <auth-password>] [--priv <priv-protocol>] [--privpw <priv-password>] )\n"
        "           [-t/--timeout <seconds>] [-v/--verbose]\n"
        "           --mode cpu|memory|swap|disk\n"
        "           [-w/--warning <percent>] [-c/--critical <percent>] [--include-mounts <path>[,<path>...]] [--exclude-mounts <path>[,<path>...]]"
    )
    parser = argparse.ArgumentParser(
        usage=usage,
        description="Nagios plugin to check a Cisco Secure Firewall Management Center (FMC) via SNMP",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-H", "--hostname", required=True, help="FMC hostname or IP")
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
    parser.add_argument("--mode", required=True, metavar="MODE",
                        choices=["cpu", "memory", "swap", "disk"],
                        help="A keyword which tells the plugin what to do\n"
                             "    cpu       (Average CPU load across all reported processors)\n"
                             "    memory    (Physical RAM usage)\n"
                             "    swap      (Virtual memory/swap usage)\n"
                             "    disk      (Usage of every fixed disk/mount reported; worst one decides status)")
    parser.add_argument("-w", "--warning", type=float, default=None,
                        help="Warning threshold in percent (default varies by mode: "
                             "cpu 85, memory 90, swap 5, disk 80)")
    parser.add_argument("-c", "--critical", type=float, default=None,
                        help="Critical threshold in percent (default varies by mode: "
                             "cpu 95, memory 97, swap 20, disk 90)")
    parser.add_argument("--include-mounts", default="",
                        help="Comma-separated list of mount paths to include in --mode disk before exclusions are applied (e.g. /,/var/log)")
    parser.add_argument("--exclude-mounts", default="",
                        help="Comma-separated list of mount paths to exclude from --mode disk (e.g. /dev/shm,/boot)")

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

    try:
        warning, critical = _resolve_thresholds(args)
    except ValueError as exc:
        print(f"UNKNOWN - {exc}")
        sys.exit(3)

    if args.verbose:
        print(f"NOTE - Effective thresholds for {args.mode}: warning={warning}, critical={critical}")

    if args.mode == "cpu":
        check_cpu(args, warning, critical)
    elif args.mode == "memory":
        check_memory(args, warning, critical)
    elif args.mode == "swap":
        check_swap(args, warning, critical)
    elif args.mode == "disk":
        check_disk(args, warning, critical)


if __name__ == "__main__":
    main()
