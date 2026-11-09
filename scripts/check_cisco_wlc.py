#!/opt/rh/rh-python38/root/usr/bin/python3

# USAGE:
#   ./check_cisco_wlc.py --hostname HOST --community COMMUNITY --mode list-interfaces
#   ./check_cisco_wlc.py --hostname HOST --community COMMUNITY --mode list-serial-numbers
#   ./check_cisco_wlc.py --hostname HOST --community COMMUNITY --mode list-licenses
#   ./check_cisco_wlc.py --hostname HOST --community COMMUNITY --mode license-health
#   ./check_cisco_wlc.py --hostname HOST --community COMMUNITY --mode interface-health
#   ./check_cisco_wlc.py --hostname HOST --community COMMUNITY --mode interface-usage
#       [--interval 5] [-w 80] [-c 90] [--include-interfaces Gi2,Vl2555]
#   ./check_cisco_wlc.py --hostname HOST --user USER --mode list-interfaces
#       [--seclevel noAuthNoPriv|authNoPriv|authPriv]
#       [--auth sha|md5] [--authpw PASSWORD] [--priv aes|des] [--privpw PASSWORD]
#       [--timeout SECONDS]
#   ./check_cisco_wlc.py --help
#
# MODES:
#   list-licenses
#     Inventories Smart Licensing entitlements, requested counts and enforcement
#     states. OK means inventory succeeded, not that licenses are compliant.
#   license-health
#     Evaluates Smart Licensing enablement and entitlement enforcement states.
#     Empty tables are skipped only on confirmed standbyHot; otherwise UNKNOWN.
#     Neither license mode reports subscription expiry or remaining capacity.
#   list-serial-numbers
#     Lists nonempty ENTITY-MIB serials with index, component, class and model.
#     Retains separate component rows even when serials repeat; no serials is UNKNOWN.
#   list-interfaces
#     Lists all interfaces, including disabled and virtual interfaces, with index,
#     name, description, alias, admin/oper state and reported speed in Mbps.
#     Inventory only: down links do not cause alerts; an empty inventory is UNKNOWN.
#   interface-health
#     Checks enabled non-Null interfaces on the active WLC. Returns CRITICAL if
#     any checked interface is not admin-up/oper-up, or UNKNOWN for missing data.
#     standbyHot returns OK with evaluation explicitly skipped; other HA states
#     return WARNING. Does not check traffic usage or error counters.
#   interface-usage
#     Samples 64-bit traffic counters twice for enabled non-Null interfaces,
#     including VLANs, and reports inbound/outbound Mbps and utilization percent.
#     Uses --interval seconds between samples (default 5, minimum 1).
#     Each direction is evaluated separately: -w defaults to 80%, -c to 90%.
#     --include-interfaces selects comma-separated exact ifName/ifDescr values.
#     Samples either HA role; low traffic is not an error. Counter resets,
#     missing counters or unknown speed return UNKNOWN unless another interface
#     already requires CRITICAL. Includes per-interface rate/utilization perfdata.
#
# SNMPv3 defaults: --seclevel authPriv --auth sha --priv aes.
# Passwords may instead use SNMP_AUTHPW and SNMP_PRIVPW environment variables.
# Timeout defaults to 5 seconds per SNMP request.
# list-interfaces lists index, name, description, alias, admin/oper state and Mbps.
# Includes disabled and virtual interfaces; down links do not cause alerts.
# Successful inventory exits 0 (OK); empty inventory exits 3 (UNKNOWN).
# SNMP failures retain the shared helper's exit status.
# interface-health checks enabled non-Null links on the active WLC; standbyHot is skipped.

import argparse
import math
import os
import sys
import time

from ves_snmp_utils import OIDS, add_snmp_args, pysnmp_get, pysnmp_walk_indexed, snmp_value_to_str


ADMIN_STATES = {1: "up", 2: "down", 3: "testing"}
OPER_STATES = {
    1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant",
    6: "notPresent", 7: "lowerLayerDown",
}

LICENSE_STATES = {
    1: "initialized", 2: "waiting", 3: "authorized", 4: "outOfCompliance",
    5: "overage", 6: "evaluationPeriod", 7: "evaluationExpired",
    8: "authorizationExpired", 9: "gracePeriodExpired", 10: "disabled",
    11: "reservedAuthorized", 12: "invalidTag", 13: "notAuthorized",
    14: "notApplicable", 15: "inUse", 16: "notInUse",
}


def _walk(args, name):
    values, status = pysnmp_walk_indexed(args, OIDS.get(name, name))
    if status != 0:
        print(values)
        raise SystemExit(status)
    return values


def _text(value):
    return " ".join(snmp_value_to_str(value).split()).replace("|", "/")


def _state(value, labels):
    if value is None:
        return "unavailable"
    number = int(value)
    return labels.get(number, "unknown({})".format(number))


def list_interfaces(args):
    names = _walk(args, "ifName")
    descriptions = _walk(args, "ifDescr")
    indices = sorted(set(names) | set(descriptions))
    if not indices:
        print("UNKNOWN - No interfaces returned by IF-MIB")
        return 3

    aliases = _walk(args, "ifAlias")
    admin = _walk(args, "ifAdminStatus")
    oper = _walk(args, "ifOperStatus")
    speeds = _walk(args, "ifHighSpeed")
    rows = []
    for index in indices:
        speed = int(speeds[index]) if index in speeds else None
        rows.append((
            str(index), _text(names.get(index, "")) or _text(descriptions.get(index, "")),
            _text(descriptions.get(index, "")) or "-",
            _text(aliases.get(index, "")) or "-",
            _state(admin.get(index), ADMIN_STATES),
            _state(oper.get(index), OPER_STATES),
            str(speed) if speed is not None and speed > 0 else "unavailable",
        ))

    up_count = sum(int(value) == 1 for index, value in oper.items() if index in indices)
    print("OK - {} interfaces on {} ({} operationally up; inventory only) | "
          "interfaces_total={} interfaces_up={}".format(
              len(indices), args.hostname, up_count, len(indices), up_count))
    print("Index | Name | Description | Alias | Admin | Oper | Speed (Mbps)")
    for row in rows:
        print(" | ".join(row))
    return 0


def list_serial_numbers(args):
    serials = _walk(args, "entPhysicalSerialNum")
    serials = {index: _text(value) for index, value in serials.items() if _text(value)}
    if not serials:
        print("UNKNOWN - No serial numbers returned by ENTITY-MIB")
        return 3

    names = _walk(args, "entPhysicalName")
    descriptions = _walk(args, "entPhysicalDescr")
    models = _walk(args, "entPhysicalModelName")
    classes = _walk(args, "entPhysicalClass")
    labels = {
        1: "other", 2: "unknown", 3: "chassis", 4: "backplane", 5: "container",
        6: "powerSupply", 7: "fan", 8: "sensor", 9: "module", 10: "port",
        11: "stack", 12: "cpu", 13: "energyObject", 14: "battery",
    }
    print("OK - {} components with serial numbers on {} | serial_components={}".format(
        len(serials), args.hostname, len(serials)))
    print("Index | Component | Class | Model | Serial number | Description")
    for index, serial in sorted(serials.items()):
        description = _text(descriptions.get(index, ""))
        name = _text(names.get(index, "")) or description or "entity {}".format(index)
        print(" | ".join((str(index), name, _state(classes.get(index), labels),
                          _text(models.get(index, "")) or "unavailable", serial,
                          description or "-")))
    return 0


def check_licenses(args, health=False):
    enabled, status = pysnmp_get(args, "1.3.6.1.4.1.9.9.831.0.4.0")
    if status != 0:
        print(enabled)
        return status
    try:
        enabled = int(enabled)
        if enabled not in (1, 2):
            raise ValueError("invalid TruthValue")
    except (TypeError, ValueError):
        print("UNKNOWN - Smart Licensing enablement unavailable or invalid")
        return 3
    if enabled == 2:
        status = 2 if health else 0
        print("{} - Smart Licensing disabled{}".format(
            "CRITICAL" if health else "OK", "" if health else " (inventory only)"))
        return status

    base = "1.3.6.1.4.1.9.9.831.0.5.1.1."
    tags = _walk(args, base + "3")
    counts = _walk(args, base + "2")
    states = _walk(args, base + "5")
    features = _walk(args, base + "7")
    indices = sorted(set(tags) | set(counts) | set(states) | set(features))
    if not indices:
        role, status = pysnmp_get(args, "1.3.6.1.4.1.9.9.176.1.1.2.0")
        if status != 0:
            print(role)
            return status
        try:
            standby = int(role) == 9
        except (TypeError, ValueError):
            standby = False
        if standby:
            print("OK - Smart Licensing enabled; no local entitlements exposed on standbyHot; "
                  "{} evaluation skipped | license_entitlements=0 license_checked=0".format(args.mode))
            return 0
        print("UNKNOWN - Smart Licensing enabled but no entitlements exposed; "
              "cannot evaluate {} without a confirmed standbyHot role".format(args.mode))
        return 3

    rows, problems, unknown = [], [], []
    checked = 0
    worst = 0
    for index in indices:
        tag = _text(tags.get(index, ""))
        feature = _text(features.get(index, "")) or tag or "entitlement {}".format(index)
        try:
            count = int(counts[index])
            state = int(states[index])
            if not tag or not 0 <= count <= 4294967295 or state not in LICENSE_STATES:
                raise ValueError("missing tag or invalid quantity/state")
        except (KeyError, TypeError, ValueError):
            unknown.append(feature)
            rows.append("{} | {} | unavailable | unavailable (incomplete or invalid data)".format(
                feature, tag or "unavailable"))
            continue
        label = "{}({})".format(LICENSE_STATES[state], state)
        rows.append("{} | {} | {} | {}".format(feature, tag, count, label))
        checked += 1
        if health:
            if state in (4, 7, 8, 9, 10, 12, 13):
                level = 2
            elif state in (1, 2, 6):
                level = 1
            elif state == 14 or (state == 16 and count != 0):
                unknown.append(feature)
                continue
            else:
                level = 0
            worst = max(worst, level)
            if level:
                problems.append("{} {}".format(feature, label))
    status = 2 if worst == 2 else 3 if unknown else worst
    message = "Smart Licensing enabled; {} entitlements found".format(len(indices))
    if health:
        message += "; {} problem(s), {} unknown".format(len(problems), len(unknown))
    else:
        message += " (inventory only; not a compliance check)"
    if problems:
        message += "; " + ", ".join(problems)
    if unknown:
        message += "; unavailable/indeterminate: " + ", ".join(unknown)
    print("{} - {} | license_entitlements={} license_checked={} license_problem={} license_unknown={}".format(
        ("OK", "WARNING", "CRITICAL", "UNKNOWN")[status], message,
        len(indices), checked, len(problems), len(unknown)))
    print("Feature | Entitlement tag | Requested quantity | Enforcement status")
    for row in rows:
        print(row)
    return status


def interface_health(args):
    role, status = pysnmp_get(args, "1.3.6.1.4.1.9.9.176.1.1.2.0")
    if status != 0:
        print(role)
        return status
    try:
        role = int(role)
    except (TypeError, ValueError):
        print("UNKNOWN - WLC HA role unavailable")
        return 3
    if role == 9:
        print("OK - WLC is standbyHot; interface-health evaluation skipped | interfaces_checked=0")
        return 0
    if role != 14:
        print("WARNING - WLC is not active or standbyHot (HA state {}); interface-health evaluation skipped".format(role))
        return 1

    names = _walk(args, "ifName")
    descriptions = _walk(args, "ifDescr")
    admin = _walk(args, "ifAdminStatus")
    oper = _walk(args, "ifOperStatus")
    indices = sorted(set(names) | set(descriptions))
    checked = 0
    failures = []
    missing = []
    rows = []
    for index in indices:
        name = _text(names.get(index, "")) or _text(descriptions.get(index, ""))
        description = _text(descriptions.get(index, ""))
        if "null" in description.lower() or name.lower().startswith(("nu", "vo")):
            continue
        admin_state = int(admin[index]) if index in admin else None
        oper_state = int(oper[index]) if index in oper else None
        if admin_state == 2:
            continue
        if admin_state not in ADMIN_STATES or oper_state not in OPER_STATES:
            missing.append(name)
        else:
            checked += 1
            if admin_state != 1 or oper_state != 1:
                failures.append(name)
        rows.append("{} | {} | {}".format(
            name, _state(admin.get(index), ADMIN_STATES),
            _state(oper.get(index), OPER_STATES)))

    if failures:
        status, message = 2, "Enabled interfaces not up: " + ", ".join(failures)
    elif missing:
        status, message = 3, "Missing or invalid interface status: " + ", ".join(missing)
    elif not checked:
        status, message = 3, "No enabled non-Null interfaces found"
    else:
        status, message = 0, "All {} enabled non-Null interfaces are up".format(checked)
    print("{} - {} (active WLC) | interfaces_checked={} interfaces_problem={} interfaces_unknown={}".format(
        ("OK", "WARNING", "CRITICAL", "UNKNOWN")[status], message,
        checked, len(failures), len(missing)))
    print("Name | Admin | Oper")
    for row in rows:
        print(row)
    return status


def _traffic_sample(args):
    sample = {}
    for label, oid in (
            ("in", "1.3.6.1.2.1.31.1.1.1.6"),
            ("out", "1.3.6.1.2.1.31.1.1.1.10")):
        started = time.monotonic()
        values = _walk(args, oid)
        sample[label] = (values, (started + time.monotonic()) / 2)
    sample["discontinuity"] = _walk(args, "1.3.6.1.2.1.31.1.1.1.19")
    uptime, status = pysnmp_get(args, OIDS["sysUpTime"])
    if status != 0:
        print(uptime)
        raise SystemExit(status)
    sample["uptime"] = int(uptime)
    return sample


def _traffic_rate(first, second, direction, index):
    before, start = first[direction]
    after, end = second[direction]
    delta = int(after[index]) - int(before[index])
    if delta < 0 or end <= start:
        raise ValueError("counter decreased or sample interval invalid")
    return delta * 8 / (end - start)


def interface_usage(args):
    names = _walk(args, "ifName")
    descriptions = _walk(args, "ifDescr")
    admin = _walk(args, "ifAdminStatus")
    speeds = _walk(args, "ifHighSpeed")
    requested = {name.strip() for name in args.include_interfaces.split(",") if name.strip()}
    all_indices = sorted(set(names) | set(descriptions))
    selected = []
    matched = set()
    for index in all_indices:
        identifiers = {_text(names.get(index, "")), _text(descriptions.get(index, ""))} - {""}
        if not requested or requested & identifiers:
            selected.append(index)
            matched.update(requested & identifiers)
    if requested - matched:
        print("UNKNOWN - Unknown interface name(s): " + ", ".join(sorted(requested - matched)))
        return 3
    indices = []
    for index in selected:
        name = _text(names.get(index, "")) or _text(descriptions.get(index, ""))
        if "null" in _text(descriptions.get(index, "")).lower() or name.lower().startswith(("nu", "vo")):
            if requested:
                print("UNKNOWN - Selected interface {} is a Null interface".format(name))
                return 3
            continue
        if index not in admin or int(admin[index]) not in ADMIN_STATES:
            print("UNKNOWN - Missing or invalid admin state for {}".format(name))
            return 3
        if int(admin[index]) == 1:
            indices.append(index)
        elif requested:
            print("UNKNOWN - Selected interface {} is not administratively up".format(name))
            return 3
    if not indices:
        print("UNKNOWN - No enabled non-Null interfaces found")
        return 3

    first = _traffic_sample(args)
    time.sleep(args.interval)
    second = _traffic_sample(args)
    if second["uptime"] <= first["uptime"]:
        print("UNKNOWN - Device uptime reset or did not advance during traffic sampling")
        return 3
    rows, perf, problems, unavailable = [], [], [], []
    status = 0
    for index in indices:
        name = _text(names.get(index, "")) or _text(descriptions.get(index, ""))
        try:
            if int(first["discontinuity"][index]) != int(second["discontinuity"][index]):
                raise ValueError("counter discontinuity during sampling")
            speed = int(speeds[index]) * 1000000
            if speed <= 0:
                raise ValueError("interface speed unavailable")
            incoming = _traffic_rate(first, second, "in", index)
            outgoing = _traffic_rate(first, second, "out", index)
            in_pct, out_pct = incoming / speed * 100, outgoing / speed * 100
            utilization = max(in_pct, out_pct)
            level = 2 if utilization >= args.critical else 1 if utilization >= args.warning else 0
            status = max(status, level)
            if level:
                problems.append("{} {:.2f}%".format(name, utilization))
            rows.append("{} | {:.3f} | {:.3f} | {:.2f} | {:.2f}".format(
                name, incoming / 1000000, outgoing / 1000000, in_pct, out_pct))
            for direction, rate, percent in (("in", incoming, in_pct), ("out", outgoing, out_pct)):
                perf.append("if{}_{}_bps={:.3f};;;0;{}".format(index, direction, rate, speed))
                perf.append("if{}_{}_pct={:.3f}%;{};{};0;100".format(
                    index, direction, percent, args.warning, args.critical))
        except (KeyError, TypeError, ValueError) as exc:
            unavailable.append(name)
            rows.append("{} | unavailable: {}".format(name, _text(str(exc))))

    if unavailable and status != 2:
        status = 3
    message = "Traffic usage on {} enabled interfaces".format(len(indices))
    if problems:
        message += "; threshold exceeded: " + ", ".join(problems)
    if unavailable:
        message += "; unavailable: " + ", ".join(unavailable)
    print("{} - {} | {}".format(("OK", "WARNING", "CRITICAL", "UNKNOWN")[status], message, " ".join(perf)))
    print("Name | In Mbps | Out Mbps | In % | Out %")
    for row in rows:
        print(row)
    return status


def main():
    parser = argparse.ArgumentParser(
                description="Query Cisco WLC interfaces via SNMP",
                formatter_class=argparse.RawDescriptionHelpFormatter,
                epilog="""Modes:
    list-licenses
        Lists Smart Licensing features, tags, requested quantities and states.
        OK means inventory succeeded, not license compliance. Disabled is reported
        without an alarm. Incomplete required data is UNKNOWN.

    license-health
        Checks Smart Licensing enablement and enforcement states. Disabled,
        noncompliant, expired or unauthorized is CRITICAL; initializing, waiting
        or evaluating is WARNING. Authorized, reserved-authorized, inUse, permitted
        overage and zero-request notInUse are acceptable. Unknown data is UNKNOWN.
        Both license modes skip empty tables only on confirmed standbyHot.
        Subscription expiry and remaining/purchased capacity are not exposed.

    list-serial-numbers
        Lists nonempty ENTITY-MIB serials with component index, name, class,
        model and description. Repeated serials remain separate component rows.
        Inventory only: at least one serial is OK; no serials is UNKNOWN.
        Component labels come from the device; local/peer identity is not guessed.

    list-interfaces
        Lists all interfaces, including disabled and virtual interfaces, with index,
        name, description, alias, admin/oper state and reported speed in Mbps.
        Inventory only: down links do not cause alerts; empty inventory is UNKNOWN.

    interface-health
        Checks enabled non-Null interfaces on the active WLC. Interfaces not
        admin-up/oper-up are CRITICAL; missing status is UNKNOWN unless another
        interface already requires CRITICAL. standbyHot returns OK with evaluation
        skipped; other HA states return WARNING. Does not check traffic or errors.

    interface-usage
        Samples 64-bit counters for enabled non-Null interfaces, including VLANs,
        and reports inbound/outbound Mbps, utilization percent and perfdata.
        --interval sets the sample delay (default 5 seconds, minimum 1).
        Each direction is evaluated separately: -w defaults to 80%, -c to 90%.
        --include-interfaces Gi2 limits sampling evaluation to exact ifName or
        ifDescr matches (comma-separated, case-sensitive). Unknown, disabled or
        Null selections return UNKNOWN; omitted means all eligible interfaces.
        Samples either HA role; low traffic is not an error. Resets, missing counters
        or unknown speed return UNKNOWN unless another interface requires CRITICAL.

SNMPv3 passwords may use SNMP_AUTHPW and SNMP_PRIVPW environment variables.
--timeout applies per SNMP request; allow additional time for traffic sampling.
""",
        )
    add_snmp_args(parser, timeout_default=5)
    parser.add_argument("--mode", required=True, choices=["list-interfaces", "interface-health", "interface-usage", "list-serial-numbers", "list-licenses", "license-health"],
                        help="Inventory interfaces, serials or licenses; check links, traffic usage or license health")
    parser.add_argument("--interval", type=float, default=5, help="Traffic sampling interval in seconds (default 5)")
    parser.add_argument("--include-interfaces", default=None, metavar="NAMES",
                        help="interface-usage only: comma-separated exact ifName/ifDescr values (e.g. Gi2)")
    parser.add_argument("-w", "--warning", type=float, default=80, help="Traffic utilization warning percent (default 80)")
    parser.add_argument("-c", "--critical", type=float, default=90, help="Traffic utilization critical percent (default 90)")
    if len(sys.argv) == 1:
        parser.print_help()
        return 3
    args = parser.parse_args()
    args.authpw = args.authpw or os.environ.get("SNMP_AUTHPW")
    args.privpw = args.privpw or os.environ.get("SNMP_PRIVPW")
    if not args.community and not args.user:
        print("UNKNOWN - No SNMP credentials provided (use --community or --user)")
        return 3
    if args.timeout <= 0:
        print("UNKNOWN - --timeout must be positive")
        return 3
    if args.include_interfaces is not None:
        if args.mode != "interface-usage":
            print("UNKNOWN - --include-interfaces is only supported with --mode interface-usage")
            return 3
        if not any(name.strip() for name in args.include_interfaces.split(",")):
            print("UNKNOWN - --include-interfaces must contain at least one interface name")
            return 3
    args.include_interfaces = args.include_interfaces or ""
    if args.mode == "interface-usage":
        if not math.isfinite(args.interval) or args.interval < 1:
            print("UNKNOWN - --interval must be finite and at least 1 second")
            return 3
        if not 0 <= args.warning < args.critical <= 100:
            print("UNKNOWN - Thresholds must satisfy 0 <= warning < critical <= 100")
            return 3
        return interface_usage(args)
    if args.mode == "interface-health":
        return interface_health(args)
    if args.mode == "list-serial-numbers":
        return list_serial_numbers(args)
    if args.mode in ("list-licenses", "license-health"):
        return check_licenses(args, health=args.mode == "license-health")
    return list_interfaces(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("UNKNOWN - Check interrupted")
        sys.exit(3)
    except Exception as exc:
        print("UNKNOWN - {}".format(exc))
        sys.exit(3)