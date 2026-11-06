#!/opt/rh/rh-python38/root/usr/bin/python3
"""Nagios/Icinga infrastructure checks for Cisco ISE using SNMP."""

import argparse
import math
import os
import sys
import time
from datetime import datetime, timedelta, timezone

NAGIOS_STATUS = ("OK", "WARNING", "CRITICAL", "UNKNOWN")
_SNMP_LOADED = False
DEFAULT_MOUNTS = "/,/opt,/boot,/tmp,/storedconfig,/mnt/encpart"
RAM_TYPE = "1.3.6.1.2.1.25.2.1.2"
DISK_TYPE = "1.3.6.1.2.1.25.2.1.4"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
MEM_TOTAL_SWAP = "1.3.6.1.4.1.2021.4.3.0"
MEM_AVAIL_SWAP = "1.3.6.1.4.1.2021.4.4.0"
MEM_TOTAL_REAL = "1.3.6.1.4.1.2021.4.5.0"
MEM_AVAIL_REAL = "1.3.6.1.4.1.2021.4.6.0"
MEM_BUFFER = "1.3.6.1.4.1.2021.4.14.0"
MEM_CACHED = "1.3.6.1.4.1.2021.4.15.0"
INTERFACE_DISCONTINUITY = "1.3.6.1.2.1.31.1.1.1.19"
INTERFACE_RATE_COUNTERS = (
    ("in_mbps", "1.3.6.1.2.1.31.1.1.1.6", 18446744073709551615, 8 / 1000000),
    ("out_mbps", "1.3.6.1.2.1.31.1.1.1.10", 18446744073709551615, 8 / 1000000),
    ("in_errors_s", "1.3.6.1.2.1.2.2.1.14", 4294967295, 1),
    ("out_errors_s", "1.3.6.1.2.1.2.2.1.20", 4294967295, 1),
    ("in_discards_s", "1.3.6.1.2.1.2.2.1.13", 4294967295, 1),
    ("out_discards_s", "1.3.6.1.2.1.2.2.1.19", 4294967295, 1),
)


class CheckError(Exception):
    def __init__(self, message, code=3):
        super().__init__(message)
        self.code = code


class CheckParser(argparse.ArgumentParser):
    def error(self, message):
        raise CheckError(message)


def load_snmp_dependencies():
    global _SNMP_LOADED, PyAsn1Error, ObjectIdentifier
    global NAGIOS_STATUS, OIDS, pysnmp_get, pysnmp_walk_indexed, snmp_value_to_str
    if _SNMP_LOADED:
        return
    from pyasn1.error import PyAsn1Error
    from pysnmp.proto.rfc1902 import ObjectIdentifier
    from ves_snmp_utils import (
        NAGIOS_STATUS, OIDS, pysnmp_get, pysnmp_walk_indexed, snmp_value_to_str,
    )
    _SNMP_LOADED = True


def text(value):
    return " ".join(str(value).replace("|", "/").split())


def integer(value, label, minimum=0, maximum=None):
    try:
        result = int(str(value))
    except (TypeError, ValueError, OverflowError):
        raise CheckError("Invalid integer for " + label)
    if result < minimum or (maximum is not None and result > maximum):
        raise CheckError("Out-of-range value for " + label)
    return result


def query(args, key, walk=False):
    oid = OIDS.get(key, key)
    result, code = (pysnmp_walk_indexed if walk else pysnmp_get)(args, oid)
    if code:
        message = text(result)
        for status in NAGIOS_STATUS:
            if message.startswith(status + " - "):
                message = message[len(status) + 3:]
                break
        raise CheckError(message, code)
    return result


def severity(value, warning, critical):
    if critical is not None and value >= critical:
        return 2
    if warning is not None and value >= warning:
        return 1
    return 0


def perf(label, value, warning=None, critical=None, unit="%", maximum=100):
    safe_label = label.replace("'", "''")
    warn = "" if warning is None else format(warning, "g")
    crit = "" if critical is None else format(critical, "g")
    limit = "" if maximum is None else str(maximum)
    return "'{}'={:g}{};{};{};0;{}".format(safe_label, value, unit, warn, crit, limit)


def thresholds(args):
    if args.mode in ("uptime", "sysinfo", "interfaces", "serial-numbers"):
        if args.warning is not None or args.critical is not None:
            raise CheckError("Thresholds are not applicable to " + args.mode)
        return None, None
    if args.mode == "timesync":
        warning = 5.0 if args.warning is None else args.warning
        critical = 30.0 if args.critical is None else args.critical
        if not (math.isfinite(warning) and math.isfinite(critical)
                and 0 <= warning < critical):
            raise CheckError("Clock-skew thresholds must satisfy 0 <= warning < critical (seconds)")
        return warning, critical
    if args.mode in ("memory", "memory_usage"):
        if args.warning is None and args.critical is None:
            return None, None
        if args.warning is None or args.critical is None:
            raise CheckError("Memory alerting requires both --warning and --critical")
    warning = 80.0 if args.warning is None else args.warning
    critical = 90.0 if args.critical is None else args.critical
    if not (math.isfinite(warning) and math.isfinite(critical)
            and 0 <= warning < critical <= 100):
        raise CheckError("Thresholds must satisfy 0 <= warning < critical <= 100")
    return warning, critical


def check_cpu(args, warning, critical):
    loads = query(args, "hrProcessorLoad", walk=True)
    if not loads:
        raise CheckError("No CPU data returned (hrProcessorLoad)")
    values = {index: integer(value, "CPU load", maximum=100)
              for index, value in loads.items()}
    average = sum(values.values()) / len(values)
    busiest = max(values, key=values.get)
    peak = values[busiest]
    code = max(severity(average, warning, critical), severity(peak, warning, critical))
    summary = "CPU last-minute average {:.1f}%, busiest processor {}={}%, {} processors".format(
        average, busiest, peak, len(values))
    metrics = " ".join((perf("cpu_avg", average, warning, critical),
                        perf("cpu_max", peak, warning, critical)))
    details = ["Processor {}: {}%".format(index, values[index]) for index in sorted(values)]
    return code, summary, metrics, details


def storage_columns(args):
    return {name: query(args, name, walk=True) for name in (
        "hrStorageType", "hrStorageDescr", "hrStorageAllocationUnits",
        "hrStorageSize", "hrStorageUsed")}


def storage_values(columns, index):
    try:
        units = integer(columns["hrStorageAllocationUnits"][index], "allocation units", 1)
        capacity = integer(columns["hrStorageSize"][index], "storage size", 1)
        used = integer(columns["hrStorageUsed"][index], "storage used", maximum=capacity)
    except KeyError:
        raise CheckError("Incomplete storage row at index {}".format(index))
    return used * units, capacity * units


def check_memory(args, warning, critical):
    columns = storage_columns(args)
    candidates = [index for index, value in columns["hrStorageType"].items()
                  if snmp_value_to_str(value).lstrip(".") == RAM_TYPE]
    if len(candidates) != 1:
        raise CheckError("Expected exactly one physical RAM entry; found {}".format(len(candidates)))
    used, capacity = storage_values(columns, candidates[0])
    percentage = used * 100 / capacity
    summary = "Raw physical RAM used {:.1f}% ({:.2f}/{:.2f} GiB), includes cache/buffers".format(
        percentage, used / 1024 ** 3, capacity / 1024 ** 3)
    if warning is None:
        summary += "; informational, no thresholds configured"
    return (severity(percentage, warning, critical), summary,
            perf("memory_raw_used", percentage, warning, critical), [])


def check_memory_usage(args, warning, critical):
    counters = {
        "total": integer(query(args, MEM_TOTAL_REAL), "real memory total", 1, 4294967295),
        "free": integer(query(args, MEM_AVAIL_REAL), "real memory available", 0, 4294967295),
        "buffers": integer(query(args, MEM_BUFFER), "memory buffers", 0, 4294967295),
        "cached": integer(query(args, MEM_CACHED), "cached memory", 0, 4294967295),
    }
    active = counters["total"] - counters["free"] - counters["buffers"] - counters["cached"]
    if active < 0:
        raise CheckError("Inconsistent UCD-SNMP physical memory counters")
    percentage = active * 100 / counters["total"]
    total_gib = counters["total"] / 1024 ** 2
    active_gib = active / 1024 ** 2
    summary = ("Estimated active physical RAM used {:.1f}% ({:.2f}/{:.2f} GiB), "
               "excludes free memory, buffers, and cache; not Linux MemAvailable").format(
                   percentage, active_gib, total_gib)
    if warning is None:
        summary += "; informational, no thresholds configured"
    return (severity(percentage, warning, critical), summary,
            perf("memory_active_used", percentage, warning, critical), [])


def check_swap(args, warning, critical):
    total = integer(query(args, MEM_TOTAL_SWAP), "swap total", 0, 4294967295)
    free = integer(query(args, MEM_AVAIL_SWAP), "swap free", 0, 4294967295)
    if free > total:
        raise CheckError("Inconsistent UCD-SNMP swap counters: free exceeds total")
    if total == 0:
        raise CheckError("No swap configured (total swap is zero)")
    used = total - free
    percentage = used * 100 / total
    summary = "Swap used {:.1f}% ({:.2f}/{:.2f} GiB)".format(
        percentage, used / 1024 ** 2, total / 1024 ** 2)
    return (severity(percentage, warning, critical), summary,
            perf("swap_used", percentage, warning, critical), [])


def mount_paths(value):
    return {path.strip() for path in value.split(",") if path.strip()}


def check_disk(args, warning, critical):
    selected = mount_paths(args.include_mounts) - mount_paths(args.exclude_mounts)
    if not selected:
        raise CheckError("No mount paths selected")
    columns = storage_columns(args)
    rows = {path: [] for path in selected}
    for index, description in columns["hrStorageDescr"].items():
        path = snmp_value_to_str(description).strip()
        if path in rows:
            rows[path].append(index)
    readings = []
    for path in sorted(rows):
        indexes = rows[path]
        if len(indexes) != 1:
            raise CheckError("Mount {}: expected one row, found {}".format(text(path), len(indexes)))
        index = indexes[0]
        storage_type = snmp_value_to_str(columns["hrStorageType"].get(index, "")).lstrip(".")
        if storage_type != DISK_TYPE:
            raise CheckError("Mount {} is missing a fixed-disk type".format(text(path)))
        used, capacity = storage_values(columns, index)
        readings.append((path, used * 100 / capacity, used, capacity))
    readings.sort(key=lambda reading: reading[1], reverse=True)
    worst_path, worst, _, _ = readings[0]
    summary = "Disk usage, worst {}={:.1f}%; {} mounts checked".format(
        text(worst_path), worst, len(readings))
    metrics = " ".join(perf("disk:" + path, percentage, warning, critical)
                       for path, percentage, _, _ in readings)
    details = ["{}: {:.1f}% ({:.2f}/{:.2f} GiB)".format(
        text(path), percentage, used / 1024 ** 3, capacity / 1024 ** 3)
        for path, percentage, used, capacity in readings]
    return severity(worst, warning, critical), summary, metrics, details


def interface_names(value):
    return {name.strip() for name in value.split(",") if name.strip()}


def optional_interface_walk(args, key):
    try:
        return query(args, key, walk=True)
    except CheckError:
        return None


def optional_interface_integer(args, oid, maximum=4294967295):
    try:
        return integer(query(args, oid), "interface rate counter", maximum=maximum)
    except CheckError:
        return None


def interface_rate_snapshot(args, selected):
    uptime_before = optional_interface_integer(args, "sysUpTime")
    readings = {}
    for index in selected:
        try:
            name = snmp_value_to_str(query(args, OIDS["ifName"] + "." + str(index))).strip()
        except CheckError:
            name = None
        marker_oid = INTERFACE_DISCONTINUITY + "." + str(index)
        marker_before = optional_interface_integer(args, marker_oid)
        counters = {}
        for label, oid, maximum, scale in INTERFACE_RATE_COUNTERS:
            started = time.monotonic()
            value = optional_interface_integer(args, oid + "." + str(index), maximum)
            finished = time.monotonic()
            counters[label] = (value, (started + finished) / 2)
        marker_after = optional_interface_integer(args, marker_oid)
        readings[index] = (name, marker_before, marker_after, counters)
    uptime_after = optional_interface_integer(args, "sysUpTime")
    return uptime_before, uptime_after, readings


def interface_rates(args, selected):
    first = interface_rate_snapshot(args, selected)
    time.sleep(args.rate_interval)
    second = interface_rate_snapshot(args, selected)
    uptimes = (first[0], first[1], second[0], second[1])
    if any(value is None for value in uptimes) or list(uptimes) != sorted(uptimes):
        return {}
    rates = {}
    for index, name in selected.items():
        before = first[2][index]
        after = second[2][index]
        markers = (before[1], before[2], after[1], after[2])
        if (before[0] != name or after[0] != name
                or any(marker is None for marker in markers) or len(set(markers)) != 1):
            continue
        rates[index] = {}
        for label, oid, maximum, scale in INTERFACE_RATE_COUNTERS:
            previous, started = before[3][label]
            current, finished = after[3][label]
            elapsed = finished - started
            if previous is not None and current is not None and current >= previous and elapsed > 0:
                rates[index][label] = (current - previous) / elapsed * scale
    return rates


def check_interfaces(args):
    names = query(args, "ifName", walk=True)
    admin = query(args, "ifAdminStatus", walk=True)
    oper = query(args, "ifOperStatus", walk=True)
    if not names:
        raise CheckError("No interface data returned (ifName)")

    include = interface_names(args.include_interfaces or "")
    if args.include_interfaces is not None and not include:
        raise CheckError("No interface names included")
    exclude = interface_names(args.exclude_interfaces or "")
    aliases = optional_interface_walk(args, "ifAlias")
    speeds = optional_interface_walk(args, "ifHighSpeed")
    counters = {key: optional_interface_walk(args, key) for key in (
        "ifInErrors", "ifOutErrors", "ifInDiscards", "ifOutDiscards")}

    rows = []
    selected = {}
    down = []
    testing = []
    errors_total = 0
    discards_total = 0
    counters_complete = all(table is not None for table in counters.values())
    for index in sorted(names):
        name = snmp_value_to_str(names[index]).strip()
        if not name:
            raise CheckError("Empty interface name at index {}".format(index))
        if include:
            if name not in include:
                continue
        elif name == "lo" or name.lower().startswith(("podman", "veth")):
            continue
        if name in exclude:
            continue
        try:
            admin_status = integer(admin[index], "interface admin status", 1, 3)
            oper_status = integer(oper[index], "interface oper status", 1, 7)
        except KeyError:
            raise CheckError("Incomplete interface row for {}".format(text(name)))

        alias = "-"
        if aliases is not None and index in aliases:
            alias = text(snmp_value_to_str(aliases[index]).strip()) or "-"
        speed = "-"
        if speeds is not None and index in speeds:
            try:
                speed_value = integer(speeds[index], "interface speed", maximum=4294967295)
                speed = "{} Mbps".format(speed_value) if speed_value else "-"
            except CheckError:
                pass

        counts = []
        for key in ("ifInErrors", "ifOutErrors", "ifInDiscards", "ifOutDiscards"):
            table = counters[key]
            value = None
            if table is not None and index in table:
                try:
                    value = integer(table[index], "interface counter", maximum=4294967295)
                except CheckError:
                    counters_complete = False
            else:
                counters_complete = False
            counts.append(value)

        in_errors, out_errors, in_discards, out_discards = counts
        errors = "{}/{}".format(in_errors, out_errors) \
            if in_errors is not None and out_errors is not None else "-"
        discards = "{}/{}".format(in_discards, out_discards) \
            if in_discards is not None and out_discards is not None else "-"
        if counters_complete:
            errors_total += in_errors + out_errors
            discards_total += in_discards + out_discards

        oper_labels = {
            1: "UP", 2: "DOWN", 3: "TESTING", 4: "UNKNOWN", 5: "DORMANT",
            6: "NOT PRESENT", 7: "LOWER LAYER DOWN",
        }
        if admin_status == 1 and oper_status != 1:
            status = oper_labels[oper_status]
            down.append("{} ({})".format(text(name), status))
        elif admin_status == 2:
            status = "ADMIN DOWN"
        elif admin_status == 3:
            status = "ADMIN TESTING"
            testing.append(text(name))
        else:
            status = "UP"
        rows.append((text(name), alias, status, speed, errors, discards))
        selected[index] = name

    if not rows:
        raise CheckError("No interfaces selected to monitor")

    exit_code = 2 if down else (1 if testing else 0)
    if down:
        summary = "{} of {} monitored interfaces not up: {}".format(
            len(down), len(rows), ", ".join(down))
    elif testing:
        summary = "{} of {} monitored interfaces in admin testing: {}".format(
            len(testing), len(rows), ", ".join(testing))
    else:
        summary = "All {} monitored interfaces are up or administratively disabled".format(len(rows))

    metrics = "'interfaces_total'={};;;; 'interfaces_down'={};;;;".format(len(rows), len(down))
    if counters_complete:
        metrics += " 'errors_total'={};;;; 'discards_total'={};;;;".format(
            errors_total, discards_total)
    details = ["{} | {} | {} | {} | errors {} | discards {}".format(*row) for row in rows]
    rates = interface_rates(args, selected)
    complete = sum(len(rates.get(index, {})) == len(INTERFACE_RATE_COUNTERS) for index in selected)
    summary += "; rates available for {}/{} interfaces".format(complete, len(rows))
    if complete == len(rows):
        totals = [sum(rates[index][label] for index in selected)
                  for label, _, _, _ in INTERFACE_RATE_COUNTERS]
        summary += "; traffic {:.3f}/{:.3f} Mbps, errors {:.2f}/{:.2f}/s, discards {:.2f}/{:.2f}/s (in/out)".format(
            *totals)
    for position, index in enumerate(selected):
        values = rates.get(index, {})
        formatted = ["{:.3f}".format(values[label]) if label in values else "-"
                     for label, _, _, _ in INTERFACE_RATE_COUNTERS]
        details[position] += " | traffic {}/{} Mbps | error rate {}/{}/s | discard rate {}/{}/s (in/out)".format(
            *formatted)
        if len(values) != len(INTERFACE_RATE_COUNTERS):
            details[position] += " | rates incomplete (missing, changed or reset counters)"
        for label, value in values.items():
            metrics += " " + perf("if:" + text(selected[index]) + ":" + label,
                                   value, unit="", maximum=None)
    return exit_code, summary, metrics, details


def check_timesync(args, warning, critical):
    started = datetime.now(timezone.utc)
    value = query(args, "hrSystemDate")
    finished = datetime.now(timezone.utc)
    try:
        octets = value.asOctets()
        if len(octets) != 11 or octets[8] not in (ord("+"), ord("-")):
            raise ValueError("missing or invalid timezone")
        if octets[7] > 9 or octets[9] > 13 or octets[10] > 59:
            raise ValueError("invalid time component")
        offset = timedelta(hours=octets[9], minutes=octets[10])
        if octets[8] == ord("-"):
            offset = -offset
        device_time = datetime((octets[0] << 8) | octets[1], octets[2], octets[3],
                               octets[4], octets[5], octets[6], octets[7] * 100000,
                               tzinfo=timezone(offset))
    except (AttributeError, TypeError, ValueError, OverflowError):
        raise CheckError("Invalid hrSystemDate; a valid timestamp with explicit timezone is required")
    midpoint = started + (finished - started) / 2
    clock_offset = (device_time - midpoint).total_seconds()
    skew = abs(clock_offset)
    direction = "ahead" if clock_offset >= 0 else "behind"
    summary = "ISE clock skew vs monitoring host: {:.1f}s ({}); not NTP synchronization status".format(
        skew, direction)
    return (severity(skew, warning, critical), summary,
            perf("clock_skew", skew, warning, critical, unit="s", maximum=None), [])


def check_uptime(args):
    ticks = integer(query(args, "sysUpTime"), "SNMP-agent uptime", maximum=4294967295)
    seconds = ticks / 100
    summary = "SNMP-agent uptime {:.2f} days (not OS uptime)".format(seconds / 86400)
    return 0, summary, perf("snmp_uptime", seconds, unit="s", maximum=None), []


def check_sysinfo(args):
    description = text(query(args, "sysDescr"))
    object_value = query(args, SYS_OBJECT_ID)
    if not description or description.startswith("No Such"):
        raise CheckError("System description unavailable")
    try:
        value = object_value.getOid() if hasattr(object_value, "getOid") else object_value
        components = value.asTuple() if hasattr(value, "asTuple") else str(value).lstrip(".")
        if isinstance(components, str) and not all(component.isdigit() for component in components.split(".")):
            raise ValueError("Invalid OID components")
        numeric_oid = ObjectIdentifier(components)
        if len(numeric_oid) < 2 or numeric_oid[0] > 2 or (numeric_oid[0] < 2 and numeric_oid[1] > 39):
            raise ValueError("Invalid OID root")
        object_id = ".".join(str(component) for component in numeric_oid.asTuple())
    except (AttributeError, TypeError, ValueError, PyAsn1Error):
        raise CheckError("System object identifier unavailable or invalid (received: {})".format(
            text(object_value)))
    name = "unavailable"
    try:
        candidate = text(query(args, "sysName"))
        if candidate and not candidate.startswith("No Such"):
            name = candidate
    except CheckError:
        pass
    return 0, "Hostname: {}; Description: {}; sysObjectID: {}".format(
        name, description, object_id), "", []


def optional_entity_walk(args, key):
    try:
        return query(args, key, walk=True)
    except CheckError:
        return {}


def check_serial_numbers(args):
    serials = query(args, "entPhysicalSerialNum", walk=True)
    serials = {index: text(snmp_value_to_str(value)) for index, value in serials.items()
               if text(snmp_value_to_str(value))}
    if not serials:
        raise CheckError("No serial numbers returned by ENTITY-MIB")

    columns = {key: optional_entity_walk(args, key) for key in (
        "entPhysicalName", "entPhysicalClass", "entPhysicalModelName", "entPhysicalDescr")}
    class_labels = {
        1: "other", 2: "unknown", 3: "chassis", 4: "backplane", 5: "container",
        6: "powerSupply", 7: "fan", 8: "sensor", 9: "module", 10: "port",
        11: "stack", 12: "cpu", 13: "energyObject", 14: "battery",
    }
    details = []
    for index in sorted(serials):
        description = text(snmp_value_to_str(columns["entPhysicalDescr"].get(index, ""))) or "-"
        name = text(snmp_value_to_str(columns["entPhysicalName"].get(index, "")))
        if not name:
            name = description if description != "-" else "entity {}".format(index)
        model = text(snmp_value_to_str(columns["entPhysicalModelName"].get(index, ""))) or "unavailable"
        try:
            class_number = integer(columns["entPhysicalClass"][index], "entity class", 1, 14)
            entity_class = class_labels[class_number]
        except (KeyError, CheckError):
            entity_class = "unavailable"
        details.append("{} | {} | {} | {} | {}".format(
            index, name, entity_class, model, serials[index]))

    return (0, "{} components with serial numbers".format(len(serials)),
            "'serial_components'={};;;;".format(len(serials)),
            ["Index | Component | Class | Model | Serial number"] + details)


def parse_args(argv):
    parser = CheckParser(
        description=__doc__,
        usage=("%(prog)s -H HOST [-C COMMUNITY] [-P PORT] [-t SECONDS] --mode MODE [OPTIONS]\n"
               "       %(prog)s --hostname HOST [--community COMMUNITY] [--port PORT] "
               "[--timeout SECONDS] --mode MODE [OPTIONS]\n"
               "       %(prog)s -H HOST --user USER --mode MODE [SNMPv3 OPTIONS]\n"
               "\nModes:\n"
               "  cpu      Last-minute average CPU load and busiest logical processor\n"
               "  disk     Usage of selected mount paths; the busiest mount drives status\n"
               "  swap     Swap space usage (default warning 80%%, critical 90%%)\n"
               "  memory   Raw physical RAM usage including cache/buffers; informational\n"
               "           unless both --warning and --critical are supplied\n"
                "  memory_usage  Estimated active RAM use excluding cache/buffers\n"
                "                (not Linux MemAvailable)\n"
               "  uptime   SNMP-agent uptime in days/seconds, not OS uptime\n"
               "  timesync Clock skew vs monitoring host, not NTP status (seconds; defaults 5/30)\n"
                "  sysinfo  System description, object identifier and optional hostname\n"
                "  interfaces  Status of selected physical interfaces; counters are informational\n"
                "  serial-numbers  List ENTITY-MIB serial numbers"),
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=("Examples:\n"
                "  %(prog)s -H 172.23.38.11 -C '<community>' -P 161 -t 5 --mode cpu\n"
                "  %(prog)s --hostname 172.23.38.11 --community '<community>' "
                "--port 161 --timeout 5 --mode disk -v\n"
                "  %(prog)s -H 172.23.38.11 --mode memory\n"
                "  %(prog)s -H 172.23.38.11 --mode memory_usage\n"
                "  %(prog)s -H 172.23.38.11 --mode swap -w 80 -c 90\n"
                "  %(prog)s -H 172.23.38.11 --mode timesync -w 5 -c 30\n"
                "  %(prog)s -H 172.23.38.11 --mode interfaces -v\n"
                "  %(prog)s -H 172.23.38.11 --mode serial-numbers -v\n"
                "\nCredentials: use -C/--community or SNMP_COMMUNITY for SNMPv2c;\n"
                "SNMPv3 uses --user with SNMP_AUTHPW/SNMP_PRIVPW or password flags.\n"
                "Memory is informational unless both -w and -c are supplied."),
    )
    parser.add_argument("-H", "--hostname", required=True, help="ISE hostname or IP address")
    parser.add_argument("-C", "--community", help="SNMPv2c community (or SNMP_COMMUNITY)")
    parser.add_argument("-P", "--port", type=int, default=161, help="SNMP UDP port (default: 161)")
    parser.add_argument("--user", help="SNMPv3 username")
    parser.add_argument("--seclevel", default="authPriv",
                        choices=("noAuthNoPriv", "authNoPriv", "authPriv"))
    parser.add_argument("--auth", default="sha", choices=("sha", "md5"))
    parser.add_argument("--authpw", help="SNMPv3 auth password (or SNMP_AUTHPW)")
    parser.add_argument("--priv", default="aes", choices=("aes", "des"))
    parser.add_argument("--privpw", help="SNMPv3 privacy password (or SNMP_PRIVPW)")
    parser.add_argument("-t", "--timeout", type=int, default=5,
                        help="Per-request timeout in seconds (default: 5)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show processor or mount details")
    parser.add_argument("--mode", required=True,
                        choices=("cpu", "disk", "swap", "memory", "memory_usage", "uptime", "sysinfo", "interfaces",
                                 "serial-numbers", "timesync"),
                        help="Check to run (see Modes above)")
    parser.add_argument("-w", "--warning", type=float,
                        help="Percent (cpu/disk/swap default 80); seconds (timesync default 5)")
    parser.add_argument("-c", "--critical", type=float,
                        help="Percent (cpu/disk/swap default 90); seconds (timesync default 30)")
    parser.add_argument("--include-mounts", default=None, help="Required disk paths, comma-separated")
    parser.add_argument("--exclude-mounts", default=None, help="Disk paths to omit, comma-separated")
    parser.add_argument("--include-interfaces", default=None,
                        help="Interface names to monitor, comma-separated (overrides defaults)")
    parser.add_argument("--exclude-interfaces", default=None,
                        help="Interface names to omit, comma-separated")
    parser.add_argument("--rate-interval", type=float, default=None,
                        help="Seconds between interface rate samples (default 5, range >0 to 60)")
    arguments = sys.argv[1:] if argv is None else argv
    if not arguments:
        parser.print_help()
        parser.exit(3)
    args = parser.parse_args(arguments)
    args.community = args.community or os.environ.get("SNMP_COMMUNITY")
    args.authpw = args.authpw or os.environ.get("SNMP_AUTHPW")
    args.privpw = args.privpw or os.environ.get("SNMP_PRIVPW")
    if not args.community and not args.user:
        raise CheckError("Supply --community, SNMP_COMMUNITY or --user")
    if args.timeout <= 0:
        raise CheckError("Timeout must be positive")
    if not 1 <= args.port <= 65535:
        raise CheckError("Port must be between 1 and 65535")
    if args.user:
        if args.seclevel != "noAuthNoPriv" and not args.authpw:
            raise CheckError("SNMPv3 authentication password required")
        if args.seclevel == "authPriv" and not args.privpw:
            raise CheckError("SNMPv3 privacy password required")
    if args.mode != "disk" and (args.include_mounts is not None or args.exclude_mounts is not None):
        raise CheckError("Mount filters are only applicable to disk mode")
    if args.mode != "interfaces" and (args.include_interfaces is not None or args.exclude_interfaces is not None):
        raise CheckError("Interface filters are only applicable to interfaces mode")
    if args.rate_interval is not None:
        if args.mode != "interfaces":
            raise CheckError("--rate-interval is only applicable to interfaces mode")
        if not math.isfinite(args.rate_interval) or not 0 < args.rate_interval <= 60:
            raise CheckError("Rate interval must be finite and satisfy 0 < interval <= 60 seconds")
    args.rate_interval = 5.0 if args.rate_interval is None else args.rate_interval
    args.include_mounts = DEFAULT_MOUNTS if args.include_mounts is None else args.include_mounts
    args.exclude_mounts = args.exclude_mounts or ""
    return args


def main(argv=None):
    try:
        args = parse_args(argv)
        warning, critical = thresholds(args)
        load_snmp_dependencies()
        if args.mode == "uptime":
            result = check_uptime(args)
        elif args.mode == "timesync":
            result = check_timesync(args, warning, critical)
        elif args.mode == "memory_usage":
            result = check_memory_usage(args, warning, critical)
        elif args.mode == "sysinfo":
            result = check_sysinfo(args)
        elif args.mode == "interfaces":
            result = check_interfaces(args)
        elif args.mode == "serial-numbers":
            result = check_serial_numbers(args)
        else:
            result = {"cpu": check_cpu, "memory": check_memory, "disk": check_disk,
                      "swap": check_swap}[
                args.mode](args, warning, critical)
        code, summary, metrics, details = result
        print("{} - {}{}".format(NAGIOS_STATUS[code], summary, " | " + metrics if metrics else ""))
        if args.verbose:
            for detail in details:
                print(detail)
        return code
    except CheckError as error:
        print("{} - {}".format(NAGIOS_STATUS[error.code], text(error)))
        return error.code
    except KeyboardInterrupt:
        print("UNKNOWN - Check interrupted")
        return 3
    except ImportError:
        print("UNKNOWN - SNMP dependencies unavailable; verify pysnmp, pyasn1 and pycryptodomex")
        return 3
    except Exception:
        print("UNKNOWN - Unexpected check failure; verify SNMP data and configuration")
        return 3


if __name__ == "__main__":
    sys.exit(main())