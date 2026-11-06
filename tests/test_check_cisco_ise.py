import contextlib
import io
import os
import subprocess
import sys
import unittest
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
from pysnmp.proto.rfc1902 import OctetString
from unittest.mock import patch

import check_cisco_ise as ise
import ves_snmp_utils as snmp

ise.load_snmp_dependencies()


class ISECheckTests(unittest.TestCase):
    def run_check(self, mode, extra=(), walks=None, gets=None, rates=None):
        output = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), \
            patch.object(ise, "interface_rates", return_value=rates or {}), \
                patch.object(ise, "pysnmp_walk_indexed", side_effect=lambda args, oid: (
                    walks.get(oid, {}), 0)), \
                patch.object(ise, "pysnmp_get", side_effect=lambda args, oid: (
                    gets.get(oid, "No Such Object"), 0)), contextlib.redirect_stdout(output):
            code = ise.main(["-H", "172.23.38.11", "-C", "test-only", "--mode", mode] + list(extra))
        return code, output.getvalue()

    def storage(self, mounts=None):
        mounts = mounts if mounts is not None else ise.DEFAULT_MOUNTS.split(",")
        columns = {ise.OIDS[key]: {} for key in (
            "hrStorageType", "hrStorageDescr", "hrStorageAllocationUnits", "hrStorageSize", "hrStorageUsed")}
        for index, path in enumerate(mounts, 900):
            for key, value in (("hrStorageType", ise.DISK_TYPE), ("hrStorageDescr", path),
                               ("hrStorageAllocationUnits", 4096), ("hrStorageSize", 100),
                               ("hrStorageUsed", 20)):
                columns[ise.OIDS[key]][index] = value
        return columns

    def interfaces(self, names, admin=None, oper=None):
        indexes = set(names)
        return {
            ise.OIDS["ifName"]: names,
            ise.OIDS["ifAdminStatus"]: admin or {index: 1 for index in indexes},
            ise.OIDS["ifOperStatus"]: oper or {index: 1 for index in indexes},
            ise.OIDS["ifAlias"]: {index: "" for index in indexes},
            ise.OIDS["ifHighSpeed"]: {index: 1000 for index in indexes},
            ise.OIDS["ifInErrors"]: {index: 0 for index in indexes},
            ise.OIDS["ifOutErrors"]: {index: 0 for index in indexes},
            ise.OIDS["ifInDiscards"]: {index: 0 for index in indexes},
            ise.OIDS["ifOutDiscards"]: {index: 0 for index in indexes},
        }

    def test_cpu_normal_and_busiest_core(self):
        for loads, expected in (({196608: 2, 196609: 1}, 0), ({1: 1, 2: 80}, 1),
                                ({1: 1, 2: 90}, 2)):
            with self.subTest(loads=loads):
                code, output = self.run_check("cpu", walks={ise.OIDS["hrProcessorLoad"]: loads})
                self.assertEqual(code, expected)
                self.assertIn("cpu_max", output)
                self.assertIn("last-minute", output)

    def test_invalid_cpu(self):
        for loads in ({}, {1: -1}, {1: 101}, {1: "broken"}, {1: "nan"}):
            self.assertEqual(self.run_check("cpu", walks={ise.OIDS["hrProcessorLoad"]: loads})[0], 3)

    def rate_snapshot(self, value=100, marker=0, name="eth0", uptime=100):
        counters = {label: (value, 10.0) for label, _, _, _ in ise.INTERFACE_RATE_COUNTERS}
        return uptime, uptime, {2: (name, marker, marker, counters)}

    def test_interface_rates_use_measured_counter_intervals(self):
        first = self.rate_snapshot()
        second = self.rate_snapshot(value=110)
        for label, _, _, _ in ise.INTERFACE_RATE_COUNTERS:
            second[2][2][3][label] = (110, 12.0)
        second[2][2][3]["in_mbps"] = (1250100, 20.0)
        with patch.object(ise, "interface_rate_snapshot", side_effect=[first, second]), \
                patch.object(ise.time, "sleep") as sleep:
            rates = ise.interface_rates(SimpleNamespace(rate_interval=5), {2: "eth0"})
        self.assertEqual(rates[2]["in_mbps"], 1)
        self.assertEqual(rates[2]["in_errors_s"], 5)
        self.assertEqual(rates[2]["out_discards_s"], 5)
        sleep.assert_called_once_with(5)

    def test_interface_rates_suppress_resets_missing_data_and_renames(self):
        for second in (self.rate_snapshot(marker=1), self.rate_snapshot(marker=None),
                       self.rate_snapshot(name="eth1"), self.rate_snapshot(uptime=99),
                       self.rate_snapshot(uptime=None)):
            with patch.object(ise, "interface_rate_snapshot", side_effect=[self.rate_snapshot(), second]), \
                    patch.object(ise.time, "sleep"):
                self.assertEqual(ise.interface_rates(SimpleNamespace(rate_interval=1), {2: "eth0"}), {})
        first = self.rate_snapshot()
        second = self.rate_snapshot()
        for label, _, _, _ in ise.INTERFACE_RATE_COUNTERS:
            second[2][2][3][label] = (99, 12.0)
        second[2][2][3]["out_mbps"] = (None, 12.0)
        second[2][2][3]["in_errors_s"] = (100, 10.0)
        with patch.object(ise, "interface_rate_snapshot", side_effect=[first, second]), \
                patch.object(ise.time, "sleep"):
            self.assertEqual(ise.interface_rates(SimpleNamespace(rate_interval=1), {2: "eth0"}), {2: {}})

    def test_interface_rate_snapshot_validation_and_timing(self):
        def get_value(args, key, walk=False):
            if key == "sysUpTime":
                return 100
            if key == ise.OIDS["ifName"] + ".2":
                return "eth0"
            if key == ise.INTERFACE_DISCONTINUITY + ".2":
                return 0
            if key == ise.INTERFACE_RATE_COUNTERS[0][1] + ".2":
                return 4294967296
            return "No Such Object"
        with patch.object(ise, "query", side_effect=get_value), \
                patch.object(ise.time, "monotonic", side_effect=range(12)):
            snapshot = ise.interface_rate_snapshot(SimpleNamespace(), {2: "eth0"})
        self.assertEqual(snapshot[:2], (100, 100))
        self.assertEqual(snapshot[2][2][:3], ("eth0", 0, 0))
        self.assertEqual(snapshot[2][2][3]["in_mbps"], (4294967296, 0.5))
        self.assertEqual(snapshot[2][2][3]["out_mbps"], (None, 2.5))

    def test_interfaces_render_rates_and_preserve_status(self):
        rates = {2: {label: value for (label, _, _, _), value in
                     zip(ise.INTERFACE_RATE_COUNTERS, (1.25, 2.5, 3, 4, 5, 6))}}
        code, output = self.run_check("interfaces", ["-v"], self.interfaces({2: "eth0"}), rates=rates)
        self.assertEqual(code, 0)
        self.assertIn("traffic 1.250/2.500 Mbps", output)
        self.assertIn("error rate 3.000/4.000/s", output)
        self.assertIn("discard rate 5.000/6.000/s", output)
        self.assertIn("'if:eth0:in_mbps'=1.25;;;0;", output)
        self.assertIn("'if:eth0:out_discards_s'=6;;;0;", output)
        code, output = self.run_check("interfaces", ["-v"],
                                      self.interfaces({2: "eth0"}, oper={2: 2}), rates={})
        self.assertEqual(code, 2)
        self.assertIn("rates available for 0/1 interfaces", output)
        self.assertIn("traffic -/- Mbps", output)
        self.assertNotIn("'if:eth0:in_mbps'", output)

    def test_interface_rate_interval_validation(self):
        for interval in ("0", "-1", "61", "nan", "inf"):
            self.assertEqual(self.run_check("interfaces", ["--rate-interval", interval])[0], 3)
        self.assertEqual(self.run_check("cpu", ["--rate-interval", "1"])[0], 3)
        code, _ = self.run_check("interfaces", ["--rate-interval", "1"], self.interfaces({2: "eth0"}))
        self.assertEqual(code, 0)

    def test_interfaces_default_filters_and_details(self):
        walks = self.interfaces({1: "lo", 2: "eth0", 8: "podman2", 9: "veth0", 3: "eth1"})
        walks[ise.OIDS["ifAlias"]][2] = "management"
        walks[ise.OIDS["ifHighSpeed"]][2] = 1000
        walks[ise.OIDS["ifInDiscards"]][2] = 4
        code, output = self.run_check("interfaces", ["-v"], walks)
        self.assertEqual(code, 0)
        self.assertIn("All 2 monitored interfaces", output)
        self.assertIn("eth0 | management | UP | 1000 Mbps", output)
        self.assertNotIn("podman2", output)
        self.assertNotIn("veth0", output)
        self.assertNotIn("lo |", output)
        self.assertIn("'discards_total'=4", output)

    def test_interfaces_status_and_explicit_filters(self):
        walks = self.interfaces({2: "eth0", 3: "eth1", 4: "eth2"},
                                admin={2: 1, 3: 1, 4: 2},
                                oper={2: 1, 3: 2, 4: 2})
        code, output = self.run_check("interfaces", ["--include-interfaces", "eth0,eth1,eth2", "-v"], walks)
        self.assertEqual(code, 2)
        self.assertIn("1 of 3 monitored interfaces not up: eth1 (DOWN)", output)
        self.assertIn("eth2 | - | ADMIN DOWN", output)
        code, output = self.run_check("interfaces", ["--exclude-interfaces", "eth1"], walks)
        self.assertEqual(code, 0)
        self.assertIn("All 2 monitored interfaces", output)

    def test_interfaces_optional_speed_does_not_change_status(self):
        walks = self.interfaces({2: "eth0"})
        walks[ise.OIDS["ifHighSpeed"]][2] = "bad"
        code, output = self.run_check("interfaces", ["-v"], walks)
        self.assertEqual(code, 0)
        self.assertIn("eth0 | - | UP | -", output)

    def test_interfaces_invalid_rows_and_empty_selection(self):
        walks = self.interfaces({2: "eth0"})
        del walks[ise.OIDS["ifOperStatus"]][2]
        self.assertEqual(self.run_check("interfaces", walks=walks)[0], 3)
        self.assertEqual(self.run_check("interfaces", ["--include-interfaces", "missing"],
                                        self.interfaces({2: "eth0"}))[0], 3)
        self.assertEqual(self.run_check("interfaces", ["--include-interfaces", ""],
                        self.interfaces({2: "eth0"}))[0], 3)
        self.assertEqual(self.run_check("interfaces", walks={})[0], 3)

    def test_serial_numbers_and_best_effort_metadata(self):
        walks = {
            ise.OIDS["entPhysicalSerialNum"]: {1: " E65BBCDGM88 "},
            ise.OIDS["entPhysicalName"]: {1: ""},
            ise.OIDS["entPhysicalClass"]: {1: 1},
            ise.OIDS["entPhysicalModelName"]: {1: "ISE-VM-K9"},
            ise.OIDS["entPhysicalDescr"]: {1: "Cisco Identity Services Engine"},
        }
        code, output = self.run_check("serial-numbers", ["-v"], walks)
        self.assertEqual(code, 0)
        self.assertIn("1 components with serial numbers", output)
        self.assertIn("1 | Cisco Identity Services Engine | other | ISE-VM-K9 | E65BBCDGM88", output)
        self.assertIn("'serial_components'=1", output)

    def test_serial_numbers_without_rows_is_unknown(self):
        code, output = self.run_check("serial-numbers", walks={})
        self.assertEqual(code, 3)
        self.assertIn("No serial numbers returned by ENTITY-MIB", output)
        code, output = self.run_check("serial-numbers", ["-v"], walks={
            ise.OIDS["entPhysicalSerialNum"]: {1: "SERIAL-1"},
        })
        self.assertEqual(code, 0)
        self.assertIn("entity 1 | unavailable | unavailable | SERIAL-1", output)

    def test_defaults_index_discovery_and_exclusion(self):
        walks = self.storage(ise.DEFAULT_MOUNTS.split(",") + ["/run", "/opt/podman/containers/storage/overlay"])
        walks[ise.OIDS["hrStorageUsed"]][906] = 100
        code, output = self.run_check("disk", ["-v"], walks)
        self.assertEqual(code, 0)
        self.assertIn("6 mounts checked", output)
        self.assertNotIn("/run", output)
        self.assertIn("'disk:/'", output)
        self.assertIn("'disk:/opt'", output)
        self.assertIn("0.00/0.00 GiB", output)

    def test_storage_unit_conversion(self):
        walks = self.storage(["/"])
        walks[ise.OIDS["hrStorageAllocationUnits"]][900] = 1024 ** 3
        code, output = self.run_check("disk", ["--include-mounts", "/", "-v"], walks)
        self.assertEqual(code, 0)
        self.assertIn("20.00/100.00 GiB", output)

    def test_disk_unrounded_thresholds(self):
        walks = self.storage(["/"])
        walks[ise.OIDS["hrStorageSize"]][900] = 10000
        for used, expected in ((7999, 0), (8000, 1), (8999, 1), (9000, 2)):
            walks[ise.OIDS["hrStorageUsed"]][900] = used
            self.assertEqual(self.run_check("disk", ["--include-mounts", "/"], walks)[0], expected)

    def test_missing_duplicate_and_excluded_mounts(self):
        for paths in (["/"], ise.DEFAULT_MOUNTS.split(",") + ["/"]):
            self.assertEqual(self.run_check("disk", walks=self.storage(paths))[0], 3)
        code, _ = self.run_check("disk", ["--include-mounts", "/,/missing", "--exclude-mounts", "/missing"],
                                 self.storage(["/"]))
        self.assertEqual(code, 0)
        self.assertEqual(self.run_check("disk", ["--include-mounts", ""], self.storage())[0], 3)

    def test_invalid_selected_storage(self):
        for key, value in (("hrStorageSize", 0), ("hrStorageUsed", -1),
                           ("hrStorageUsed", 101), ("hrStorageAllocationUnits", 0),
                           ("hrStorageAllocationUnits", "bad"), ("hrStorageType", ise.RAM_TYPE)):
            walks = self.storage(["/"])
            walks[ise.OIDS[key]][900] = value
            self.assertEqual(self.run_check("disk", ["--include-mounts", "/"], walks)[0], 3)
        walks = self.storage(["/"])
        del walks[ise.OIDS["hrStorageAllocationUnits"]][900]
        self.assertEqual(self.run_check("disk", ["--include-mounts", "/"], walks)[0], 3)

    def test_memory_informational_and_explicit_alerting(self):
        walks = self.storage(["Physical memory"])
        for key, value in (("hrStorageType", ise.RAM_TYPE), ("hrStorageAllocationUnits", 1024),
                           ("hrStorageSize", 32639152), ("hrStorageUsed", 30572648)):
            walks[ise.OIDS[key]][900] = value
        code, output = self.run_check("memory", walks=walks)
        self.assertEqual(code, 0)
        self.assertIn("93.7%", output)
        self.assertIn("includes cache/buffers", output)
        self.assertIn("informational", output)
        self.assertEqual(self.run_check("memory", ["-w", "80", "-c", "90"], walks)[0], 2)
        self.assertEqual(self.run_check("memory", ["-w", "80"], walks)[0], 3)
        self.assertEqual(self.run_check("memory", walks=self.storage())[0], 3)

    def test_memory_usage_excludes_free_buffers_and_cache(self):
        gets = {ise.MEM_TOTAL_REAL: 32639152, ise.MEM_AVAIL_REAL: 1980928,
                ise.MEM_BUFFER: 56372, ise.MEM_CACHED: 7019900}
        code, output = self.run_check("memory_usage", gets=gets)
        self.assertEqual(code, 0)
        self.assertIn("Estimated active physical RAM used 72.3%", output)
        self.assertIn("not Linux MemAvailable", output)
        self.assertIn("informational, no thresholds configured", output)
        self.assertIn("'memory_active_used'", output)

    def test_memory_usage_thresholds_and_invalid_counters(self):
        gets = {ise.MEM_TOTAL_REAL: 100, ise.MEM_AVAIL_REAL: 0,
                ise.MEM_BUFFER: 0, ise.MEM_CACHED: 5}
        self.assertEqual(self.run_check("memory_usage", ["-w", "90", "-c", "95"], gets=gets)[0], 2)
        self.assertEqual(self.run_check("memory_usage", ["-w", "90"], gets=gets)[0], 3)
        for invalid in (-1, 101):
            bad = dict(gets)
            bad[ise.MEM_AVAIL_REAL] = invalid
            self.assertEqual(self.run_check("memory_usage", gets=bad)[0], 3)
        inconsistent = dict(gets)
        inconsistent[ise.MEM_CACHED] = 101
        self.assertEqual(self.run_check("memory_usage", gets=inconsistent)[0], 3)

    def test_swap_usage_and_unit_conversion(self):
        gets = {ise.MEM_TOTAL_SWAP: 8 * 1024 ** 2, ise.MEM_AVAIL_SWAP: 6 * 1024 ** 2}
        code, output = self.run_check("swap", gets=gets)
        self.assertEqual(code, 0)
        self.assertIn("Swap used 25.0% (2.00/8.00 GiB)", output)
        self.assertIn("'swap_used'=25%;80;90;0;100", output)

    def test_swap_unrounded_thresholds_and_overrides(self):
        for free, expected in ((10000, 0), (2001, 0), (2000, 1), (1001, 1), (1000, 2), (0, 2)):
            with self.subTest(free=free):
                gets = {ise.MEM_TOTAL_SWAP: 10000, ise.MEM_AVAIL_SWAP: free}
                self.assertEqual(self.run_check("swap", gets=gets)[0], expected)
        gets = {ise.MEM_TOTAL_SWAP: 100, ise.MEM_AVAIL_SWAP: 50}
        self.assertEqual(self.run_check("swap", ["-w", "40", "-c", "50"], gets=gets)[0], 2)
        self.assertEqual(self.run_check("swap", ["-w", "40"], gets=gets)[0], 1)
        self.assertEqual(self.run_check("swap", ["-w", "90", "-c", "80"], gets=gets)[0], 3)

    def test_swap_invalid_missing_and_zero_counters(self):
        for total, free in ((0, 0), (0, 1), (100, 101), (-1, 0), (100, -1),
                            ("No Such Object", 0), (100, "bad"),
                            (4294967296, 0), (100, 4294967296)):
            with self.subTest(total=total, free=free):
                code, output = self.run_check("swap", gets={
                    ise.MEM_TOTAL_SWAP: total, ise.MEM_AVAIL_SWAP: free})
                self.assertEqual(code, 3)
                self.assertNotIn("'swap_used'", output)
        self.assertEqual(self.run_check("swap", gets={})[0], 3)
        with patch.object(ise, "query", side_effect=ise.CheckError("SNMP timeout")):
            code, output = self.run_check("swap", gets={})
        self.assertEqual(code, 3)
        self.assertIn("SNMP timeout", output)

    def test_timesync_midpoint_thresholds_and_direction(self):
        device = OctetString(bytes((7, 234, 11, 3, 12, 55, 2, 0, 43, 0, 0)))
        device_time = datetime(2026, 11, 3, 12, 55, 2, tzinfo=timezone.utc)
        for offset, expected in ((0, 0), (4.9, 0), (5, 1), (-5, 1), (29.9, 1), (30, 2), (-30, 2)):
            with self.subTest(offset=offset):
                midpoint = device_time - timedelta(seconds=offset)
                with patch.object(ise, "datetime", wraps=datetime) as clock:
                    clock.now.side_effect = [midpoint - timedelta(seconds=1),
                                             midpoint + timedelta(seconds=1)]
                    code, output = self.run_check("timesync", gets={ise.OIDS["hrSystemDate"]: device})
                self.assertEqual(code, expected)
                self.assertIn("ahead" if offset >= 0 else "behind", output)
                self.assertIn("not NTP synchronization status", output)
                self.assertIn(";5;30;0;", output)

    def test_timesync_timezone_offsets_and_deciseconds(self):
        for hour, sign, offset_hour in ((14, 43, 2), (10, 45, 2)):
            with self.subTest(sign=sign):
                device = OctetString(bytes((7, 234, 11, 3, hour, 55, 2, 5, sign, offset_hour, 30)))
                reference_hour = 12 if sign == 43 else 13
                reference = datetime(2026, 11, 3, reference_hour, 25, 2, 500000, tzinfo=timezone.utc)
                with patch.object(ise, "datetime", wraps=datetime) as clock:
                    clock.now.return_value = reference
                    code, output = self.run_check("timesync", gets={ise.OIDS["hrSystemDate"]: device})
                self.assertEqual(code, 0)
                self.assertIn("'clock_skew'=0s;5;30;0;", output)

    def test_timesync_invalid_data_and_thresholds(self):
        valid = bytes((7, 234, 11, 3, 12, 55, 2, 0, 43, 0, 0))
        values = ["No Such Object", OctetString(valid[:8]), OctetString(b"")]
        for index, invalid in ((2, 13), (3, 0), (4, 24), (5, 60), (6, 60),
                               (7, 10), (8, 0), (9, 14), (10, 60)):
            octets = bytearray(valid)
            octets[index] = invalid
            values.append(OctetString(bytes(octets)))
        for value in values:
            with self.subTest(value=value):
                code, output = self.run_check("timesync", gets={ise.OIDS["hrSystemDate"]: value})
                self.assertEqual(code, 3)
                self.assertIn("Invalid hrSystemDate", output)
        for warning, critical in ((-1, 30), (5, 5), (30, 5), ("nan", 30), (5, "inf")):
            self.assertEqual(self.run_check("timesync", ["-w", str(warning), "-c", str(critical)], gets={})[0], 3)
        args = ise.parse_args(["-H", "ise", "-C", "test-only", "--mode", "timesync", "-c", "120"])
        self.assertEqual(ise.thresholds(args), (5, 120))

    def test_uptime(self):
        code, output = self.run_check("uptime", gets={ise.OIDS["sysUpTime"]: 389536126})
        self.assertEqual(code, 0)
        self.assertIn("45.09 days", output)
        self.assertIn("not OS uptime", output)
        for value in ("No Such Object", -1, 4294967296):
            self.assertEqual(self.run_check("uptime", gets={ise.OIDS["sysUpTime"]: value})[0], 3)

    def test_sysinfo_optional_name_and_sanitization(self):
        gets = {ise.OIDS["sysDescr"]: "Cisco Identity\nServices Engine | text",
                ise.SYS_OBJECT_ID: ".1.3.6.1.4.1.9.1.1426"}
        code, output = self.run_check("sysinfo", gets=gets)
        self.assertEqual(code, 0)
        self.assertIn("Hostname: unavailable", output)
        self.assertEqual(len(output.splitlines()), 1)
        self.assertNotIn("|", output)
        self.assertEqual(self.run_check("sysinfo", gets={})[0], 3)

    def test_sysinfo_typed_oid_with_symbolic_display(self):
        class SymbolicOID(ise.ObjectIdentifier):
            def prettyPrint(self):
                return "SNMPv2-SMI::enterprises.9.1.1426"

        from pysnmp.smi import builder, view
        from pysnmp.smi.rfc1902 import ObjectIdentity

        oid_string = "1.3.6.1.4.1.9.1.1426"
        resolved = ObjectIdentity(oid_string).resolveWithMib(view.MibViewController(builder.MibBuilder()))
        for value in (ise.ObjectIdentifier(oid_string), SymbolicOID(oid_string), resolved):
            with self.subTest(value_type=type(value).__name__):
                code, output = self.run_check("sysinfo", gets={
                    ise.OIDS["sysDescr"]: "Cisco Identity Services Engine",
                    ise.SYS_OBJECT_ID: value,
                    ise.OIDS["sysName"]: "SP-99941-ISE01"})
                self.assertEqual(code, 0)
                self.assertIn("sysObjectID: " + oid_string, output)
                self.assertIn("SP-99941-ISE01", output)

    def test_sysinfo_invalid_oid(self):
        for value in ("", "No Such Object", "No Such Instance", "1..3", "1", "3.1.2", "1.40.1", None):
            with self.subTest(value=value):
                code, output = self.run_check("sysinfo", gets={
                    ise.OIDS["sysDescr"]: "Cisco Identity Services Engine", ise.SYS_OBJECT_ID: value})
                self.assertEqual(code, 3)
                self.assertIn("System object identifier unavailable or invalid (received:", output)

    def test_configuration_errors(self):
        for mode, flags in (("cpu", ["-w", "nan"]), ("cpu", ["-c", "inf"]),
                            ("cpu", ["-w", "90", "-c", "80"]), ("cpu", ["-w", "-1"]),
                            ("uptime", ["-w", "5"]), ("sysinfo", ["-c", "90"]),
                            ("cpu", ["--include-mounts", "/"]), ("cpu", ["-t", "0"]),
                            ("cpu", ["--include-interfaces", "eth0"]),
                            ("interfaces", ["-w", "80"]),
                            ("memory_usage", ["-w", "80"]),
                            ("serial-numbers", ["-w", "5"]),
                            ("cpu", ["--unknown-option"]), ("cpu", ["--user", "test"] )):
            with self.subTest(mode=mode, flags=flags):
                self.assertEqual(self.run_check(mode, flags)[0], 3)

    def test_port_aliases_and_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            short = ise.parse_args(["-H", "node", "-C", "test-only", "-P", "1161",
                                    "-t", "2", "--mode", "cpu"])
            long = ise.parse_args(["--hostname", "node", "--community", "test-only",
                                   "--port", "1161", "--timeout", "2", "--mode", "cpu"])
            self.assertEqual(vars(short), vars(long))
            default = ise.parse_args(["-H", "node", "-C", "test-only", "--mode", "cpu"])
            self.assertEqual(default.port, 161)
            for value in ("0", "-1", "65536", "bad"):
                self.assertEqual(self.run_check("cpu", ["-P", value])[0], 3)
            for value in ("1", "65535"):
                self.assertEqual(ise.parse_args(["-H", "node", "-C", "test-only",
                                                "--mode", "cpu", "-P", value]).port, int(value))

    def test_shared_transport_port_for_get_and_walk(self):
        for port in (None, 1161):
            args = SimpleNamespace(hostname="node", timeout=2)
            if port is not None:
                args.port = port
            for function, command in ((snmp._pysnmp_get_single, "getCmd"),
                                      (snmp._pysnmp_walk_raw, "nextCmd")):
                with self.subTest(port=port, command=command), \
                        patch.object(snmp, "SnmpEngine"), \
                        patch.object(snmp, "UdpTransportTarget") as transport, \
                        patch.object(snmp, command, return_value=iter([
                            (None, 0, 0, [(None, 42)])])):
                    result, code = function(args, ise.OIDS["sysUpTime"], object())
                    self.assertEqual(code, 0)
                    self.assertIsNotNone(result)
                    transport.assert_called_once_with(("node", 161 if port is None else port),
                                                      timeout=2, retries=0)

    def test_help_usage_and_examples(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as result:
            ise.main(["--help"])
        self.assertEqual(result.exception.code, 0)
        help_text = output.getvalue()
        for expected in ("usage:", "-H HOST", "--hostname HOST", "-C COMMUNITY", "--community COMMUNITY",
                         "-P PORT", "--port PORT", "-t SECONDS", "--timeout SECONDS", "--mode MODE",
                         "Examples:", "Last-minute average", "SNMP_COMMUNITY"):
            self.assertIn(expected, help_text)
        usage_text = help_text.split("Nagios/Icinga infrastructure checks", 1)[0]
        self.assertIn("Modes:", usage_text)
        for expected in ("cpu      Last-minute average CPU load", "disk     Usage of selected mount paths",
                         "memory   Raw physical RAM usage", "uptime   SNMP-agent uptime",
                         "memory_usage  Estimated active RAM use",
                         "sysinfo  System description", "interfaces  Status of selected physical interfaces",
                         "serial-numbers  List ENTITY-MIB serial numbers",
                         "unless both --warning and --critical are supplied"):
            self.assertIn(expected, usage_text)

    def test_cli_startup_without_snmp_imports(self):
        bootstrap = (
            "import builtins, runpy, sys\n"
            "original_import = builtins.__import__\n"
            "def guarded_import(name, *args, **kwargs):\n"
            "    if name.split('.')[0] in ('ves_snmp_utils', 'pysnmp', 'pyasn1', 'Cryptodome'):\n"
            "        raise ImportError('SNMP imports blocked for test')\n"
            "    return original_import(name, *args, **kwargs)\n"
            "builtins.__import__ = guarded_import\n"
            "sys.argv = sys.argv[1:]\n"
            "runpy.run_path(sys.argv[0], run_name='__main__')\n"
        )
        cases = ((["--help"], 0, "Modes:"), ([], 3, "Modes:"),
                 (["--mode", "cpu"], 3, "required"),
                 (["-H", "node", "-C", "test-only", "--mode", "cpu"], 3,
                  "SNMP dependencies unavailable"))
        for arguments, expected_code, expected_text in cases:
            with self.subTest(arguments=arguments):
                result = subprocess.run([sys.executable, "-B", "-c", bootstrap, ise.__file__] + arguments,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, expected_code, result.stdout + result.stderr)
                self.assertIn(expected_text, result.stdout)
                self.assertNotIn("Traceback", result.stderr)

    def test_interrupt_during_dependency_loading(self):
        output = io.StringIO()
        with patch.object(ise, "load_snmp_dependencies", side_effect=KeyboardInterrupt), \
                contextlib.redirect_stdout(output):
            code = ise.main(["-H", "node", "-C", "test-only", "--mode", "cpu"])
        self.assertEqual(code, 3)
        self.assertEqual(output.getvalue(), "UNKNOWN - Check interrupted\n")

    def test_environment_credentials_and_v3(self):
        with patch.dict(os.environ, {"SNMP_COMMUNITY": "test-only", "SNMP_AUTHPW": "test-auth",
                                     "SNMP_PRIVPW": "test-priv"}, clear=True):
            args = ise.parse_args(["-H", "node", "--mode", "cpu"])
            self.assertEqual(args.community, "test-only")
            args = ise.parse_args(["-H", "node", "--mode", "cpu", "--user", "test-user"])
            self.assertEqual(args.authpw, "test-auth")
            self.assertEqual(args.privpw, "test-priv")
        with patch.dict(os.environ, {}, clear=True):
            args = ise.parse_args(["-H", "node", "--mode", "cpu", "--user", "test-user",
                                   "--seclevel", "noAuthNoPriv"])
            self.assertEqual(args.user, "test-user")
            with self.assertRaises(ise.CheckError):
                ise.parse_args(["-H", "node", "--mode", "cpu"])

    def test_timeout_and_optional_name_timeout(self):
        output = io.StringIO()
        with patch.object(ise, "pysnmp_walk_indexed", return_value=("UNKNOWN - SNMP timeout", 3)), \
                contextlib.redirect_stdout(output):
            code = ise.main(["-H", "172.23.38.12", "-C", "test-only", "--mode", "cpu"])
        self.assertEqual(code, 3)
        self.assertEqual(output.getvalue(), "UNKNOWN - SNMP timeout\n")
        args = ise.parse_args(["-H", "node", "-C", "test-only", "--mode", "sysinfo"])
        with patch.object(ise, "pysnmp_get", side_effect=[("Cisco Identity Services Engine", 0),
                          ("1.3.6.1.4.1.9.1.1426", 0), ("UNKNOWN - SNMP timeout", 3)]):
            self.assertEqual(ise.check_sysinfo(args)[0], 0)


if __name__ == "__main__":
    unittest.main()