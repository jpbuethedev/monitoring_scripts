import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
sys.path.insert(0, str(ROOT / "scripts"))
import ves_snmp_utils as snmp


class WlcSnmpTests(unittest.TestCase):
    def parse(self, *options):
        parser = argparse.ArgumentParser()
        snmp.add_snmp_args(parser, timeout_default=15, standard_aliases=True)
        args = parser.parse_args(["-H", "localhost", *options])
        snmp.prepare_wlc_snmp_args(args)
        return args

    def test_v1_v2_and_port(self):
        for protocol, model in (("1", 0), ("2c", 1)):
            args = self.parse("-p", protocol, "-P", "1161", "-C", "public")
            auth, is_v3 = snmp._build_auth_data(args)
            self.assertFalse(is_v3)
            self.assertEqual(auth.mpModel, model)
            self.assertEqual((args.port, args.timeout), (1161, 15))

    def test_shorthand_and_context(self):
        for separator in (",", ";"):
            shorthand = separator.join(("snmpv3", "sha", "authpass", "aes128", "privpass", "testuser", "0x8000000001", "mycontext"))
            args = self.parse("-C", shorthand)
            self.assertEqual((args.protocol, args.user, args.authpw, args.privpw), ("3", "testuser", "authpass", "privpass"))
            context = snmp._snmp_context(args)
            self.assertEqual(context.contextEngineId, bytes.fromhex("8000000001"))
            self.assertEqual(str(context.contextName), "mycontext")
            auth, is_v3 = snmp._build_auth_data(args)
            self.assertTrue(is_v3)
            self.assertEqual(auth.privProtocol, snmp.usmAesCfb128Protocol)
        args = self.parse("-C", "snmpv3,sha,authpass,aes,privpass,testuser,,mycontext")
        self.assertIsNone(args.contextengineid)
        self.assertEqual(args.contextname, "mycontext")

    def test_protocol_selection_and_fallback(self):
        args = self.parse("-p", "3", "--username", "testuser", "--authpassword", "authpass", "--privpassword", "privpass", "-C", "public")
        with patch.object(snmp, "_pysnmp_get_single", return_value=("error", 3)) as request:
            self.assertEqual(snmp.pysnmp_get(args, "1.3.6.1"), ("error", 3))
            self.assertEqual(request.call_count, 1)
        args = self.parse("--user", "testuser", "--authpw", "authpass", "--privpw", "privpass", "--community", "public")
        with patch.object(snmp, "_pysnmp_get_single", side_effect=[("error", 3), ("ok", 0)]) as request:
            self.assertEqual(snmp.pysnmp_get(args, "1.3.6.1"), ("ok", 0))
            self.assertEqual(request.call_count, 2)

    def test_context_and_port_reach_get_and_walk(self):
        args = self.parse("-P", "1161", "-C", "snmpv3,sha,authpass,aes,privpass,testuser,0x8000000001,mycontext")
        auth, _ = snmp._build_auth_data(args)
        with patch.object(snmp, "getCmd", return_value=iter([(None, None, None, [(None, "ok")])])) as request:
            self.assertEqual(snmp._pysnmp_get_single(args, "1.3.6.1", auth), ("ok", 0))
            self.assertEqual(request.call_args[0][2].transportAddr[1], 1161)
            self.assertEqual(str(request.call_args[0][3].contextName), "mycontext")
            self.assertEqual(request.call_args[0][3].contextEngineId, bytes.fromhex("8000000001"))
        with patch.object(snmp, "nextCmd", return_value=iter([])) as request:
            self.assertEqual(snmp._pysnmp_walk_raw(args, "1.3.6.1", auth), ([], 0))
            self.assertEqual(request.call_args[0][2].transportAddr[1], 1161)
            self.assertEqual(str(request.call_args[0][3].contextName), "mycontext")
            self.assertEqual(request.call_args[0][3].contextEngineId, bytes.fromhex("8000000001"))

    def test_privacy_algorithms_and_security_levels(self):
        for name, protocol in (("aes", snmp.usmAesCfb128Protocol), ("aes128", snmp.usmAesCfb128Protocol),
                               ("des", snmp.usmDESPrivProtocol), ("3des", snmp.usm3DESEDEPrivProtocol),
                               ("3desde", snmp.usm3DESEDEPrivProtocol)):
            args = self.parse("--username", "testuser", "--authpassword", "authpass", "--privpassword", "privpass", "--privprotocol", name)
            self.assertEqual(snmp._build_auth_data(args)[0].privProtocol, protocol)
        for level in ("noAuthNoPriv", "authNoPriv"):
            options = ["--username", "testuser", "--seclevel", level]
            if level == "authNoPriv":
                options += ["--authpassword", "authpass"]
            self.assertTrue(snmp._build_auth_data(self.parse(*options))[1])
        self.assertEqual(self.parse("--username", "testuser").seclevel, "noAuthNoPriv")
        self.assertEqual(self.parse("--username", "testuser", "--authpassword", "authpass").seclevel, "authNoPriv")
        self.assertEqual(self.parse("--username", "testuser", "--authpassword", "authpass", "--privpassword", "privpass").seclevel, "authPriv")

    def test_bad_arguments(self):
        for options in (("-C", "snmpv3,sha,secret"), ("-C", "snmpv3,sha,,aes,,testuser"),
                ("-p", "3", "--username", "testuser", "--seclevel", "authPriv"),
                        ("-C", "public", "-P", "65536"),
                        ("--username", "testuser", "--authpassword", "authpass", "--privpassword", "privpass", "--privprotocol", "bad"),
                        ("--username", "testuser", "--authpassword", "authpass", "--privpassword", "privpass", "--contextengineid", "0x123")):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.parse(*options)

    def test_python_help_and_invalid_cli(self):
        for name in ("check_cisco_wlc.py", "check_cisco_wlc_ntp.py", "check_cisco_fmc.py", "check_cisco_firewall.py", "check_cisco_ise.py"):
            script = str(ROOT / "scripts" / name)
            for flag in ("--help", "--usage", "-?", "--version", "-V"):
                result = subprocess.run([sys.executable, "-B", script, flag], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, (name, flag, result.stderr))
            options = ["-H", "localhost", "-p", "3", "--username", "testuser", "--seclevel", "authPriv"]
            if name != "check_cisco_wlc_ntp.py":
                options += ["--mode", "list-interfaces" if name == "check_cisco_wlc.py" else "cpu"]
            result = subprocess.run([sys.executable, "-B", script, *options], capture_output=True, text=True)
            self.assertEqual(result.returncode, 3)
            self.assertIn("authentication password is required", result.stdout)


PERL_MOCK = r'''
package Net::SNMP;
use strict;
use warnings;
use JSON::PP;
sub session {
    my ($class, %args) = @_;
    print STDERR "TRACE ", encode_json({session => \%args}), "\n";
    return (bless({}, $class), undef);
}
sub get_request {
    my ($self, %args) = @_;
    print STDERR "TRACE ", encode_json({request => \%args}), "\n";
    my %values = ('1.3.6.1.4.1.9.9.176.1.1.2.0' => 14, '1.3.6.1.4.1.9.9.176.1.1.6.0' => 1,
                  '1.3.6.1.4.1.9.9.176.1.1.4.0' => 9, '1.3.6.1.4.1.9.9.176.1.1.8.0' => 2,
                  '1.3.6.1.4.1.9.9.843.1.3.4.0' => 1);
    return {map { $_ => $values{$_} } @{$args{-varbindlist}}};
}
sub get_table {
    my ($self, %args) = @_;
    print STDERR "TRACE ", encode_json({table => \%args}), "\n";
    return { $args{-baseoid}.'.1' => 'sample' };
}
sub close { return 1; }
1;
'''


class PerlWlcSnmpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.perl = shutil.which("perl")
        if not cls.perl and os.environ.get("LOCALAPPDATA"):
            portable = Path(os.environ["LOCALAPPDATA"]) / "StrawberryPerlPortable" / "perl" / "bin" / "perl.exe"
            if portable.exists():
                cls.perl = str(portable)
        if not cls.perl:
            raise unittest.SkipTest("Perl is unavailable")
        cls.temp = tempfile.TemporaryDirectory()
        module = Path(cls.temp.name) / "Net" / "SNMP.pm"
        module.parent.mkdir()
        module.write_text(PERL_MOCK, encoding="ascii")
        cls.env = os.environ.copy()
        cls.env["PERL5LIB"] = cls.temp.name
        cls.env.pop("SNMP_AUTHPW", None)
        cls.env.pop("SNMP_PRIVPW", None)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def invoke(self, script, *options):
        result = subprocess.run([self.perl, str(script), *options], env=self.env, capture_output=True, text=True)
        traces = [json.loads(line[6:]) for line in result.stderr.splitlines() if line.startswith("TRACE ")]
        return result, traces

    def test_sessions_and_context(self):
        scripts = (WORKSPACE / "monitoring_scripts/scripts/check_cisco_wlc_ha.pl", WORKSPACE / "check_cisco_wlc_ha/check_cisco_wlc_ha.pl")
        for script in scripts:
            if not script.exists():
                continue
            with self.subTest(script=script):
                result, traces = self.invoke(script, "-H", "localhost", "-p", "1", "-C", "public", "-P", "1161")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((traces[0]["session"]["-version"], traces[0]["session"]["-port"], traces[0]["session"]["-timeout"]), (1, 1161, 15))
                result, traces = self.invoke(script, "-H", "localhost", "-C", "snmpv3,sha,authpass,aes128,privpass,testuser,0x8000000001,mycontext", "--ap-serial")
                self.assertEqual(result.returncode, 0, result.stderr)
                session = traces[0]["session"]
                self.assertEqual((session["-username"], session["-authpassword"], session["-privpassword"], session["-privprotocol"]), ("testuser", "authpass", "privpass", "aes128"))
                for trace in traces[1:]:
                    request = trace.get("request", trace.get("table"))
                    self.assertEqual((request["-contextengineid"], request["-contextname"]), ("0x8000000001", "mycontext"))
                result, traces = self.invoke(script, "--host", "localhost", "--version", "3", "--secname", "testuser", "--authpass", "authpass", "--privpass", "privpass")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(traces[0]["session"]["-version"], 3)
                result, _ = self.invoke(script, "-H", "localhost", "-C", "snmpv3,sha,short")
                self.assertEqual(result.returncode, 3)
                result, _ = self.invoke(script, "-H", "localhost", "-C", "snmpv3,sha,,aes,,testuser")
                self.assertEqual(result.returncode, 3)
                for flag in ("-?", "--usage", "-h", "--help", "-V", "--version"):
                    result, _ = self.invoke(script, flag)
                    self.assertEqual(result.returncode, 0, (flag, result.stderr))
                result, traces = self.invoke(script, "-H", "localhost", "-p", "3", "--username", "testuser", "--seclevel", "noAuthNoPriv")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("-authpassword", traces[0]["session"])
                result, traces = self.invoke(script, "-H", "localhost", "--username", "testuser", "--authpassword", "authpass")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(traces[0]["session"]["-authpassword"], "authpass")
                self.assertNotIn("-privpassword", traces[0]["session"])


if __name__ == "__main__":
    unittest.main()