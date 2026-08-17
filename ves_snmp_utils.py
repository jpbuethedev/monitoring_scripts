"""
ves_snmp_utils.py — Shared SNMP utilities for VES Nagios check scripts.

Provides:
  Subprocess-based (CLI snmpwalk):
    - run_subprocess()           : Safe subprocess wrapper with timeout
    - run_snmpwalk()             : CLI snmpwalk with v3 -> v2c fallback (string output)
    - run_snmpwalk_lines()       : CLI snmpwalk returning list of lines
    - run_snmpwalk_host()        : CLI snmpwalk for arbitrary host (not args.hostname)
    - parse_snmp_string_output() : Parse STRING values from snmpwalk output

  pysnmp-based (library):
    - pysnmp_get()               : SNMP GET with v3 -> v2c fallback
    - pysnmp_walk()              : SNMP WALK returning list of (oid_str, value) tuples
    - pysnmp_walk_dict()         : SNMP WALK returning dict keyed by last N OID octets
    - pysnmp_walk_indexed()      : SNMP WALK returning dict keyed by last OID index (int)
    - snmp_value_to_str()        : Convert pysnmp value to Python string

  Common:
    - add_snmp_args()            : Shared argparse SNMP v2c/v3 arguments
    - is_auth_error()            : Detect SNMP authentication failures in output
"""

import subprocess
import re
from pysnmp.hlapi import *


# -------------------------
# Common Model Dictionaries
# -------------------------

# Nagios status text indexed by exit code (0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN)
NAGIOS_STATUS = ("OK", "WARNING", "CRITICAL", "UNKNOWN")

# Cisco ciscoEnvMonState (CISCO-ENVMON-MIB) — shared by fan and power checks
CISCO_ENV_STATE_MAP = {
    1: "Normal",
    2: "Warning",
    3: "Critical",
    4: "Shutdown",
    5: "Not Present",
    6: "Not Functioning",
}

# Numeric representation for performance data (ciscoEnvMonState → perf int)
CISCO_ENV_STATE_NUMERIC = {1: 0, 2: 1, 3: 2, 4: 3, 6: 4}

# CISCO-ENTITY-SENSOR-MIB data mappings
SENSOR_DATA_TYPE = {
    1: 'other', 2: 'unknown', 3: 'voltsAC', 4: 'voltsDC', 5: 'amperes',
    6: 'watts', 7: 'hertz', 8: 'celsius', 9: 'percentRH', 10: 'rpm',
}

SENSOR_DATA_SCALE = {
    1: 'yocto', 2: 'zepto', 3: 'atto', 4: 'femto', 5: 'pico',
    6: 'nano', 7: 'micro', 8: 'milli', 9: 'units',
}

SENSOR_STATUS_MAP = {1: 'OK', 2: 'UNKNOWN', 3: 'CRITICAL'}

# -------------------------
# Centralized OID Dictionary
# -------------------------

OIDS = {
    # MIB-II System
    "sysDescr":               "1.3.6.1.2.1.1.1.0",
    "sysUpTime":              "1.3.6.1.2.1.1.3.0",
    "sysName":                "1.3.6.1.2.1.1.5.0",

    # MIB-II Interfaces
    "ifDescr":                "1.3.6.1.2.1.2.2.1.2",
    "ifAdminStatus":          "1.3.6.1.2.1.2.2.1.7",
    "ifOperStatus":           "1.3.6.1.2.1.2.2.1.8",

    # MIB-II ARP (ipNetToMediaTable)
    "arpIfIndex":             "1.3.6.1.2.1.4.22.1.1",
    "arpPhysAddress":         "1.3.6.1.2.1.4.22.1.2",
    "arpNetAddress":          "1.3.6.1.2.1.4.22.1.3",

    # ENTITY-MIB
    "entPhysicalDescr":       "1.3.6.1.2.1.47.1.1.1.1.2",
    "entPhysicalClass":       "1.3.6.1.2.1.47.1.1.1.1.5",
    "entPhysicalName":        "1.3.6.1.2.1.47.1.1.1.1.7",
    "entPhysicalSerialNum":   "1.3.6.1.2.1.47.1.1.1.1.11",
    "entPhysicalModelName":   "1.3.6.1.2.1.47.1.1.1.1.13",

    # ENTITY-STATE-MIB
    "entStateOper":           "1.3.6.1.2.1.131.1.1.1.7",

    # CISCO-ENTITY-FRU-CONTROL-MIB — Fan tray / power supply operational status
    # (not populated by ENTITY-STATE-MIB on ASA/FTD/Secure Firewall platforms)
    "cefcFanTrayOperStatus":      "1.3.6.1.4.1.9.9.117.1.4.1.1.1",
    "cefcFRUPowerOperStatus":     "1.3.6.1.4.1.9.9.117.1.1.2.1.2",

    # CISCO-ENTITY-SENSOR-MIB
    "entSensorType":              "1.3.6.1.4.1.9.9.91.1.1.1.1.1",
    "entSensorScale":             "1.3.6.1.4.1.9.9.91.1.1.1.1.2",
    "entSensorValue":             "1.3.6.1.4.1.9.9.91.1.1.1.1.4",
    "entSensorStatus":            "1.3.6.1.4.1.9.9.91.1.1.1.1.5",
    "entSensorThresholdLow":      "1.3.6.1.4.1.9.9.91.1.2.1.1.1",
    "entSensorThresholdHigh":     "1.3.6.1.4.1.9.9.91.1.2.1.1.2",

    # CISCO-ENVMON-MIB — Temperature
    "ciscoEnvMonTempDescr":       "1.3.6.1.4.1.9.9.13.1.3.1.2",
    "ciscoEnvMonTempValue":       "1.3.6.1.4.1.9.9.13.1.3.1.3",
    "ciscoEnvMonTempThreshold":   "1.3.6.1.4.1.9.9.13.1.3.1.4",

    # CISCO-ENVMON-MIB — Fan
    "ciscoEnvMonFanDescr":        "1.3.6.1.4.1.9.9.13.1.4.1.2",
    "ciscoEnvMonFanState":        "1.3.6.1.4.1.9.9.13.1.4.1.3",

    # CISCO-ENVMON-MIB — Power Supply
    "ciscoEnvMonSupplyDescr":     "1.3.6.1.4.1.9.9.13.1.5.1.2",
    "ciscoEnvMonSupplyState":     "1.3.6.1.4.1.9.9.13.1.5.1.3",

    # CISCO-MEMORY-POOL-MIB
    "ciscoMemPoolName":       "1.3.6.1.4.1.9.9.48.1.1.1.2",
    "ciscoMemPoolUsed":       "1.3.6.1.4.1.9.9.48.1.1.1.5",
    "ciscoMemPoolFree":       "1.3.6.1.4.1.9.9.48.1.1.1.6",

    # CISCO-HSRP-MIB
    "cHsrpGrpStandbyState":  "1.3.6.1.4.1.9.9.106.1.2.1.1.15",

    # CISCO-PROCESS-MIB — CPU
    "cpmCPUTotal5secRev":     "1.3.6.1.4.1.9.9.109.1.1.1.1.6",
    "cpmCPUTotal1minRev":     "1.3.6.1.4.1.9.9.109.1.1.1.1.7",
    "cpmCPUTotal5minRev":     "1.3.6.1.4.1.9.9.109.1.1.1.1.8",

    # CISCO-NTP-MIB
    "cntpPeersPeerAddr":      "1.3.6.1.4.1.9.9.168.1.2.1.1.3",
    "cntpPeersRefId":         "1.3.6.1.4.1.9.9.168.1.2.1.1.16",
    "cntpPeersOffset":        "1.3.6.1.4.1.9.9.168.1.2.1.1.20",

    # Cisco Image / Version
    "ciscoImageString":       "1.3.6.1.4.1.9.2.1.73.0",
    "ciscoImageVersion":      "1.3.6.1.4.1.9.9.305.1.1.1.0",

    # CISCO-STACKWISE-MIB
    "cswSwitchInfoTable":         "1.3.6.1.4.1.9.9.500.1.2.1.1",
    "cswStackGroupMemberCount":   "1.3.6.1.4.1.9.9.500.1.1.3.0",

    # CISCO-RESILIENT-ETHERNET-PROTOCOL-MIB — Segment
    "crepSegmentComplete":        "1.3.6.1.4.1.9.9.601.1.3.1.1.4",
    "crepSegmentPreempt":         "1.3.6.1.4.1.9.9.601.1.3.1.1.5",
    "crepSegmentPreemptStatus":   "1.3.6.1.4.1.9.9.601.1.3.1.1.6",

    # CISCO-RESILIENT-ETHERNET-PROTOCOL-MIB — Interface
    "crepIfTable":                "1.3.6.1.4.1.9.9.601.1.2.1.1",

    # CISCO-CDP-MIB
    "cdpCacheDeviceId":           "1.3.6.1.4.1.9.9.23.1.2.1.1.6",

    # IF-MIB (extended)
    "ifName":                     "1.3.6.1.2.1.31.1.1.1.1",
    "ifAlias":                    "1.3.6.1.2.1.31.1.1.1.18",

    # CISCO-FIREWALL-MIB — Hardware status (indices: 6=primaryUnit, 7=secondaryUnit)
    "cfwHardwareStatusValue":     "1.3.6.1.4.1.9.9.147.1.2.1.1.1.3",
    "cfwHardwareStatusDetail":    "1.3.6.1.4.1.9.9.147.1.2.1.1.1.4",

    # CISCO-FIREWALL-MIB cfwConnectionStatValue (Gauge32), indexed by
    # [cfwConnectionStatService=40 (entire firewall), cfwConnectionStatType=6 (currentInUse) / 7 (high)].
    # NOTE: the previous OIDs here (1.3.6.1.4.1.9.9.171.1.2.1.*) were wrong - that tree is
    # CISCO-IPSEC-FLOW-MONITOR-MIB (cikeGlobalIn* IKE/IPsec counters), unrelated to firewall
    # connections; device-verified via snmpwalk on all 4 test units (values were sane: currentInUse
    # 188-451, high 4560-5040, vs the old OIDs' 6.4M-6.8M/106K-114K IKE octet/packet counters).
    "connActiveConnections":  "1.3.6.1.4.1.9.9.147.1.2.2.2.1.5.40.6",
    "connPeakConnections":    "1.3.6.1.4.1.9.9.147.1.2.2.2.1.5.40.7",
    # No "failed connections" stat exists in cfwConnectionStatTable (ConnectionStat enum has no
    # failure type) - confirmed via full walk of the table on all 4 test devices, only
    # currentInUse/high were populated. There is no known equivalent OID for this metric.

    # CISCO-ENHANCED-MEMPOOL-MIB — used on ASA/FTD platforms instead of CISCO-MEMORY-POOL-MIB
    # (indexed by entPhysicalIndex, then cempMemPoolIndex)
    "cempMemPoolName":        "1.3.6.1.4.1.9.9.221.1.1.1.1.3",
    "cempMemPoolUsed":        "1.3.6.1.4.1.9.9.221.1.1.1.1.7",
    "cempMemPoolFree":        "1.3.6.1.4.1.9.9.221.1.1.1.1.8",
}

# Backward-compatible alias
IF_DESCR_OID = OIDS["ifDescr"]


# -------------------------
# Auth Error Detection
# -------------------------

_AUTH_ERROR_PATTERNS = [
    "authenticationfailure",
    "authorizationerror",
    "unknown user name",
    "wrong digest",
    "usmstatswrongdigests",
    "usmstatsunknownusernames",
    "snmp login failed",
]


def is_auth_error(output):
    """Check if SNMP output indicates an authentication/authorization failure."""
    lower = output.lower()
    return any(p in lower for p in _AUTH_ERROR_PATTERNS)


def is_timeout_error(indication):
    """Check if an SNMP errorIndication represents a timeout/unreachable host."""
    lower = str(indication).lower()
    return "timeout" in lower or "timed out" in lower


# -------------------------
# Common Argparse Arguments
# -------------------------

def add_snmp_args(parser, timeout_default=30):
    """Add standard SNMP v2c/v3 and output arguments to an argparse parser."""
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--community")
    parser.add_argument("--user")
    parser.add_argument("--seclevel", default="authPriv",
                        choices=["noAuthNoPriv", "authNoPriv", "authPriv"])
    parser.add_argument("--auth", default="sha")
    parser.add_argument("--authpw")
    parser.add_argument("--priv", default="aes")
    parser.add_argument("--privpw")
    parser.add_argument("--timeout", type=int, default=timeout_default)
    parser.add_argument("--multiline", action="store_true")


# -------------------------
# pysnmp Auth Builder
# -------------------------

def _build_auth_data(args):
    """Build pysnmp auth data from args. Returns (auth_data, is_v3)."""
    if args.user:
        seclevel = getattr(args, 'seclevel', 'authPriv')
        if seclevel == 'authPriv':
            auth_proto = usmHMACSHAAuthProtocol if args.auth.lower() == 'sha' else usmHMACMD5AuthProtocol
            priv_proto = usmAesCfb128Protocol if args.priv.lower() == 'aes' else usmDESPrivProtocol
            return UsmUserData(args.user, args.authpw, args.privpw,
                               authProtocol=auth_proto, privProtocol=priv_proto), True
        elif seclevel == 'authNoPriv':
            auth_proto = usmHMACSHAAuthProtocol if args.auth.lower() == 'sha' else usmHMACMD5AuthProtocol
            return UsmUserData(args.user, args.authpw,
                               authProtocol=auth_proto), True
        else:  # noAuthNoPriv
            return UsmUserData(args.user), True
    elif args.community:
        return CommunityData(args.community, mpModel=1), False
    return None, False


# -------------------------
# pysnmp Value Conversion
# -------------------------

def snmp_value_to_str(val):
    """Convert pysnmp OctetString or other SNMP type to Python string."""
    try:
        if hasattr(val, 'prettyPrint'):
            return val.prettyPrint()
        return str(val)
    except Exception:
        return str(val)


# -------------------------
# pysnmp GET (v3 -> v2c)
# -------------------------

def _pysnmp_get_single(args, oid, auth_data):
    """Single SNMP GET using given auth_data. Returns (value, rc)."""
    try:
        iterator = getCmd(
            SnmpEngine(),
            auth_data,
            UdpTransportTarget((args.hostname, 161), timeout=args.timeout, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        if errorIndication:
            if "authorization" in str(errorIndication).lower():
                return "CRITICAL - Invalid credentials", 2
            if is_timeout_error(errorIndication):
                return f"UNKNOWN - SNMP timeout: {errorIndication}", 3
            return f"CRITICAL - SNMP error: {errorIndication}", 2
        if errorStatus:
            return f"CRITICAL - SNMP error at {errorIndex}: {errorStatus.prettyPrint()}", 2
        for varBind in varBinds:
            return varBind[1], 0
    except Exception as e:
        return f"CRITICAL - SNMP get failed: {e}", 2


def pysnmp_get(args, oid):
    """SNMP GET with v3 -> v2c fallback. Returns (value, rc)."""
    if args.user:
        auth_v3, _ = _build_auth_data(args)
        value, rc = _pysnmp_get_single(args, oid, auth_v3)
        if rc == 0:
            return value, rc
    if args.community:
        auth_v2 = CommunityData(args.community, mpModel=1)
        return _pysnmp_get_single(args, oid, auth_v2)
    return "CRITICAL - No SNMP credentials provided", 2


# -------------------------
# pysnmp WALK (v3 -> v2c)
# -------------------------

def _pysnmp_walk_raw(args, oid, auth_data):
    """Core walk returning list of (oid_obj, value). Returns (result_list, rc)."""
    result = []
    try:
        for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
            SnmpEngine(),
            auth_data,
            UdpTransportTarget((args.hostname, 161), timeout=args.timeout, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False
        ):
            if errorIndication:
                if "authorization" in str(errorIndication).lower():
                    return "CRITICAL - Invalid credentials", 2
                if is_timeout_error(errorIndication):
                    return f"UNKNOWN - SNMP timeout: {errorIndication}", 3
                return f"CRITICAL - SNMP error: {errorIndication}", 2
            if errorStatus:
                return f"CRITICAL - SNMP error at {errorIndex}: {errorStatus.prettyPrint()}", 2
            for varBind in varBinds:
                result.append((varBind[0], varBind[1]))
        return result, 0
    except Exception as e:
        return f"CRITICAL - SNMP walk failed: {e}", 2


def _pysnmp_walk_with_fallback(args, oid):
    """Walk with v3 -> v2c fallback. Returns raw (list_of_tuples, rc)."""
    if args.user:
        auth_v3, _ = _build_auth_data(args)
        output, rc = _pysnmp_walk_raw(args, oid, auth_v3)
        if rc == 0:
            return output, rc
        if args.community:
            auth_v2 = CommunityData(args.community, mpModel=1)
            return _pysnmp_walk_raw(args, oid, auth_v2)
        return output, rc
    elif args.community:
        auth_v2 = CommunityData(args.community, mpModel=1)
        return _pysnmp_walk_raw(args, oid, auth_v2)
    return "CRITICAL - No SNMP credentials provided", 2


def pysnmp_walk(args, oid):
    """SNMP WALK returning list of (oid_string, value) tuples.
    Used by stack_health. Returns (list, rc) or (error_string, rc)."""
    output, rc = _pysnmp_walk_with_fallback(args, oid)
    if rc != 0:
        return output, rc
    result = [(obj.prettyPrint(), val) for obj, val in output]
    return result, 0


def pysnmp_walk_dict(args, oid, key_depth=5):
    """SNMP WALK returning dict keyed by last `key_depth` OID octets.
    Used by arp_summary. Returns (dict, rc) or (error_string, rc)."""
    output, rc = _pysnmp_walk_with_fallback(args, oid)
    if rc != 0:
        return output, rc
    result = {}
    for obj, val in output:
        idx = '.'.join(str(obj).split('.')[-key_depth:])
        result[idx] = val
    return result, 0


def pysnmp_walk_indexed(args, oid):
    """SNMP WALK returning dict keyed by last OID index (int).
    Used by hardware_health. Returns (dict, rc) or (error_string, rc)."""
    output, rc = _pysnmp_walk_with_fallback(args, oid)
    if rc != 0:
        return output, rc
    result = {}
    for obj, val in output:
        idx = int(str(obj).split('.')[-1])
        result[idx] = val
    return result, 0


def pysnmp_walk_multi_indexed(args, oid, key_depth=2):
    """SNMP WALK returning dict keyed by a tuple of the last `key_depth` OID index integers.
    Used for tables with composite indices (e.g. cempMemPoolTable, cfwConnectionStatTable).
    Returns (dict, rc) or (error_string, rc)."""
    output, rc = _pysnmp_walk_with_fallback(args, oid)
    if rc != 0:
        return output, rc
    result = {}
    for obj, val in output:
        parts = str(obj).split('.')[-key_depth:]
        result[tuple(int(p) for p in parts)] = val
    return result, 0


# -------------------------
# Subprocess Runner
# -------------------------

def _build_snmpv3_cli_args(args):
    """Build SNMPv3 CLI arguments for snmpwalk/snmpget based on seclevel."""
    seclevel = getattr(args, 'seclevel', 'authPriv')
    cli = ["-v3", "-l", seclevel, "-u", args.user]
    if seclevel in ('authNoPriv', 'authPriv'):
        cli += ["-a", args.auth, "-A", args.authpw]
    if seclevel == 'authPriv':
        cli += ["-x", args.priv, "-X", args.privpw]
    return cli


def _build_nwc_health_v3_args(args):
    """Build check_nwc_health SNMPv3 arguments based on seclevel."""
    seclevel = getattr(args, 'seclevel', 'authPriv')
    cli = ["--username", args.user]
    if seclevel in ('authNoPriv', 'authPriv'):
        cli += ["--authprotocol", args.auth, "--authpassword", args.authpw]
    if seclevel == 'authPriv':
        cli += ["--privprotocol", args.priv, "--privpassword", args.privpw]
    return cli


def run_subprocess(cmd, timeout):
    """Run a command via subprocess with timeout.
    Returns (stdout, stderr, returncode).
    On timeout returns ('', '', -1)."""
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "", -1


# -------------------------
# Subprocess-based SNMP Walk
# -------------------------

def run_snmpwalk(args, oid):
    """Run snmpwalk via subprocess with SNMPv3 -> SNMPv2c fallback.

    Returns (output_string, return_code):
      - On success:    (stdout_stripped, 0)
      - On auth error: ("CRITICAL - Invalid credentials", 2)
      - On timeout:    ("CRITICAL - SNMP timeout", 2)
      - On failure:    ("CRITICAL - Invalid credentials", 2)
    """
    # Try SNMPv3 first
    if args.user:
        cmd = ["snmpwalk"] + _build_snmpv3_cli_args(args) + [args.hostname, oid]
        stdout, stderr, rc = run_subprocess(cmd, args.timeout)
        if rc == -1:
            return "CRITICAL - SNMP timeout", 2
        if rc != 0 and is_auth_error(stdout + stderr):
            return "CRITICAL - Invalid credentials", 2
        if rc == 0:
            return stdout.strip(), 0
        # Non-auth v3 failure — fall through to v2c

    # Fallback to SNMPv2c
    if args.community:
        cmd = [
            "snmpwalk", "-v2c",
            "-c", args.community,
            args.hostname, oid
        ]
        stdout, stderr, rc = run_subprocess(cmd, args.timeout)
        if rc == -1:
            return "CRITICAL - SNMP timeout", 2
        if rc == 0:
            return stdout.strip(), 0

    return "CRITICAL - Invalid credentials", 2


def run_snmpwalk_lines(args, oid):
    """Run snmpwalk via subprocess, returning output as list of lines.

    Returns list of strings on success.
    Prints error and calls sys.exit(3) on failure (Nagios UNKNOWN).
    """
    import sys
    output, rc = run_snmpwalk(args, oid)
    if rc != 0:
        print(f"UNKNOWN - SNMP error: {output}")
        sys.exit(3)
    return output.strip().splitlines() if output else []


def run_snmpwalk_numeric(args, oid):
    """Run snmpwalk via subprocess with -On (numeric OID output).

    Returns (output_string, return_code) with v3 -> v2c fallback.
    """
    if args.user:
        cmd = ["snmpwalk", "-On"] + _build_snmpv3_cli_args(args) + [args.hostname, oid]
        stdout, stderr, rc = run_subprocess(cmd, args.timeout)
        if rc == -1:
            return "CRITICAL - SNMP timeout", 2
        if rc != 0 and is_auth_error(stdout + stderr):
            return "CRITICAL - Invalid credentials", 2
        if rc == 0:
            return stdout.strip(), 0

    if args.community:
        cmd = [
            "snmpwalk", "-v2c", "-On",
            "-c", args.community,
            args.hostname, oid
        ]
        stdout, stderr, rc = run_subprocess(cmd, args.timeout)
        if rc == -1:
            return "CRITICAL - SNMP timeout", 2
        if rc == 0:
            return stdout.strip(), 0

    return "CRITICAL - Invalid credentials", 2


def run_snmpget(args, oid):
    """Run snmpget via subprocess with -Oqv (quiet value only).

    Returns (value_string, return_code) with v3 -> v2c fallback.
    """
    if args.user:
        cmd = ["snmpget", "-Oqv"] + _build_snmpv3_cli_args(args) + [args.hostname, oid]
        stdout, stderr, rc = run_subprocess(cmd, args.timeout)
        if rc == -1:
            return "CRITICAL - SNMP timeout", 2
        if rc != 0 and is_auth_error(stdout + stderr):
            return "CRITICAL - Invalid credentials", 2
        if rc == 0:
            return stdout.strip(), 0

    if args.community:
        cmd = [
            "snmpget", "-v2c", "-Oqv",
            "-c", args.community,
            args.hostname, oid
        ]
        stdout, stderr, rc = run_subprocess(cmd, args.timeout)
        if rc == -1:
            return "CRITICAL - SNMP timeout", 2
        if rc == 0:
            return stdout.strip(), 0

    return "CRITICAL - Invalid credentials", 2


def run_snmpwalk_host(host, oid, community=None, user=None, auth=None,
                      authpw=None, priv=None, privpw=None, seclevel='authPriv',
                      timeout=30):
    """Run snmpwalk for a specific host (not args.hostname).
    Used by HSRP to query multiple group members.

    Returns list of output lines.
    Raises RuntimeError on failure.
    """
    cmd = ["snmpwalk"]
    if user:
        cmd += ["-v3", "-l", seclevel, "-u", user]
        if seclevel in ('authNoPriv', 'authPriv'):
            cmd += ["-a", auth, "-A", authpw]
        if seclevel == 'authPriv':
            cmd += ["-x", priv, "-X", privpw]
    else:
        cmd += ["-v2c", "-c", community]
    cmd += ["-t", str(timeout), host, oid]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=timeout)
        if result.returncode != 0:
            raise RuntimeError(f"SNMP ERROR: {result.stdout.strip()}")
        return result.stdout.strip().split("\n")
    except subprocess.TimeoutExpired:
        raise RuntimeError("SNMP timeout")


# -------------------------
# SNMP Output Parsing
# -------------------------

def parse_snmp_string_output(output):
    """Parse snmpwalk output for STRING values.
    Returns dict: {oid_index: value_string}."""
    parsed = {}
    if not output:
        return parsed
    for line in output.strip().split("\n"):
        match = re.match(r".*::.*\.(\d+) = STRING: \"?(.*?)\"?$", line)
        if match:
            index, value = match.groups()
            parsed[index] = value.strip()
    return parsed
