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
import os
import argparse
import sys
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
    "ifInDiscards":           "1.3.6.1.2.1.2.2.1.13",
    "ifInErrors":             "1.3.6.1.2.1.2.2.1.14",
    "ifOutDiscards":          "1.3.6.1.2.1.2.2.1.19",
    "ifOutErrors":            "1.3.6.1.2.1.2.2.1.20",

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

    # HOST-RESOURCES-MIB — CPU load and storage (RAM/disk) tables, used on Linux-based
    # appliances (e.g. FMC) instead of the IOS-only CISCO-PROCESS-MIB / CISCO-MEMORY-POOL-MIB
    "hrSystemDate":           "1.3.6.1.2.1.25.1.2.0",
    "hrProcessorLoad":        "1.3.6.1.2.1.25.3.3.1.2",
    "hrStorageType":          "1.3.6.1.2.1.25.2.3.1.2",
    "hrStorageDescr":         "1.3.6.1.2.1.25.2.3.1.3",
    "hrStorageAllocationUnits": "1.3.6.1.2.1.25.2.3.1.4",
    "hrStorageSize":          "1.3.6.1.2.1.25.2.3.1.5",
    "hrStorageUsed":          "1.3.6.1.2.1.25.2.3.1.6",

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

    # NTPv4-MIB (RFC 5907) — standard NTP status; populated on Cisco C9800 WLC where the
    # CISCO-NTP-MIB peer offset column is empty
    "ntpEntStatusCurrentMode":        "1.3.6.1.2.1.197.1.2.1.0",
    "ntpEntStatusStratum":            "1.3.6.1.2.1.197.1.2.2.0",
    "ntpEntStatusActiveRefSourceId":  "1.3.6.1.2.1.197.1.2.3.0",
    "ntpEntStatusActiveOffset":       "1.3.6.1.2.1.197.1.2.5.0",
    "ntpEntStatusDispersion":         "1.3.6.1.2.1.197.1.2.7.0",
    "ntpAssocRefId":                  "1.3.6.1.2.1.197.1.3.1.1.3",
    "ntpAssocAddress":                "1.3.6.1.2.1.197.1.3.1.1.5",
    "ntpAssocOffset":                 "1.3.6.1.2.1.197.1.3.1.1.6",
    "ntpAssocStratum":                "1.3.6.1.2.1.197.1.3.1.1.7",

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
    "ifHighSpeed":                "1.3.6.1.2.1.31.1.1.1.15",

    # CISCO-FIREWALL-MIB — Hardware status (indices: 6=primaryUnit, 7=secondaryUnit)
    "cfwHardwareStatusValue":     "1.3.6.1.4.1.9.9.147.1.2.1.1.1.3",
    "cfwHardwareStatusDetail":    "1.3.6.1.4.1.9.9.147.1.2.1.1.1.4",
    # cfwHardwareInformation (column 2) is self-referential rather than pair-mirrored: on
    # real devices its text includes "(this device)" only on the row (6=primary/7=secondary)
    # matching the unit that actually answered the query - used to label which IP is which
    # role in ha_pair output. Confirmed against the official CISCO-FIREWALL-MIB definition.
    "cfwHardwareInformation":     "1.3.6.1.4.1.9.9.147.1.2.1.1.1.2",

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

class _UsageAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        parser.print_usage()
        parser.exit()


def add_snmp_args(parser, timeout_default=30, standard_aliases=False):
    """Add standard SNMP v2c/v3 and output arguments to an argparse parser."""
    parser.add_argument(*(["-H", "--hostname"] if standard_aliases else ["--hostname"]), required=True)
    parser.add_argument(*(["-C", "--community"] if standard_aliases else ["--community"]),
                        help="Community, or snmpv3,authproto,authpass,privproto,privpass,username[,contextengineid][,contextname]" if standard_aliases else None)
    parser.add_argument(*(["--user", "--username"] if standard_aliases else ["--user"]),
                        help="SNMPv3 security username" if standard_aliases else None)
    parser.add_argument("--seclevel", default=None if standard_aliases else "authPriv",
                        choices=["noAuthNoPriv", "authNoPriv", "authPriv"],
                        help="SNMPv3 security level; inferred from passwords when omitted" if standard_aliases else None)
    parser.add_argument(*(["--auth", "--authprotocol"] if standard_aliases else ["--auth"]), default="sha",
                        help="SNMPv3 authentication protocol: sha or md5 (default sha)" if standard_aliases else None)
    parser.add_argument(*(["--authpw", "--authpassword"] if standard_aliases else ["--authpw"]),
                        help="Authentication password; alternatively SNMP_AUTHPW" if standard_aliases else None)
    parser.add_argument(*(["--priv", "--privprotocol"] if standard_aliases else ["--priv"]), default="aes",
                        help="SNMPv3 privacy protocol: aes, aes128, des, 3des or 3desde (default aes)" if standard_aliases else None)
    parser.add_argument(*(["--privpw", "--privpassword"] if standard_aliases else ["--privpw"]),
                        help="Privacy password; alternatively SNMP_PRIVPW" if standard_aliases else None)
    parser.add_argument(*(["-t", "--timeout"] if standard_aliases else ["--timeout"]), type=int, default=timeout_default,
                        help="Seconds per SNMP request (default {})".format(timeout_default) if standard_aliases else None)
    parser.add_argument("--multiline", action="store_true")
    if standard_aliases:
        parser.add_argument("-?", "--usage", action=_UsageAction, nargs=0, help="Show usage and exit")
        parser.add_argument("-V", "--version", action="version", version="%(prog)s 1.0.0")
        parser.add_argument("-v", "--verbose", action="count", default=0, help="Show SNMP debug details (up to 3 times)")
        parser.add_argument("-P", "--port", type=int, default=161, help="SNMP port (default 161)")
        parser.add_argument("-p", "--protocol", choices=["1", "2c", "3"], help="SNMP protocol (default 2c; 3 when username is supplied)")
        parser.add_argument("--contextengineid", help="SNMPv3 context engine ID as hexadecimal")
        parser.add_argument("--contextname", help="SNMPv3 context name")
        parser.epilog = (parser.epilog or "") + "\nSNMPv3 shorthand examples: snmpv3,sha,authpass,aes,privpass,user and snmpv3,sha,authpass,aes,privpass,user,,contextname. Use any single-character separator. CLI credentials may be visible in process listings."


def prepare_wlc_snmp_args(args):
    """Normalize and validate the WLC checks' SNMP options."""
    shorthand = args.community and args.community.lower().startswith("snmpv3")
    if shorthand:
        if len(args.community) < 7:
            raise ValueError("Invalid SNMPv3 community shorthand")
        fields = args.community.split(args.community[6])
        if len(fields) < 6 or len(fields) > 8 or fields[0].lower() != "snmpv3":
            raise ValueError("Invalid SNMPv3 community shorthand")
        if not fields[2] or not fields[4] or not fields[5]:
            raise ValueError("SNMPv3 shorthand requires username and both passwords")
        if args.protocol not in (None, "3") or args.user or args.authpw or args.privpw:
            raise ValueError("SNMPv3 shorthand cannot be combined with other credentials or an SNMPv1/v2c protocol")
        args.auth, args.authpw, args.priv, args.privpw, args.user = fields[1:6]
        if len(fields) > 6:
            if args.contextengineid:
                raise ValueError("Context engine ID specified twice")
            args.contextengineid = fields[6] or None
        if len(fields) > 7:
            if args.contextname:
                raise ValueError("Context name specified twice")
            args.contextname = fields[7] or None
        args.community = None
        args.protocol = "3"
    args.authpw = args.authpw or os.environ.get("SNMP_AUTHPW")
    args.privpw = args.privpw or os.environ.get("SNMP_PRIVPW")
    args._wlc_snmp = True
    args.legacy_fallback = args.protocol is None and bool(args.user and args.community)
    if args.protocol is None:
        args.protocol = "3" if args.user else "2c"
    if not 1 <= args.port <= 65535:
        raise ValueError("--port must be between 1 and 65535")
    if args.timeout <= 0:
        raise ValueError("--timeout must be positive")
    if args.verbose > 3:
        raise ValueError("--verbose can be repeated at most 3 times")
    if args.protocol == "3":
        if not args.user:
            raise ValueError("SNMPv3 requires --username")
        if args.seclevel is None:
            args.seclevel = "authPriv" if args.privpw else "authNoPriv" if args.authpw else "noAuthNoPriv"
        args.auth = args.auth.lower()
        args.priv = args.priv.lower()
        if args.auth not in ("sha", "md5"):
            raise ValueError("Unsupported SNMPv3 authentication protocol")
        if args.priv not in ("aes", "aes128", "des", "3des", "3desde", "3desede"):
            raise ValueError("Unsupported SNMPv3 privacy protocol")
        if args.seclevel in ("authNoPriv", "authPriv") and not args.authpw:
            raise ValueError("SNMPv3 authentication password is required")
        if args.seclevel == "authPriv" and not args.privpw:
            raise ValueError("SNMPv3 privacy password is required")
    elif not args.community:
        raise ValueError("SNMPv1/v2c requires --community")
    elif args.user:
        raise ValueError("--username requires SNMPv3")
    if args.contextengineid:
        engine = args.contextengineid
        hex_engine = engine[2:] if engine.lower().startswith("0x") else engine
        if not re.fullmatch(r"[0-9a-fA-F]{10,64}", hex_engine) or len(hex_engine) % 2:
            raise ValueError("--contextengineid must be 5 to 32 bytes of hexadecimal")
    if args.contextname and len(args.contextname.encode("utf-8")) > 32:
        raise ValueError("--contextname must be at most 32 bytes")
    if args.protocol != "3" and (args.contextengineid or args.contextname):
        raise ValueError("SNMP context requires SNMPv3")
    if args.verbose:
        print("SNMPv{} target={} port={} timeout={}".format(args.protocol, args.hostname, args.port, args.timeout), file=sys.stderr)
    if args.verbose > 1 and args.protocol == "3":
        print("SNMPv3 security={} auth={} privacy={}".format(args.seclevel, args.auth, args.priv), file=sys.stderr)
    if args.verbose > 2 and args.protocol == "3":
        print("SNMPv3 context name={} engine={}".format(args.contextname or "(default)", args.contextengineid or "(default)"), file=sys.stderr)


# -------------------------
# pysnmp Auth Builder
# -------------------------

def _build_auth_data(args):
    """Build pysnmp auth data from args. Returns (auth_data, is_v3)."""
    if args.user:
        seclevel = getattr(args, 'seclevel', 'authPriv')
        if seclevel == 'authPriv':
            auth_proto = usmHMACSHAAuthProtocol if args.auth.lower() == 'sha' else usmHMACMD5AuthProtocol
            privacy = args.priv.lower()
            if getattr(args, '_wlc_snmp', False) and privacy in ('3des', '3desde', '3desede'):
                priv_proto = usm3DESEDEPrivProtocol
            elif privacy == 'aes' or (getattr(args, '_wlc_snmp', False) and privacy == 'aes128'):
                priv_proto = usmAesCfb128Protocol
            else:
                priv_proto = usmDESPrivProtocol
            return UsmUserData(args.user, args.authpw, args.privpw,
                               authProtocol=auth_proto, privProtocol=priv_proto), True
        elif seclevel == 'authNoPriv':
            auth_proto = usmHMACSHAAuthProtocol if args.auth.lower() == 'sha' else usmHMACMD5AuthProtocol
            return UsmUserData(args.user, args.authpw,
                               authProtocol=auth_proto), True
        else:  # noAuthNoPriv
            return UsmUserData(args.user), True
    elif args.community:
        return CommunityData(args.community, mpModel=0 if getattr(args, '_wlc_snmp', False) and args.protocol == '1' else 1), False
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

def _snmp_context(args):
    engine = getattr(args, 'contextengineid', None)
    if engine and engine.lower().startswith('0x'):
        engine = engine[2:]
    return ContextData(contextEngineId=bytes.fromhex(engine) if engine else None,
                       contextName=getattr(args, 'contextname', None) or '')


def _pysnmp_get_single(args, oid, auth_data):
    """Single SNMP GET using given auth_data. Returns (value, rc)."""
    try:
        iterator = getCmd(
            SnmpEngine(),
            auth_data,
            UdpTransportTarget((args.hostname, getattr(args, 'port', 161)), timeout=args.timeout, retries=0),
            _snmp_context(args),
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
    if getattr(args, '_wlc_snmp', False) and not args.legacy_fallback:
        auth_data, _ = _build_auth_data(args)
        return _pysnmp_get_single(args, oid, auth_data)
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
            UdpTransportTarget((args.hostname, getattr(args, 'port', 161)), timeout=args.timeout, retries=0),
            _snmp_context(args),
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
    if getattr(args, '_wlc_snmp', False) and not args.legacy_fallback:
        auth_data, _ = _build_auth_data(args)
        return _pysnmp_walk_raw(args, oid, auth_data)
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
