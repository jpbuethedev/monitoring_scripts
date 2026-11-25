"""
ves_snmp_args.py — SNMP command-line options shared by the VES Nagios check scripts.

Deliberately free of pysnmp imports so plugins can print help and validate
arguments before (or without) loading the SNMP libraries.

Provides:
    - add_snmp_args()      : Shared argparse SNMP v1/v2c/v3 arguments
    - prepare_snmp_args()  : Normalize and validate the standardized options
                             (prepare_wlc_snmp_args is kept as an alias)
"""

import argparse
import os
import re
import sys


class _UsageAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        parser.print_usage()
        parser.exit()


def add_snmp_args(parser, timeout_default=30, standard_aliases=False, verbose_help=None, multiline=True):
    """Add standard SNMP v2c/v3 and output arguments to an argparse parser.

    standard_aliases selects the standardized option set (-p/-P, v1/v2c/v3, contexts,
    long aliases, -V/-?/-v). verbose_help overrides the -v help text for plugins whose
    -v also enables extra output; multiline=False omits --multiline for plugins that
    do not render multi-line output.
    """
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
    if multiline:
        parser.add_argument("--multiline", action="store_true")
    if standard_aliases:
        parser.add_argument("-?", "--usage", action=_UsageAction, nargs=0, help="Show usage and exit")
        parser.add_argument("-V", "--version", action="version", version="%(prog)s 1.0.0")
        parser.add_argument("-v", "--verbose", action="count", default=0,
                            help=verbose_help or "Show SNMP debug details (up to 3 times)")
        parser.add_argument("-P", "--port", type=int, default=161, help="SNMP port (default 161)")
        parser.add_argument("-p", "--protocol", choices=["1", "2c", "3"], help="SNMP protocol (default 2c; 3 when username is supplied)")
        parser.add_argument("--contextengineid", help="SNMPv3 context engine ID as hexadecimal")
        parser.add_argument("--contextname", help="SNMPv3 context name")
        parser.epilog = (parser.epilog or "") + "\nSNMPv3 shorthand examples: snmpv3,sha,authpass,aes,privpass,user and snmpv3,sha,authpass,aes,privpass,user,,contextname. Use any single-character separator. CLI credentials may be visible in process listings."


def prepare_snmp_args(args):
    """Normalize and validate the standardized SNMP options (raises ValueError)."""
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


prepare_wlc_snmp_args = prepare_snmp_args
