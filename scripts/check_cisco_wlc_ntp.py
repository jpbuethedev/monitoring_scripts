#!/opt/rh/rh-python38/root/usr/bin/python3

#
# Nagios plugin: checks NTP synchronization state of a Cisco C9800 WLC via SNMP (NTPv4-MIB, RFC 5907).
#
# Usage: check_cisco_wlc_ntp.py --hostname <wlc>
#            ( --community <snmp-community> | --user <snmpv3-user> [--seclevel noAuthNoPriv|authNoPriv|authPriv]
#              [--auth <auth-protocol>] [--authpw <auth-password>] [--priv <priv-protocol>] [--privpw <priv-password>] )
#            [ --timeout <seconds> ] [ -w/--warning <ms> ] [ -c/--critical <ms> ] [ --min-peers <n> ]
#
# Unlike check_ves_ntp_timesync.py (CISCO-NTP-MIB peer offsets, which the WLC leaves empty and which
# would not flag an unsynchronized device), this check reports the device's own sync state:
#   CRITICAL  - not running / not synchronized / no servers configured / synced to local clock only,
#               or stratum 16 (unsynchronized)
#   CRITICAL  - |offset| >= --critical (ms);  WARNING - |offset| >= --warning (ms)
#   CRITICAL  - no usable peer;  WARNING - fewer than --min-peers usable peers (stratum < 16)
#   UNKNOWN   - NTPv4-MIB not populated or mode "unknown"

import argparse
import ipaddress
import os
import sys
from ves_snmp_utils import NAGIOS_STATUS, OIDS, add_snmp_args, pysnmp_get, pysnmp_walk_indexed, snmp_value_to_str

# ntpEntStatusCurrentMode
NTP_MODE = {
    1: "not running",
    2: "not synchronized",
    3: "no servers configured",
    4: "synchronized to local clock only",
    5: "synchronized to reference clock",
    6: "synchronized to remote server",
    7: "unknown",
}
SYNCED_MODES = (5, 6)
STRATUM_UNSYNCHRONIZED = 16


def _unknown(message):
    print(f"UNKNOWN - {message}")
    sys.exit(3)


def _get_or_exit(args, oid):
    value, rc = pysnmp_get(args, oid)
    if rc != 0:
        print(value)
        sys.exit(rc)
    return value


def _get_int(args, oid, name):
    try:
        return int(_get_or_exit(args, oid))
    except (TypeError, ValueError):
        _unknown(f"{name} not available via SNMP (NTPv4-MIB not populated)")


def _walk_or_exit(args, oid):
    result, rc = pysnmp_walk_indexed(args, oid)
    if rc != 0:
        print(result)
        sys.exit(rc)
    return result


def _parse_ms(value, name):
    """Parse an NTPv4-MIB display string such as "-0.4433 ms" into a float of milliseconds."""
    try:
        return float(snmp_value_to_str(value).split()[0])
    except (IndexError, ValueError):
        _unknown(f"Invalid {name} value: {snmp_value_to_str(value)!r}")


def _read_peers(args):
    """Return {assoc_index: (address, stratum)} for every configured NTP association."""
    addresses = _walk_or_exit(args, OIDS["ntpAssocAddress"])
    strata = _walk_or_exit(args, OIDS["ntpAssocStratum"])
    peers = {}
    for idx, raw in addresses.items():
        try:
            address = str(ipaddress.ip_address(raw.asOctets()))
        except (AttributeError, ValueError):
            address = snmp_value_to_str(raw)
        try:
            peers[idx] = (address, int(strata[idx]))
        except (KeyError, TypeError, ValueError):
            continue
    return peers


def _perf(offset_ms, warning, critical, stratum, usable, total, dispersion_ms):
    parts = []
    if offset_ms is not None:
        parts.append(f"offset_ms={abs(offset_ms):.4f}ms;{warning:g};{critical:g};0;")
    parts.append(f"stratum={stratum};;;0;{STRATUM_UNSYNCHRONIZED}")
    parts.append(f"peers_usable={usable};;;0;{total}")
    parts.append(f"dispersion_ms={dispersion_ms:.3f}ms;;;0;")
    return " ".join(parts)


def main():
    parser = argparse.ArgumentParser(description="Check NTP synchronization state of a Cisco C9800 WLC via SNMP (NTPv4-MIB)")
    add_snmp_args(parser, timeout_default=5)
    parser.add_argument("-w", "--warning", type=float, default=100.0,
                        help="Warning threshold for the absolute clock offset in milliseconds (default 100)")
    parser.add_argument("-c", "--critical", type=float, default=500.0,
                        help="Critical threshold for the absolute clock offset in milliseconds (default 500)")
    parser.add_argument("--min-peers", type=int, default=2,
                        help="WARNING if fewer than this many peers are usable, i.e. stratum below 16 (default 2)")

    args = parser.parse_args()

    # fall back to env vars so SNMPv3 secrets don't have to appear in the process list
    args.authpw = args.authpw or os.environ.get("SNMP_AUTHPW")
    args.privpw = args.privpw or os.environ.get("SNMP_PRIVPW")

    if not args.community and not args.user:
        _unknown("No SNMP credentials provided (use --community or --user)")
    if args.warning < 0 or args.critical < 0 or args.warning >= args.critical:
        _unknown(f"--warning ({args.warning:g}) must be non-negative and lower than --critical ({args.critical:g})")
    if args.min_peers < 0:
        _unknown("--min-peers must not be negative")

    mode = _get_int(args, OIDS["ntpEntStatusCurrentMode"], "ntpEntStatusCurrentMode")
    stratum = _get_int(args, OIDS["ntpEntStatusStratum"], "ntpEntStatusStratum")
    active_source = _get_int(args, OIDS["ntpEntStatusActiveRefSourceId"], "ntpEntStatusActiveRefSourceId")
    dispersion_ms = _parse_ms(_get_or_exit(args, OIDS["ntpEntStatusDispersion"]), "ntpEntStatusDispersion")

    if mode not in NTP_MODE or mode == 7:
        _unknown(f"NTP mode unknown (ntpEntStatusCurrentMode={mode})")

    peers = _read_peers(args)
    usable = [idx for idx, (_, peer_stratum) in peers.items() if peer_stratum < STRATUM_UNSYNCHRONIZED]
    peer_lines = [
        f"  * NTP Peer - {address} stratum {peer_stratum}"
        f"{' (selected)' if idx == active_source else ''}"
        f"{'' if peer_stratum < STRATUM_UNSYNCHRONIZED else ' (unusable)'}"
        for idx, (address, peer_stratum) in sorted(peers.items())
    ]

    synced = mode in SYNCED_MODES and stratum < STRATUM_UNSYNCHRONIZED
    offset_ms = None
    exit_code = 0

    if not synced:
        exit_code = 2
        summary = f"NTP {NTP_MODE[mode]} (stratum {stratum}), {len(usable)}/{len(peers)} peer(s) usable"
    else:
        offset_ms = _parse_ms(_get_or_exit(args, OIDS["ntpEntStatusActiveOffset"]), "ntpEntStatusActiveOffset")
        if abs(offset_ms) >= args.critical:
            exit_code = 2
        elif abs(offset_ms) >= args.warning:
            exit_code = 1

        notes = []
        if not usable:
            exit_code = 2
            notes.append("no usable peer")
        elif len(usable) < args.min_peers:
            exit_code = max(exit_code, 1)
            notes.append(f"fewer than {args.min_peers} usable peers")

        source = peers.get(active_source)
        source_text = f" {source[0]}" if source else ""
        summary = (f"NTP {NTP_MODE[mode]}{source_text} (stratum {stratum}), offset {offset_ms:+.4f} ms, "
                   f"{len(usable)}/{len(peers)} peer(s) usable")
        if notes:
            summary += f" - {', '.join(notes)}"

    perf = _perf(offset_ms, args.warning, args.critical, stratum, len(usable), len(peers), dispersion_ms)
    print(f"{NAGIOS_STATUS[exit_code]} - {summary} | {perf}")
    for line in peer_lines:
        print(line)
    sys.exit(exit_code)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("UNKNOWN - Check interrupted")
        sys.exit(3)
