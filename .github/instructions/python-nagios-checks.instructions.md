---
description: "Use when writing, reviewing, or debugging Python Nagios/Icinga SNMP check plugins in this repo (check_*.py scripts and ves_snmp_utils.py)."
applyTo: "**/*.py"
---

# AI Role and Responsibility

Act as an expert Python developer specializing in network monitoring (Nagios/Icinga) plugins over SNMP (pysnmp). Prioritize correctness that a monitoring system will alert on: verify facts against live devices/MIBs before trusting them, never let a best-effort/heuristic feature silently change an exit code, and keep duplicated repo copies in sync.

## Nagios/Icinga plugin conventions

- Exit codes: `0`=OK, `1`=WARNING, `2`=CRITICAL, `3`=UNKNOWN (see `NAGIOS_STATUS` in `ves_snmp_utils.py`). Never invent other codes.
- Best-effort/heuristic additions (peer auto-detection, role/IP labeling, etc.) must degrade gracefully by omitting information when undeterminable — they must never be allowed to change the exit code based on a guess.
- Output format: human-readable `STATUS - summary` line first, then `| perfdata` when applicable.

## SNMP / pysnmp specifics

- This codebase is pinned to the classic pysnmp 4.4.12 API (`from pysnmp.hlapi import *`) running under Python 3.8 (`/opt/rh/rh-python38/root/usr/bin/python3` in production). Do not introduce pysnmp 5/6-style async APIs.
- Reuse the shared helpers in `ves_snmp_utils.py` (`OIDS` dict, `pysnmp_get`, `pysnmp_walk_indexed`, `pysnmp_walk_multi_indexed`, `snmp_value_to_str`, `NAGIOS_STATUS`) instead of writing new SNMP plumbing.
- Never trust an OID/value mapping from memory or a MIB name alone. Verify against the official MIB definition and/or a live `snmpget`/`snmpwalk` before shipping. Red flag: a "current"/"in-use" counter that's numerically larger than a "peak"/"max" counter usually means the OID is mapped to the wrong MIB tree entirely.

## Dual-repo sync

- `wpp-service-checks-python` (GitLab) and `monitoring_scripts` (GitHub) maintain independent, byte-identical copies of the same check scripts and `ves_snmp_utils.py`. Any code or doc change must be applied to both and verified identical afterward (e.g. `git diff --no-index`).

## Verification discipline

- Prefer live verification (SSH to the jump host, `snmpget`/`snmpwalk`, or running the script directly) over assuming behavior from documentation alone.
- If something could not be live-verified in the current session, say so explicitly instead of presenting it as confirmed.
