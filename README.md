# Monitoring Scripts & Tools

A collection of Perl plugins, and PowerShell monitoring scripts used for WPP infrastructure management and Nagios/Naemon/Icinga monitoring.

---

## Monitoring Scripts (`monitoring_scripts/`)

Nagios/Icinga-compatible plugins designed for use with NSClient++ or NRPE.

### `check_bgp_peer.pl`

Perl plugin that monitors BGP and EIGRP routing peer status via SNMP. It auto-detects the active routing protocol by querying BGP4-MIB first and falling back to CISCO-EIGRP-MIB. On Cisco devices it also detects the platform (IOS, IOS-XE, IOS-XR, NX-OS) and hardware model via ENTITY-MIB, and checks accepted prefix counts using CISCO-BGP4-MIB. For EIGRP, it handles multiple IOS index formats (with/without VPN ID, IPv4/IPv6) and resolves peer interface names via ifDescr. Outputs Nagios-format status with per-peer detail lines and performance data (`peers_total`, `peers_established`, `peers_down`).

| Feature | Detail |
|---|---|
| **Language** | Perl 5.12+ |
| **Protocols** | BGP (BGP4-MIB), EIGRP (CISCO-EIGRP-MIB) |
| **SNMP** | v1, v2c, v3 (authNoPriv, authPriv) |
| **Platform detection** | Cisco IOS, IOS-XE, IOS-XR, NX-OS via sysObjectID + ENTITY-MIB |
| **Cisco BGP prefix check** | CISCO-BGP4-MIB (legacy + v2 OIDs) |

| Parameter | Default | Description |
|---|---|---|
| `--hostname` | required | Target hostname or IP address |
| `--version` | 2c | SNMP version (1, 2c, or 3) |
| `--community` | — | Community string (v1/v2c) |
| `--username` | — | SNMPv3 username (required for v3) |
| `--authproto` | SHA | Auth protocol: MD5, SHA, SHA256 |
| `--privproto` | AES | Priv protocol: DES, AES |
| `--timeout` | 10 | SNMP timeout in seconds |
| `--retries` | 2 | SNMP retries |

**Usage:**
```bash
./check_bgp_peer.pl --hostname <HOST> --community <COMMUNITY>
./check_bgp_peer.pl --hostname <HOST> --version 3 --username <USER> --authproto SHA --authpass <PASS> --privproto AES --privpass <PASS>
```

**Output example:**
```
OK: 2/2 BGP peers established [C881-K9] | peers_total=2 peers_established=2 peers_down=0
Peer=10.1.1.1 ASN=65001 State=established Uptime=30d12h5m
Peer=10.1.1.2 ASN=65002 State=established Uptime=15d3h22m
```

**Requirements:** `Net::SNMP`, `Getopt::Long`

---

### `check_cert_expiry.ps1`

PowerShell plugin that inspects all non-self-signed certificates in the Windows `LocalMachine\My` (Personal) certificate store. For each certificate it checks days remaining until expiry against configurable thresholds and performs an online CRL/OCSP revocation check via `X509Chain`. Outputs a Nagios-format status line with summary counts and per-certificate detail lines (CN, expiry date, revocation status, thumbprint). Certificates are deduplicated and sorted by days remaining.

| Feature | Detail |
|---|---|
| **Language** | PowerShell |
| **Certificate store** | `LocalMachine\My` (Personal) |
| **Revocation check** | Online CRL/OCSP via `X509Chain` (entire chain, 10s timeout) |
| **Output** | Nagios format with perfdata (`total`, `crit`, `warn`) + per-cert detail lines |
| **Self-signed** | Automatically skipped |

| Parameter | Default | Description |
|---|---|---|
| `-WarningDays` | 30 | Days before expiry to trigger WARNING |
| `-CriticalDays` | 10 | Days before expiry to trigger CRITICAL |
| `-ShowOnlyProblems` | off | Only report certificates with issues |

**Usage:**
```powershell
.\check_cert_expiry.ps1
.\check_cert_expiry.ps1 -WarningDays 60 -CriticalDays 30
.\check_cert_expiry.ps1 -ShowOnlyProblems
```

**Output example:**
```
OK - Certs: Total=3, Critical=0, Warning=0 | 'total'=3 'crit'=0 'warn'=0

[OK] CN: myserver.example.com
    Expiry     : 2027-03-15  (290 days)
    Revocation : OK
    Thumbprint : A1B2C3D4...
```

**NSClient++ configuration:**
```ini
[/settings/external scripts/scripts]
;PowerShell plugin that checks LocalMachine\My cert expiry and revocation.
check_cert_expiry = cmd /c powershell.exe -ExecutionPolicy Bypass -NonInteractive -Command "& "scripts\check_cert_expiry.ps1" -WarningDays %ARG1% -CriticalDays %ARG2%; exit $LASTEXITCODE"
```

---

### `check_cisco_wlc_ha.pl`

Perl plugin that monitors Cisco 9800 Wireless LAN Controller HA (SSO) health via SNMP. It first queries CISCO-RF-MIB to determine the local unit's role (`active`, `standbyHot`, or transitional states like `initialization`/`negotiation`), RF duplex mode (peer detected or not), peer unit state, and last switchover reason. When the local unit is **active**, it additionally queries CISCO-LWAPP-HA-MIB (`cLHaPeerHotStandbyEvent`) to verify HA peer reachability. When the local unit is **standbyHot**, it skips the LWAPP-HA check (only meaningful on the active) and validates that the peer is in `active` state. Transitional/abnormal local states trigger WARNING by default. Supports two escalation modes: `--strict` escalates peer-state mismatches and transitional states to CRITICAL, while `--hard-strict` (superset) escalates any anomaly including LWAPP-HA read failures to CRITICAL with no UNKNOWN/WARNING fallbacks. Optionally, `--ap-serial` walks the AP table (CISCO-LWAPP-AP-MIB with automatic fallback to AIRESPACE-WIRELESS-MIB) and appends each AP name and serial number to the output, useful for inventory and initial discovery. Outputs Nagios-format status with performance data for trending (`peer_up`, `duplex`, `unit_state`, `peer_state`, `last_swact_reason`).

| Feature | Detail |
|---|---|
| **Language** | Perl 5.12+ |
| **MIBs** | CISCO-RF-MIB (redundancy framework), CISCO-LWAPP-HA-MIB (HA peer health), CISCO-LWAPP-AP-MIB / AIRESPACE-WIRELESS-MIB (AP inventory) |
| **SNMP** | v2c, v3 (noAuthNoPriv, authNoPriv, authPriv) |
| **Platform** | Cisco 9800 WLC (SSO HA pair) |
| **Output** | Nagios format with perfdata (`peer_up`, `duplex`, `unit_state`, `peer_state`, `last_swact_reason`) |

| Parameter | Default | Description |
|---|---|---|
| `--host` | required | Target WLC IP or hostname |
| `--version` | 3 | SNMP version (2c or 3) |
| `--secname` | — | SNMPv3 username |
| `--seclevel` | authPriv | SNMPv3 security level |
| `--authproto` | SHA | Auth protocol (SHA or MD5) |
| `--privproto` | AES | Privacy protocol (AES or DES) |
| `--strict` | off | Escalate unexpected states to CRITICAL |
| `--hard-strict` | off | Escalate any anomaly to CRITICAL (superset of `--strict`) |
| `--ap-serial` | off | Walk AP table and include each AP name + serial number in output |
| `--timeout` | 5 | SNMP timeout in seconds |
| `--port` | 161 | SNMP port |

**Usage:**
```bash
./check_cisco_wlc_ha.pl --host 172.26.9.68 --version 3 --secname nagios --authpass 'AuthPass' --privpass 'PrivPass' --timeout 10
./check_cisco_wlc_ha.pl --host 172.26.9.68 --version 2c --community '<community>' --timeout 10
./check_cisco_wlc_ha.pl --host 172.26.9.68 --version 3 --secname nagios --authpass 'AuthPass' --privpass 'PrivPass' --strict
./check_cisco_wlc_ha.pl --host 172.26.9.68 --version 2c --community '<community>' --timeout 10 --ap-serial
```

**Output example:**
```
OK - Role=ACTIVE(active); HA Peer: reachable; RF: peer detected (duplex=true); RF PeerState: standbyHot; LastSwact: none | peer_up=1 duplex=1 unit_state=14 peer_state=9 last_swact_reason=2
```

**Output example (with `--ap-serial`):**
```
OK - Role=ACTIVE(active); HA Peer: reachable; RF: peer detected (duplex=true); RF PeerState: standbyHot; LastSwact: none; AP_Serials: AP-Floor1=FCZ2345A001, AP-Floor2=FCZ2345A002 | peer_up=1 duplex=1 unit_state=14 peer_state=9 last_swact_reason=2
```

**Requirements:** `Net::SNMP`, `Getopt::Long`

---

### `check_puppet_certs.ps1`

PowerShell plugin that checks Puppet SSL certificate expiry and reports Nagios-format output with performance data. Auto-detects the Puppet SSL directory on both Windows and Linux, scans `certs/` and `ca/signed/` sub-directories for `.pem`/`.crt` files, and classifies each certificate as OK, WARNING, CRITICAL, or EXPIRED. Also reports the configured Puppet server and agent version in the output.

| Feature | Detail |
|---|---|
| **Language** | PowerShell (cross-platform) |
| **Cert parsing** | .NET `X509Certificate2`, `openssl` fallback |
| **SSL dir detection** | Auto-detect on Windows & Linux, manual override |
| **Output** | Nagios format with per-certificate perfdata (days remaining) |

| Parameter | Default | Description |
|---|---|---|
| `-WarningDays` | 30 | Days before expiry to trigger WARNING |
| `-CriticalDays` | 7 | Days before expiry to trigger CRITICAL |
| `-PuppetSslDir` | auto-detect | Override the Puppet SSL directory path |

**Usage:**
```powershell
.\check_puppet_certs.ps1
.\check_puppet_certs.ps1 -WarningDays 60 -CriticalDays 14
.\check_puppet_certs.ps1 -PuppetSslDir "C:\ProgramData\PuppetLabs\puppet\etc\ssl"
```

**Output example:**
```
OK: [puppet-server=puppet.example.com puppet-version=7.29.1] All 3 certificate(s) are valid (warn=30d crit=7d) | 'agent_days'=364;30;7;0; 'ca_days'=1825;30;7;0;
```

**NSClient++ configuration:**
```ini
[/settings/external scripts/scripts]
;PowerShell plugin that checks Puppet SSL cert expiry.
check_puppet_cert_expiry = powershell -ExecutionPolicy Bypass -NonInteractive -File "scripts\check_puppet_certs.ps1" -WarningDays %ARG1% -CriticalDays %ARG2%
```

---

### `get_patch_level.ps1`

PowerShell plugin that reports the Windows version, build number, and patch level (UBR) by reading the registry key `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion`. Handles both modern Windows (10/11/Server 2016+) using `CurrentMajorVersionNumber`/`CurrentMinorVersionNumber` and legacy Windows (7/8/8.1) by falling back to the `CurrentVersion` string. Resolves the friendly version label (e.g. 22H2) from `DisplayVersion` or `ReleaseId`, and retrieves the product name from the registry or `Win32_OperatingSystem` as fallback. Outputs Nagios-format status with performance data for graphing patch level trends.

| Feature | Detail |
|---|---|
| **Language** | PowerShell 3.0+ |
| **Data source** | Registry (`CurrentVersion` key) |
| **Compatibility** | Windows 7 SP1 through Windows 11, Server 2008 R2 through Server 2025 |
| **Output** | Nagios format with perfdata (`version_major`, `version_minor`, `build`, `ubr`) |

**Usage:**
```powershell
.\get_patch_level.ps1
```

**Output example:**
```
OK: Windows Server 2019 Standard 1809 - Version: 10.0 - Build: 17763 - Patch Level (UBR): 6532 | 'version_major'=10;;;; 'version_minor'=0;;;; 'build'=17763;;;; 'ubr'=6532;;;;
```

**NSClient++ configuration:**
```ini
[/settings/external scripts/scripts]
;PowerShell plugin that reports Windows version, build, and patch level.
check_patch_level = powershell.exe -ExecutionPolicy Bypass -File "scripts\get_patch_level.ps1"
```

---

## Exit Codes (all monitoring scripts)

| Code | Status |
|---|---|
| 0 | OK |
| 1 | WARNING |
| 2 | CRITICAL |
| 3 | UNKNOWN |
# wpp-service-checks-python

Nagios/Icinga-style Python check plugins for monitoring Cisco network devices (via SNMP) and VMware ESXi/vCenter (via the vSphere API).

All checks follow the standard Nagios plugin exit code convention:

| Code | Status   |
|------|----------|
| 0    | OK       |
| 1    | WARNING  |
| 2    | CRITICAL |
| 3    | UNKNOWN  |

Most scripts print a single-line summary followed by `| perfdata` performance data. Pass `--multiline` for a more verbose, human-readable breakdown.

## Requirements

- Python 3 (scripts target the RHEL `rh-python38` SCL interpreter via their shebang; adjust as needed for your environment)
- [`pysnmp`](https://pypi.org/project/pysnmp/) — used by the pysnmp-based helpers in `ves_snmp_utils.py`
- Net-SNMP CLI tools (`snmpwalk`, `snmpget`) — used by the subprocess-based helpers in `ves_snmp_utils.py`
- [`pyvmomi`](https://pypi.org/project/pyvmomi/) (`pyVim`, `pyVmomi`) — required only by [check_ves_vmware_esx_listvms.py](check_ves_vmware_esx_listvms.py)
- [`check_nwc_health`](https://labs.consol.de/nagios/check_nwc_health/) installed at `/usr/local/nagios/libexec/check_nwc_health` — required by [check_ves_interface.py](check_ves_interface.py) and [check_ves_licenses.py](check_ves_licenses.py)

Install the Python dependencies with:

```bash
pip install pysnmp pyvmomi
```

## Shared module: `ves_snmp_utils.py`

[ves_snmp_utils.py](ves_snmp_utils.py) provides the common building blocks used by the `check_ves_*` scripts:

- **Subprocess-based SNMP** (shells out to `snmpwalk`/`snmpget`): `run_snmpwalk()`, `run_snmpwalk_lines()`, `run_snmpwalk_host()`, `parse_snmp_string_output()`
- **pysnmp library-based SNMP**: `pysnmp_get()`, `pysnmp_walk()`, `pysnmp_walk_dict()`, `pysnmp_walk_indexed()`, `pysnmp_walk_multi_indexed()`, `snmp_value_to_str()`
- **Common helpers**: `add_snmp_args()` (adds the standard SNMPv2c/v3 CLI arguments to an `argparse` parser), `is_auth_error()`, the `OIDS` dictionary of well-known Cisco/MIB-II OIDs, and the `NAGIOS_STATUS` / `CISCO_ENV_STATE_MAP` lookup tables

All SNMP-based checks support both SNMPv2c and SNMPv3 and will automatically fall back from v3 to v2c (or vice versa) when credentials for both are supplied.

### Common SNMP arguments (`add_snmp_args`)

| Argument      | Description                                                        |
|---------------|---------------------------------------------------------------------|
| `--hostname`  | Target device hostname or IP (required)                             |
| `--community` | SNMPv2c community string                                            |
| `--user`      | SNMPv3 username                                                     |
| `--seclevel`  | SNMPv3 security level: `noAuthNoPriv`, `authNoPriv`, `authPriv` (default `authPriv`) |
| `--auth`      | SNMPv3 auth protocol (default `sha`)                                 |
| `--authpw`    | SNMPv3 auth password                                                 |
| `--priv`      | SNMPv3 privacy protocol (default `aes`)                              |
| `--privpw`    | SNMPv3 privacy password                                              |
| `--timeout`   | SNMP timeout in seconds (default varies by script)                   |
| `--multiline` | Print verbose, multi-line output instead of a single summary line    |

### [check_cisco_firewall.py](check_cisco_firewall.py)
Checks a Cisco firewall (ASA/FTD/Secure Firewall 3100) via SNMP. Supports failover status, CPU, memory, connections, uptime, HA role/state (local and peer), sysinfo, fan tray/power supply hardware health, and interface admin/oper status.

```bash
./check_cisco_firewall.py -H <host> -C <community> --mode ha_summary|ha_pair|cpu|memory|connections|uptime|primary_state|secondary_state|sysinfo|hardware|interfaces [--peer-hostname <host>] [-w/--warning <n>] [-c/--critical <n>]
```

| Mode                 | Description                                                              |
|----------------------|---------------------------------------------------------------------------|
| `ha_summary`          | HA state of both the primary and secondary units (`cfwHardwareStatusValue`) |
| `ha_pair`             | Cross-checks HA state by independently querying both `--hostname` and `--peer-hostname`, requiring both reachable, in agreement, and in a failover-safe state (9/10) |
| `cpu`                 | Average CPU load (5s/1m/5m); `--warning`/`--critical` are percent (default 80/90) |
| `memory`              | System/data-plane memory pool usage; `--warning`/`--critical` are percent (default 80/90) |
| `connections`         | Current in-use connection count, with peak count included in verbose output and perfdata; `--warning`/`--critical` are connection counts |
| `uptime`              | Time since last reboot (`sysUpTime`); `--warning`/`--critical` are minimum seconds |
| `primary_state`       | Combined text role and numeric HA state of the primary unit (`cfwHardwareStatusDetail`/`cfwHardwareStatusValue` index 6) - same result regardless of which paired unit's IP is queried |
| `secondary_state`     | Combined text role and numeric HA state of the secondary unit (`cfwHardwareStatusDetail`/`cfwHardwareStatusValue` index 7) - same result regardless of which paired unit's IP is queried |
| `sysinfo`             | Hardware description, hostname and chassis model (`sysDescr`, `sysName`, `entPhysicalModelName`) |
| `hardware`            | Fan tray / power supply operational status |
| `interfaces`          | Admin/oper status, link speed and error/discard counters of all real interfaces, excluding ASA-internal pseudo-interfaces |

The `hardware` mode uses `CISCO-ENTITY-FRU-CONTROL-MIB` (fan tray/PSU status is not populated via `ENTITY-STATE-MIB` on these platforms) and returns `OK` with no fan/PSU components on units where it's not populated at all (e.g. a secondary logical FTD instance sharing chassis with another instance) — this is by design on some units, not a fault, so it does not alert. The `interfaces` mode monitors every real interface reported via `ifName`/`ifAdminStatus`/`ifOperStatus`, excluding a small set of ASA-internal pseudo-interfaces (`Internal-Data0/1`, `nlp_int_tap`, etc.) — interface naming (`nameif`) varies significantly across firewall pairs, so no fixed interface list is used. Output includes a per-interface `name (alias): UP|DOWN` line for every monitored interface, followed by its link speed (`ifHighSpeed`, Mbps) and error/discard counters (`ifInErrors`/`ifOutErrors`/`ifInDiscards`/`ifOutDiscards`) when available — these are informational only and never affect the exit code or the UP/DOWN determination; aggregate totals are also included in the perfdata as `errors_total`/`discards_total`.

`primary_state`/`secondary_state` report the HA pair's **configured role** (which unit is "primary" and which is "secondary" as set in the ASA HA config), not "this host" vs. "the other host" — the role assignment is fixed cluster-wide and is shared by both units' MIBs, so querying either paired unit's IP returns identical output for both modes. Output text says "Primary unit"/"Secondary unit" (never "local"/"peer") to avoid implying the result depends on which IP you queried. The numeric state reflects which of the two units is presently active vs. standby (this does change over time, e.g. after a failover), independent of the fixed primary/secondary role:

| State | Meaning | Status |
|-------|---------|--------|
| 9     | Active           | OK |
| 10    | Standby Ready    | OK |
| 11    | Standby Cold     | WARNING |
| 12    | Failed           | CRITICAL |

So a healthy pair always shows one unit as Active (9) and the other as Standby Ready (10) — it does not matter whether the Active one is the primary or the secondary unit. These extended values (9-12) are seen on real devices but go beyond the standard `CISCO-FIREWALL-MIB` `HardwareStatus` textual convention (which only defines up to 10).

`ha_summary`, `primary_state`, and `secondary_state` also best-effort annotate the queried unit's own slot and live status, e.g. `[10.56.1.226 = primary unit, currently active]`. For `primary_state`/`secondary_state`, if the fixed role being reported (primary/secondary) doesn't match the queried IP's own role, the note is flipped to describe the queried IP's actual status instead, e.g. `[10.56.1.226 = primary unit, currently active; this result reflects the secondary/peer unit]`. This reuses the same `_determine_unit_role()` helper as `ha_pair` (below) and is simply omitted if the platform doesn't populate the underlying OID.

For `ha_pair`, `--peer-hostname` is optional: if omitted, the peer is guessed from `--hostname` using the environment's observed +/-2-last-octet IPv4 convention (e.g. `.226`/`.228`) and confirmed via a live SNMP query before being trusted; a confirmed auto-detected peer is noted in the output as `(peer <ip> auto-detected via IP heuristic)`. If no candidate can be confirmed (or `--hostname` isn't a plain IPv4 address), the check exits `WARNING` rather than guessing blindly.

The `ha_pair` output also best-effort labels which IP is the Primary/Secondary unit, e.g. `Primary [10.56.1.226]: Active (9), Secondary [10.56.1.228]: Standby Ready (10)`. This uses `cfwHardwareInformation`, a self-referential text field (unlike the pair-mirrored `cfwHardwareStatusValue`/`Detail`) that includes `(this device)` only on the row matching the unit that actually answered the query. If the platform doesn't populate this OID, the IP labels are simply omitted rather than guessed.

Running the script with no arguments prints usage/help and exits `UNKNOWN` instead of argparse's terse error. `--community`/`--user` credentials are required up front (`UNKNOWN` if neither is given). An SNMP timeout (unreachable host) is reported as `UNKNOWN` rather than `CRITICAL`, and any unexpected error or manual interruption (Ctrl+C) is caught and reported as a single-line `UNKNOWN` result instead of a raw Python traceback.