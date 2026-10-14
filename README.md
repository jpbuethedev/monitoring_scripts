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

See [OIDS_check_cisco_wlc_ha.md](OIDS_check_cisco_wlc_ha.md) for the OIDs and state meanings used by this check.
For a plain-language explanation, see [How the check works](LOGIC_check_cisco_wlc_ha.md).

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
./check_cisco_wlc_ha.pl --host <WLC-IP> --version 3 --secname <SNMPv3-USER> --authpass '<AUTH-PASSWORD>' --privpass '<PRIVACY-PASSWORD>' --timeout 10
./check_cisco_wlc_ha.pl --host <WLC-IP> --version 2c --community '<COMMUNITY>' --timeout 10
./check_cisco_wlc_ha.pl --host <WLC-IP> --version 3 --secname <SNMPv3-USER> --authpass '<AUTH-PASSWORD>' --privpass '<PRIVACY-PASSWORD>' --strict
./check_cisco_wlc_ha.pl --host <WLC-IP> --version 2c --community '<COMMUNITY>' --timeout 10 --ap-serial
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

### `check_cisco_firewall.py`

Python plugin that checks a Cisco firewall (ASA/FTD/Secure Firewall 3100) via SNMP. Supports failover status, CPU, memory, connections, uptime, HA role/state (local and peer), sysinfo, fan tray/power supply hardware health, and interface admin/oper status. Uses the shared [ves_snmp_utils.py](ves_snmp_utils.py) module for all SNMP access. For a plain-language walkthrough, see [How the check works](LOGIC_check_cisco_firewall.md); for numeric OIDs and detailed state mappings, see [OIDS_check_cisco_firewall.md](OIDS_check_cisco_firewall.md).

| Feature | Detail |
|---|---|
| **Language** | Python 3 (`rh-python38` shebang) |
| **MIBs** | CISCO-FIREWALL-MIB, CISCO-PROCESS-MIB, CISCO-MEMORY-POOL-MIB, CISCO-ENHANCED-MEMPOOL-MIB, CISCO-ENTITY-FRU-CONTROL-MIB, ENTITY-MIB, IF-MIB |
| **SNMP** | v2c, v3 (noAuthNoPriv, authNoPriv, authPriv) |
| **Platform** | Cisco ASA / FTD / Secure Firewall 3100 |
| **Modes** | `ha_summary`, `ha_pair`, `cpu`, `memory`, `connections`, `uptime`, `primary_state`, `secondary_state`, `sysinfo`, `hardware`, `interfaces` |

| Parameter | Default | Description |
|---|---|---|
| `-H/--hostname` | required | Target hostname or IP address |
| `-C/--community` | — | SNMPv2c community string |
| `--user` | — | SNMPv3 username |
| `--peer-hostname` | auto-detected | Peer unit IP/hostname, used by `ha_pair` |
| `-t/--timeout` | 30 | SNMP timeout in seconds |
| `-w/--warning` / `-c/--critical` | mode-dependent | Thresholds (percent, seconds or counts depending on mode) |

**Usage:**
```bash
./check_cisco_firewall.py -H <host> -C <community> --mode ha_summary|ha_pair|cpu|memory|connections|uptime|primary_state|secondary_state|sysinfo|hardware|interfaces [--peer-hostname <host>] [-w/--warning <n>] [-c/--critical <n>]
```

**Output example:**
```
OK - Role=ACTIVE(active); HA Peer: reachable | peer_up=1
```

**Requirements:** `pysnmp`

---

### `check_cisco_fmc.py`

Python plugin that checks a Cisco Secure Firewall Management Center (FMC) via SNMP. FMC is a Linux (Yocto) appliance rather than an IOS/ASA platform, so it uses HOST-RESOURCES-MIB instead of the ASA-specific CISCO-PROCESS-MIB/CISCO-MEMORY-POOL-MIB. Uses the shared [ves_snmp_utils.py](ves_snmp_utils.py) module for all SNMP access. For a plain-language walkthrough, see [How the check works](LOGIC_check_cisco_fmc.md); for numeric OIDs, table details, and live-tested examples, see [OIDS_check_cisco_fmc.md](OIDS_check_cisco_fmc.md).

| Feature | Detail |
|---|---|
| **Language** | Python 3 (`rh-python38` shebang) |
| **MIBs** | HOST-RESOURCES-MIB (`hrProcessorLoad`, `hrStorageTable`, `hrSystemDate`), MIB-II and ENTITY-MIB (`sysinfo`) |
| **SNMP** | v2c, v3 (noAuthNoPriv, authNoPriv, authPriv) |
| **Platform** | Cisco Secure Firewall Management Center (FMC) |
| **Modes** | `cpu` (average CPU load across all reported cores; also escalates if any single core is at/above threshold even when the average isn't), `memory` (physical RAM usage), `swap` (virtual memory/swap usage; OK if no swap configured), `disk` (usage of every fixed-disk mount; worst one decides status; supports `--include-mounts` and `--exclude-mounts`), `timesync` (clock skew vs monitoring host), `sysinfo` (hostname and available chassis identity) |

| Parameter | Default | Description |
|---|---|---|
| `-H/--hostname` | required | FMC hostname or IP address |
| `-C/--community` | — | SNMPv2c community string |
| `--user` | — | SNMPv3 username |
| `-t/--timeout` | 30 | SNMP timeout in seconds |
| `-v/--verbose` | off | For `disk` mode, adds per-mount used/total MB to each mount's output line |
| `--mode` | required | `cpu`, `memory`, `swap`, `disk`, `timesync`, or `sysinfo` |
| `-w/--warning` | mode-dependent | Warning threshold in percent for resource modes, seconds for timesync; not used by sysinfo |
| `-c/--critical` | mode-dependent | Critical threshold in percent for resource modes, seconds for timesync; not used by sysinfo |
| `--include-mounts` | — | `disk` mode only: comma-separated list of mount paths to include first; exclusions are then applied to the remaining set (e.g. `/,/var/log`) |
| `--exclude-mounts` | — | `disk` mode only: comma-separated list of mount paths to exclude after the include filter (e.g. `/dev/shm,/boot`) |

**Usage:**
```bash
./check_cisco_fmc.py -H $HOSTADDRESS$ -C <community> --mode <mode> [options]
./check_cisco_fmc.py -H $HOSTADDRESS$ --user <user> --mode <mode> [SNMPv3 options]
# Modes: cpu, memory, swap, disk, timesync, sysinfo
```

**Default thresholds per mode** (used when `-w`/`-c` aren't given explicitly; tuned for FMC's Linux memory-caching behavior and burst-y CPU rather than a flat 80/90 for every mode):

| Mode | `-w/--warning` | `-c/--critical` | Rationale |
|---|---|---|---|
| `cpu` | 85 | 95 | Snort/detection-engine and policy-apply spikes are normal and short-lived; the busiest-core escalation already catches a genuinely stuck core, so the average threshold can be looser. |
| `memory` | 90 | 97 | FMC intentionally keeps physical RAM usage high (page cache/event buffers) — high usage alone isn't a fault, so avoid tight thresholds here. |
| `swap` | 5 | 20 | FMC avoids swapping until RAM is genuinely exhausted, so any sustained swap usage is a meaningful sign of real memory pressure. |
| `disk` | 80 | 90 | Standard safety margin; combine with `--exclude-mounts /dev/shm` (tmpfs, not meaningful) and treat `/var`/`/var/lib/mysql` (event DB/logs) as the mounts that matter most if space is tight. |
| `timesync` | 5 seconds | 30 seconds | Compares the FMC clock against the monitoring host; requires an accurate monitoring host clock. |

```bash
./check_cisco_fmc.py -H $HOSTADDRESS$ -C <community string> --mode cpu
./check_cisco_fmc.py -H $HOSTADDRESS$ -C <community string> --mode memory
./check_cisco_fmc.py -H $HOSTADDRESS$ -C <community string> --mode swap
./check_cisco_fmc.py -H $HOSTADDRESS$ -C <community string> --mode disk --include-mounts /,/var,/var/lib/mysql --exclude-mounts /dev/shm
./check_cisco_fmc.py -H $HOSTADDRESS$ -C <community string> --mode timesync -w 5 -c 30
./check_cisco_fmc.py -H $HOSTADDRESS$ -C <community string> --mode sysinfo
```

`timesync` measures clock skew via `hrSystemDate`, not which NTP peer the FMC uses or whether its NTP daemon is synchronized. Live probes on `10.56.1.221` found no NTP peer/status MIB, but did find a populated system clock (timesync returned OK at 0.4s skew). `sysinfo` uses `sysName` and `sysDescr` plus the ENTITY-MIB chassis row: model `FS-VMW-SW-K9` was reported, but serial was empty and is shown as `unavailable`. Missing optional hardware data does not fail this informational mode; missing hostname/description returns UNKNOWN.

**Output example:**
```
OK - Average CPU usage: 3.2% (cpu196608=2%, cpu196609=4%, cpu196610=3%, cpu196611=4%) | cpu_avg=3.2%;85.0;95.0;0;100
OK - Physical memory usage: 61.0% (19588.5MB / 32116.2MB) | memory_used=61.0%;90.0;97.0;0;100
OK - Swap space usage: 0.0% (0.0MB / 6725.8MB) | swap_used=0.0%;5.0;20.0;0;100
OK - Disk usage (worst: /=51.8%) | disk=51.8%;80.0;90.0;0;100 ...
/=51.8%
/Volume=42.9%
/var=42.9%
/boot=34.4%
/dev/shm=0.0%
```

**Requirements:** `pysnmp`

---

### `check_cisco_wlc.py`

Lists Cisco WLC interfaces and checks interface health via IF-MIB and CISCO-RF-MIB using the shared [ves_snmp_utils.py](ves_snmp_utils.py) module. Supports SNMPv2c and SNMPv3.

For the decision flow, rate formulas, numeric OIDs and limitations, see [How the WLC check works](LOGIC_check_cisco_wlc.md). This is a read-only Nagios/Naemon-compatible plugin for Cisco C9800 WLCs; it does not change interface configuration. Keep the script and shared helper in the same directory. The shebang uses `/opt/rh/rh-python38/root/usr/bin/python3`; direct execution requires executable permission and LF line endings.

| Mode | Purpose | HA behavior |
|---|---|---|
| `list-interfaces` | Inventory of every reported interface, without link alarms | Lists the queried unit regardless of role |
| `interface-health` | Enabled non-Null interfaces must be admin-up/oper-up | Evaluates active; explicitly skips standbyHot; other states are WARNING |
| `interface-usage` | Sampled inbound/outbound rates and utilization alarms | Evaluates either unit; low traffic is not an error |

| Parameter | Default | Description |
|---|---|---|
| `--hostname HOST` | Required | Target WLC hostname or IP; SNMP uses UDP port 161 |
| `--mode MODE` | Required | One of the three modes above |
| `--community VALUE` | Unset | SNMPv2c community; provide this or `--user` |
| `--user USER` | Unset | SNMPv3 username; the helper tries v3 first and may fall back to v2c if a community is also supplied |
| `--seclevel LEVEL` | `authPriv` | `noAuthNoPriv`, `authNoPriv` or `authPriv` |
| `--auth PROTOCOL` | `sha` | Use `sha` or `md5` |
| `--authpw VALUE` | Unset | Authentication password; `SNMP_AUTHPW` is the environment fallback |
| `--priv PROTOCOL` | `aes` | Use `aes` or `des` |
| `--privpw VALUE` | Unset | Privacy password; `SNMP_PRIVPW` is the environment fallback |
| `--timeout SECONDS` | `5` | Positive integer timeout per SNMP request, not for the whole check |
| `--interval SECONDS` | `5` | Usage only: finite sample delay of at least 1 second |
| `-w/--warning PERCENT` | `80` | Usage only: warning starts at this utilization |
| `-c/--critical PERCENT` | `90` | Usage only: critical starts at this utilization; requires `0 <= warning < critical <= 100` |
| `--include-interfaces NAMES` | All eligible | Usage only: comma-separated exact, case-sensitive `ifName` or `ifDescr` matches |
| `--multiline` | Off | Accepted by the shared parser; these modes always print their table on separate lines |
| `-h/--help` | N/A | Shows options and detailed mode descriptions without querying SNMP |

There are no `-H`/`-C` aliases. `--interval`, `-w` and `-c` affect only usage mode; `--include-interfaces` is rejected in other modes. Prefer environment variables over password options to avoid exposing SNMPv3 passwords in process listings. Explicit password options take precedence.

```bash
./check_cisco_wlc.py --hostname <WLC-IP> --community <community> --mode list-interfaces
./check_cisco_wlc.py --hostname <WLC-IP> --community <community> --mode interface-health
./check_cisco_wlc.py --hostname <WLC-IP> --community <community> --mode interface-usage --interval 5 -w 80 -c 90
./check_cisco_wlc.py --hostname <WLC-IP> --community <community> --mode interface-usage --include-interfaces Gi2
./check_cisco_wlc.py --hostname <WLC-IP> --user <user> --mode list-interfaces
```

Examples for the observed pair (replace the community placeholder):

```bash
./check_cisco_wlc.py --hostname 172.23.36.12 --community '<community>' --mode list-interfaces
./check_cisco_wlc.py --hostname 172.23.36.12 --community '<community>' --mode interface-health
./check_cisco_wlc.py --hostname 172.23.36.13 --community '<community>' --mode interface-usage --include-interfaces Gi2
./check_cisco_wlc.py --hostname 172.23.36.12 --community '<community>' --mode interface-usage --include-interfaces GigabitEthernet2,Vlan2555 --interval 10 -w 70 -c 85
./check_cisco_wlc.py --hostname 172.23.36.12 --user '<user>' --seclevel authPriv --mode interface-health
```

For the last example, set `SNMP_AUTHPW` and `SNMP_PRIVPW` in the execution environment. No password values are built into the plugin.

`list-interfaces` prints every interface, including administratively disabled and virtual interfaces, as a pipe-delimited table: index, name, description, alias, admin state, operational state, and reported speed in Mbps. It is an informational inventory: down interfaces do not cause alerts, including interfaces on a standby WLC. A successful nonempty inventory returns OK; an empty inventory returns UNKNOWN. SNMP failures retain the shared helper's status. Performance data contains `interfaces_total` and `interfaces_up`.

`interface-health` reads `cRFStatusUnitState` (`1.3.6.1.4.1.9.9.176.1.1.2.0`). On the active WLC (14), it ignores administratively down and Null interfaces, then returns CRITICAL if any remaining interface is not admin-up/oper-up. Missing or invalid status, or no eligible interfaces, returns UNKNOWN unless a confirmed interface failure already requires CRITICAL. Output includes a name/admin/oper table and `interfaces_checked`, `interfaces_problem`, `interfaces_unknown` perfdata. A standbyHot WLC (9) returns OK with an explicit evaluation-skipped message, not a claim that its links are healthy; other HA states return WARNING without evaluating links. SNMP failures retain the helper's status. This mode does not check traffic rates, error counters, or HA peer health.

`interface-usage` samples `ifHCInOctets` and `ifHCOutOctets` twice, separated by `--interval` seconds (default 5, minimum 1), and calculates bits per second from the actual elapsed time for each direction. It lists inbound/outbound Mbps and utilization against `ifHighSpeed` for every admin-up non-Null interface, including VLAN interfaces. Each direction is compared separately, not added together; WARNING starts at `-w` (default 80%) and CRITICAL at `-c` (default 90%). The worst interface/direction determines status. This mode samples the queried unit even when it is standby; low traffic is not an error. VLAN speeds are device-reported logical capacities, not necessarily a physical bottleneck, and VLAN/physical traffic may overlap.

Use `--include-interfaces Gi2` to evaluate only the physical uplink, or supply a comma-separated list such as `Gi2,Vl2555`. Matches are exact and case-sensitive against `ifName` or `ifDescr`, so `GigabitEthernet2` also works. Unknown names, explicitly selected disabled/Null interfaces, or an empty selection return UNKNOWN. The option applies only to `interface-usage`; without it, all eligible interfaces are evaluated. Unselected interfaces do not contribute rate errors or perfdata, although SNMP walks still read whole columns.

Counter decreases, changes in `ifCounterDiscontinuityTime`, uptime resets, missing counters or unknown speed prevent a valid rate and return UNKNOWN, unless another interface already requires CRITICAL. There is no 32-bit counter fallback. Perfdata uses stable interface-index labels (`if2_in_bps`, `if2_out_bps`, `if2_in_pct`, `if2_out_pct`). Sampling takes at least `--interval` plus SNMP request time; configure the monitoring system's overall plugin timeout accordingly. Calculations have synthetic test coverage. User-supplied live output confirmed valid Gi2 rates on both WLCs and valid Vl2555 rates on `.12`; `.13` returned UNKNOWN because a Vl2555 counter decreased. The cause of that decrease has not been established.

`--timeout` defaults to 5 seconds per SNMP request. SNMPv3 passwords can also be supplied through `SNMP_AUTHPW` and `SNMP_PRIVPW`. Requires Python 3.8 and `pysnmp`, like the other Python checks.

| Output/perfdata | Meaning |
|---|---|
| Inventory: `interfaces_total`, `interfaces_up` | Interface count and count whose operational state is up, including virtual interfaces |
| Health: `interfaces_checked`, `interfaces_problem`, `interfaces_unknown` | Evaluated valid-status rows, non-up rows, and missing/invalid-status rows; standby skip only emits `interfaces_checked=0` |
| Usage: `ifN_in_bps`, `ifN_out_bps` | Bits per second for interface index N; no unit suffix, values are bps |
| Usage: `ifN_in_pct`, `ifN_out_pct` | Percent of reported interface capacity, with warning/critical thresholds |

The first line contains the status and perfdata after `|`. Subsequent pipe-delimited rows are long plugin output, not additional perfdata. Usage rows show Mbps rounded to three decimals and percentages to two; status uses unrounded values. Interface-index metric labels are consistent within the reported inventory but may change if the device renumbers interfaces.

| Exit | Conditions |
|---|---|
| `0` OK | Nonempty inventory; healthy active links; explicit standbyHot health skip; valid usage below warning |
| `1` WARNING | Transitional/unexpected health-mode HA state, or usage at/above warning but below critical |
| `2` CRITICAL | Confirmed active-interface health failure, usage at/above critical, or a helper-reported SNMP failure classified as critical |
| `3` UNKNOWN | Empty/unevaluable data, invalid request, SNMP timeout, counter/reset/speed issues, or an unexpected exception |

If a usage row cannot be evaluated, the result is UNKNOWN even when another row is WARNING; a confirmed CRITICAL row takes precedence. Request/uptime/SNMP failures that abort sampling return immediately. Missing required command-line options or invalid argparse values use argparse's own error/exit 2, not a Nagios UNKNOWN summary. No arguments prints help and exits 3.

Troubleshooting: use `list-interfaces` to find exact names; use `--include-interfaces Gi2` when intentionally monitoring only the uplink; retain UNKNOWN handling for counters that decrease. A health-mode standby skip does not certify physical links or HA peer health. A successful SNMP walk or low usage does not prove forwarding is healthy. See the LOGIC guide for the observed `.13` VLAN counter issue and validation scope. NTP monitoring remains a separate [plugin](check_cisco_wlc_ntp.py).

---

### `check_cisco_wlc_ntp.py`

Python plugin that checks the NTP synchronization state of a Cisco C9800 WLC via the standard NTPv4-MIB (`1.3.6.1.2.1.197`). Reports the device's own sync mode, stratum, active offset and per-peer stratum, so an unsynchronized WLC is flagged CRITICAL. Uses the shared [ves_snmp_utils.py](ves_snmp_utils.py) module for all SNMP access. For a plain-language walkthrough, see [How the check works](LOGIC_check_cisco_wlc_ntp.md).

| Feature | Detail |
|---|---|
| **Language** | Python 3 (`rh-python38` shebang) |
| **MIBs** | NTPv4-MIB (`ntpEntStatus*`, `ntpAssocTable`) |
| **SNMP** | v2c, v3 (noAuthNoPriv, authNoPriv, authPriv) |
| **Platform** | Cisco C9800 WLC (tested on C9800-CL, IOS-XE 17.15.6) |
| **Output** | Nagios format with perfdata (`offset_ms`, `stratum`, `peers_usable`, `dispersion_ms`) |

| Parameter | Default | Description |
|---|---|---|
| `--hostname` | required | WLC hostname or IP address |
| `--community` | — | SNMPv2c community string |
| `--user` | — | SNMPv3 username |
| `--timeout` | 5 | SNMP timeout in seconds |
| `-w/--warning` | 100 | Warning threshold for absolute offset in milliseconds |
| `-c/--critical` | 500 | Critical threshold for absolute offset in milliseconds |
| `--min-peers` | 2 | WARNING if fewer peers than this are usable (stratum below 16) |

CRITICAL if the mode is not running / not synchronized / no servers configured / synchronized to local clock only, if the stratum is 16, if no peer is usable, or if the offset reaches `--critical`. WARNING if the offset reaches `--warning` or fewer than `--min-peers` peers are usable. UNKNOWN if NTPv4-MIB isn't populated. `--authpw`/`--privpw` can also be supplied via `SNMP_AUTHPW`/`SNMP_PRIVPW`.

Stratum is a server's distance from a primary time source. The plugin applies it to the device itself and to each configured peer:

| Stratum | Meaning | How the plugin treats it |
|---|---|---|
| 0 | Unspecified / invalid | Not special-cased: a peer reporting 0 counts as usable |
| 1 | Primary server, directly attached to a reference clock (GPS, radio, atomic) | Usable peer |
| 2-15 | Secondary server, one hop further from the reference clock for each step | Usable peer |
| 16 | Unsynchronized / not reachable (a peer that was never contacted shows `.INIT.`) | Unusable peer; on the device itself this is CRITICAL |

**Usage:**
```bash
./check_cisco_wlc_ntp.py --hostname <WLC-IP> --community <community> [-w <ms>] [-c <ms>] [--min-peers <n>]
```

**Output example:**
```
OK - NTP synchronized to remote server 10.56.140.125 (stratum 2), offset -0.4433 ms, 3/4 peer(s) usable | offset_ms=0.4433ms;100;500;0; stratum=2;;;0;16 peers_usable=3;;;0;4 dispersion_ms=10.548ms;;;0;
  * NTP Peer - 10.56.139.121 stratum 16 (unusable)
  * NTP Peer - 10.56.139.122 stratum 2
  * NTP Peer - 10.56.140.124 stratum 1
  * NTP Peer - 10.56.140.125 stratum 1 (selected)
```

**Requirements:** `pysnmp`

---

## Exit Codes (all monitoring scripts)

| Code | Status |
|---|---|
| 0 | OK |
| 1 | WARNING |
| 2 | CRITICAL |
| 3 | UNKNOWN |