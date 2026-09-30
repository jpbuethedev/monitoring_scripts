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

### `check_cisco_firewall.py`

Python plugin that checks a Cisco firewall (ASA/FTD/Secure Firewall 3100) via SNMP. Supports failover status, CPU, memory, connections, uptime, HA role/state (local and peer), sysinfo, fan tray/power supply hardware health, and interface admin/oper status. Uses the shared [ves_snmp_utils.py](ves_snmp_utils.py) module for all SNMP access. Full OID/logic reference: [OIDS_check_cisco_firewall.md](OIDS_check_cisco_firewall.md).

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

Python plugin that checks a Cisco Secure Firewall Management Center (FMC) via SNMP. FMC is a Linux (Yocto) appliance rather than an IOS/ASA platform, so it uses HOST-RESOURCES-MIB instead of the ASA-specific CISCO-PROCESS-MIB/CISCO-MEMORY-POOL-MIB. Uses the shared [ves_snmp_utils.py](ves_snmp_utils.py) module for all SNMP access. Full OID/logic reference: [OIDS_check_cisco_fmc.md](OIDS_check_cisco_fmc.md).

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

## Exit Codes (all monitoring scripts)

| Code | Status |
|---|---|
| 0 | OK |
| 1 | WARNING |
| 2 | CRITICAL |
| 3 | UNKNOWN |