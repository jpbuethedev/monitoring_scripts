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
check_cert_expiry = cmd /c powershell.exe -ExecutionPolicy Bypass -NonInteractive -Command "& "scripts\check_cert_expiry.ps1" -WarningDays %ARG1% -CriticalDays %ARG2%; exit $LASTEXITCODE"
```

---

### `check_cisco_wlc_ha.pl`

Perl plugin that monitors Cisco 9800 Wireless LAN Controller HA (SSO) health via SNMP. Detects local unit role (active/standbyHot) using CISCO-RF-MIB, checks HA peer reachability via CISCO-LWAPP-HA-MIB, and validates RF duplex and peer state. Supports `--strict` and `--hard-strict` modes for tighter alerting.

| Feature | Detail |
|---|---|
| **Language** | Perl 5.12+ |
| **MIBs** | CISCO-RF-MIB, CISCO-LWAPP-HA-MIB |
| **SNMP** | v2c, v3 (noAuthNoPriv, authNoPriv, authPriv) |
| **Platform** | Cisco 9800 WLC |

| Parameter | Default | Description |
|---|---|---|
| `--host` | required | Target WLC IP or hostname |
| `--version` | 3 | SNMP version (2c or 3) |
| `--strict` | off | Escalate unexpected states to CRITICAL |
| `--hard-strict` | off | Escalate any anomaly to CRITICAL (superset of `--strict`) |
| `--timeout` | 5 | SNMP timeout in seconds |

**Usage:**
```bash
./check_cisco_wlc_ha.pl --host 172.26.9.68 --version 3 --secname nagios --authpass 'AuthPass' --privpass 'PrivPass' --timeout 10
./check_cisco_wlc_ha.pl --host 172.26.9.68 --version 2c --community 'public' --timeout 10
./check_cisco_wlc_ha.pl --host 172.26.9.68 --version 3 --secname nagios --authpass 'AuthPass' --privpass 'PrivPass' --strict
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
check_puppet_cert_expiry = powershell -ExecutionPolicy Bypass -NonInteractive -File "scripts\check_puppet_certs.ps1" -WarningDays %ARG1% -CriticalDays %ARG2%
```

---

### `get_patch_level.ps1`

PowerShell plugin that reports the Windows version, build number, and patch level (UBR). Compatible with Windows 7 through Windows 11 and modern Windows Server (10/11/Server 2016+). Outputs Nagios-format performance data.

**Output example:**
```
OK: Windows Server 2019 Standard 1809 - Version: 10.0 - Build: 17763 - Patch Level (UBR): 6532 | 'version_major'=10;;;; 'version_minor'=0;;;; 'build'=17763;;;; 'ubr'=6532;;;;
```

**Usage:**
```powershell
.\get_patch_level.ps1
```

**NSClient++ configuration:**
```ini
[/settings/external scripts/scripts]
check_patch_level = powershell.exe -ExecutionPolicy Bypass -File "scripts\get_patch_level.ps1"
```

**Requirements:** PowerShell 3.0+

---

## Exit Codes (all monitoring scripts)

| Code | Status |
|---|---|
| 0 | OK |
| 1 | WARNING |
| 2 | CRITICAL |
| 3 | UNKNOWN |
