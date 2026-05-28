# Monitoring Scripts & Tools

A collection of shell scripts, Perl plugins, and PowerShell monitoring scripts used for WPP infrastructure management and Nagios/Icinga monitoring.

---

## Monitoring Scripts (`monitoring_scripts/`)

Nagios/Icinga-compatible plugins designed for use with NSClient++ or NRPE.

### `check_bgp_peer.pl`

Perl plugin that checks BGP and EIGRP peer status via SNMP. Supports SNMPv2c and SNMPv3, auto-detects routing protocol (BGP or EIGRP), and identifies Cisco platforms for prefix checks.

| Feature | Detail |
|---|---|
| **Language** | Perl 5.12+ |
| **Protocols** | BGP (BGP4-MIB), EIGRP (CISCO-EIGRP-MIB) |
| **SNMP** | v1, v2c, v3 (authPriv) |
| **Platform detection** | Cisco IOS, IOS-XE, IOS-XR, NX-OS |

**Usage:**
```bash
./check_bgp_peer.pl --hostname <HOST> [--version 2c] [--community <COMMUNITY>]
./check_bgp_peer.pl --hostname <HOST> --version 3 --username <USER> --authproto SHA --authpass <PASS> --privproto AES --privpass <PASS>
```

**Requirements:** `Net::SNMP`, `Getopt::Long`

---

### `check_cert_expiry.ps1`

PowerShell plugin that checks certificate expiry and revocation status in the Windows `LocalMachine\My` (Personal) certificate store. Performs online CRL/OCSP revocation checks and outputs Nagios-format performance data.

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

**NSClient++ configuration:**
```ini
[/settings/external scripts/scripts]
check_cert_expiry = cmd /c powershell.exe -ExecutionPolicy Bypass -NonInteractive -Command "& 'C:\Program Files\NSClient++\scripts\check_cert_expiry.ps1' -WarningDays %ARG1% -CriticalDays %ARG2%; exit $LASTEXITCODE"
```

---

### `check_puppet_certs.ps1`

PowerShell plugin that checks Puppet SSL certificate expiry. Auto-detects the Puppet SSL directory on both Windows and Linux.

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

**NSClient++ configuration:**
```ini
[/settings/external scripts/scripts]
check_puppet_certs = powershell -ExecutionPolicy Bypass -NonInteractive -File "C:\Program Files\NSClient++\scripts\check_puppet_certs.ps1" -WarningDays 30 -CriticalDays 7
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
check_patch_level = powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files\NSClient++\scripts\get_patch_level.ps1"
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
