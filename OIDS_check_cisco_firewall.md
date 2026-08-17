# check_cisco_firewall.py — OIDs queried per mode

SNMP OIDs used by [check_cisco_firewall.py](check_cisco_firewall.py), sourced from the shared `OIDS` dict in [ves_snmp_utils.py](ves_snmp_utils.py). Target platforms: ASA / FTD / Secure Firewall 3100 (e.g. Firepower 3110).

## ha_summary
HA state of the primary/secondary hardware units.

| OID name | OID | Notes |
|---|---|---|
| `cfwHardwareStatusValue` | 1.3.6.1.4.1.9.9.147.1.2.1.1.1.3 | Queried at `.6` (primary) and `.7` (secondary) |

## cpu
Average CPU load (5s/1m/5m).

| OID name | OID |
|---|---|
| `cpmCPUTotal5secRev` | 1.3.6.1.4.1.9.9.109.1.1.1.1.6 |
| `cpmCPUTotal1minRev` | 1.3.6.1.4.1.9.9.109.1.1.1.1.7 |
| `cpmCPUTotal5minRev` | 1.3.6.1.4.1.9.9.109.1.1.1.1.8 |

## memory
System/data-plane memory pool usage. Classic table is tried first; enhanced table is the fallback for platforms that don't populate the classic one.

| OID name | OID | Notes |
|---|---|---|
| `ciscoMemPoolName` | 1.3.6.1.4.1.9.9.48.1.1.1.2 | CISCO-MEMORY-POOL-MIB (classic ASA) |
| `ciscoMemPoolUsed` | 1.3.6.1.4.1.9.9.48.1.1.1.5 | |
| `ciscoMemPoolFree` | 1.3.6.1.4.1.9.9.48.1.1.1.6 | |
| `cempMemPoolName` | 1.3.6.1.4.1.9.9.221.1.1.1.1.3 | CISCO-ENHANCED-MEMPOOL-MIB fallback (newer ASA/FTD/Secure Firewall) |
| `cempMemPoolUsed` | 1.3.6.1.4.1.9.9.221.1.1.1.1.7 | |
| `cempMemPoolFree` | 1.3.6.1.4.1.9.9.221.1.1.1.1.8 | |

## connections
Current in-use/peak/failed connection counts (scalar OIDs).

| OID name | OID |
|---|---|
| `connActiveConnections` | 1.3.6.1.4.1.9.9.171.1.2.1.3.0 |
| `connPeakConnections` | 1.3.6.1.4.1.9.9.171.1.2.1.4.0 |
| `connFailedConnections` | 1.3.6.1.4.1.9.9.171.1.2.1.6.0 |

## uptime
Time since last reboot.

| OID name | OID |
|---|---|
| `sysUpTime` | 1.3.6.1.2.1.1.3.0 |

## primary_state / secondary_state
Combined text role and numeric HA state (index 6=primary, 7=secondary).

| OID name | OID |
|---|---|
| `cfwHardwareStatusDetail` | 1.3.6.1.4.1.9.9.147.1.2.1.1.1.4 |
| `cfwHardwareStatusValue` | 1.3.6.1.4.1.9.9.147.1.2.1.1.1.3 |

## sysinfo
Hardware description and hostname.

| OID name | OID |
|---|---|
| `sysDescr` | 1.3.6.1.2.1.1.1.0 |
| `sysName` | 1.3.6.1.2.1.1.5.0 |

## hardware
Fan tray / power supply operational status, plus best-effort voltage/RPM sensor readings.

| OID name | OID | Notes |
|---|---|---|
| `entPhysicalClass` | 1.3.6.1.2.1.47.1.1.1.1.5 | Identifies fan (7) vs power supply (6) entries |
| `entPhysicalDescr` | 1.3.6.1.2.1.47.1.1.1.1.2 | Component name/description |
| `cefcFanTrayOperStatus` | 1.3.6.1.4.1.9.9.117.1.4.1.1.1 | Required |
| `cefcFRUPowerOperStatus` | 1.3.6.1.4.1.9.9.117.1.1.2.1.2 | Required |
| `entSensorType` | 1.3.6.1.4.1.9.9.91.1.1.1.1.1 | Best-effort; not every platform populates this MIB |
| `entSensorValue` | 1.3.6.1.4.1.9.9.91.1.1.1.1.4 | Best-effort |
| `entSensorScale` | 1.3.6.1.4.1.9.9.91.1.1.1.1.2 | Best-effort |

### cefcFanTrayOperStatus value meanings

| Value | MIB label | Meaning | Script severity |
|---|---|---|---|
| `1` | `unknown` | System can't currently determine the fan tray's status | WARNING |
| `2` | `up` | Fan tray present and operating normally | OK |
| `3` | `down` | Fan tray present but not operating / failed | WARNING (downgraded — see note) |
| `4` | `warning` | Fan tray operating outside normal parameters (degraded) | CRITICAL |

Note: `down(3)` is deliberately downgraded to WARNING instead of CRITICAL because production Secure Firewall 3100 / FTD 7.4.2 units have been observed consistently reporting `down(3)` for the fan tray even when the hardware is otherwise healthy. `warning(4)` is kept at CRITICAL since it reflects a real problem. See `FAN_TRAY_STATUS_MAP`/`FAN_TRAY_STATUS_SEVERITY` in [check_cisco_firewall.py](check_cisco_firewall.py).

Note: some units (e.g. a secondary logical FTD instance sharing chassis with another instance) never report any `entPhysicalClass` fan/PSU rows at all — confirmed live on 10.56.1.227/.229. That's expected on those units, not a fault, so the script exits OK with no fan/PSU components rather than UNKNOWN.

## interfaces
Admin/oper status of all real interfaces (ASA-internal pseudo-interfaces excluded).

| OID name | OID |
|---|---|
| `ifName` | 1.3.6.1.2.1.31.1.1.1.1 |
| `ifAdminStatus` | 1.3.6.1.2.1.2.2.1.7 |
| `ifOperStatus` | 1.3.6.1.2.1.2.2.1.8 |
| `ifAlias` | 1.3.6.1.2.1.31.1.1.1.18 |

## Verifying against native Cisco commands

SSH to the device lands in FXOS on the Secure Firewall 3100 series. For everything except `hardware`, run `connect ftd` then `system support diagnostic-cli` then `enable` to get the classic ASA-style `show` command set.

| Mode | Native command | Where to run |
|---|---|---|
| `ha_summary` / `primary_state` / `secondary_state` | `show failover` or `show failover state` | FTD diagnostic-cli |
| `cpu` | `show cpu usage` | FTD diagnostic-cli |
| `memory` | `show memory` or `show memory detail` | FTD diagnostic-cli |
| `connections` | `show conn count` | FTD diagnostic-cli |
| `uptime` | `show version` | FTD diagnostic-cli |
| `sysinfo` | `show version` + `show hostname` | FTD diagnostic-cli |
| `hardware` | `show environment` + `show inventory` | FXOS (chassis owns the hardware on the 3100 series) |
| `interfaces` | `show interface ip brief` (or `show interface` for detail) + `show nameif` | FTD diagnostic-cli |
