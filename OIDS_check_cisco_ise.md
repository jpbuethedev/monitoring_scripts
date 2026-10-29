# Cisco ISE SNMP OID Reference

The check uses numeric OIDs through `ves_snmp_utils.py`; no local MIB installation is required. HOST-RESOURCES table indexes must be discovered on each execution, never copied from these examples.

| Object | Numeric OID | Use |
|---|---|---|
| `sysDescr.0` | `1.3.6.1.2.1.1.1.0` | Required description for sysinfo |
| `sysObjectID.0` | `1.3.6.1.2.1.1.2.0` | Required object identifier for sysinfo; plugin-local constant |
| `sysUpTime.0` | `1.3.6.1.2.1.1.3.0` | SNMP-agent uptime, centiseconds |
| `sysName.0` | `1.3.6.1.2.1.1.5.0` | Optional hostname; confirmed live |
| `entPhysicalClass` | `1.3.6.1.2.1.47.1.1.1.1.5` | Entity class, joined by dynamic index |
| `entPhysicalName` | `1.3.6.1.2.1.47.1.1.1.1.7` | Optional component name |
| `entPhysicalFirmwareRev` | `1.3.6.1.2.1.47.1.1.1.1.9` | Optional firmware revision |
| `entPhysicalSoftwareRev` | `1.3.6.1.2.1.47.1.1.1.1.10` | Optional component software revision |
| `entPhysicalSerialNum` | `1.3.6.1.2.1.47.1.1.1.1.11` | Required serial-number inventory column |
| `entPhysicalModelName` | `1.3.6.1.2.1.47.1.1.1.1.13` | Optional component model |
| `hrProcessorLoad` | `1.3.6.1.2.1.25.3.3.1.2` | Per-logical-processor last-minute load, integer percent |
| `hrStorageType` | `1.3.6.1.2.1.25.2.3.1.2` | RAM/fixed-disk selection |
| `hrStorageDescr` | `1.3.6.1.2.1.25.2.3.1.3` | Exact mount description |
| `hrStorageAllocationUnits` | `1.3.6.1.2.1.25.2.3.1.4` | Bytes per allocation unit |
| `hrStorageSize` | `1.3.6.1.2.1.25.2.3.1.5` | Capacity in allocation units |
| `hrStorageUsed` | `1.3.6.1.2.1.25.2.3.1.6` | Used allocation units |
| `memTotalReal` | `1.3.6.1.4.1.2021.4.5.0` | Physical RAM total in kB |
| `memAvailReal` | `1.3.6.1.4.1.2021.4.6.0` | Free physical RAM in kB |
| `memBuffer` | `1.3.6.1.4.1.2021.4.14.0` | Buffer memory in kB |
| `memCached` | `1.3.6.1.4.1.2021.4.15.0` | Cached memory in kB |
| `ifName` | `1.3.6.1.2.1.31.1.1.1.1` | Interface name; join IF-MIB columns by row index |
| `ifAdminStatus` | `1.3.6.1.2.1.2.2.1.7` | Configured interface state |
| `ifOperStatus` | `1.3.6.1.2.1.2.2.1.8` | Operational interface state |
| `ifAlias` | `1.3.6.1.2.1.31.1.1.1.18` | Optional interface alias |
| `ifHighSpeed` | `1.3.6.1.2.1.31.1.1.1.15` | Optional link speed in Mbps |
| `ifInErrors` / `ifOutErrors` | `1.3.6.1.2.1.2.2.1.14` / `.20` | Informational error counters |
| `ifInDiscards` / `ifOutDiscards` | `1.3.6.1.2.1.2.2.1.13` / `.19` | Informational discard counters |

Storage type identifiers: `hrStorageRam = 1.3.6.1.2.1.25.2.1.2`; `hrStorageFixedDisk = 1.3.6.1.2.1.25.2.1.4`.

## Calculations And Performance Data

- CPU: arithmetic mean and maximum of all reported processor percentages. Perfdata: `cpu_avg`, `cpu_max` (percent).
- Storage: `capacity_bytes = allocation_units * size`, `used_bytes = allocation_units * used`, `usage_percent = used / size * 100`. Selected rows require positive allocation units and size, and `0 <= used <= size`.
- Disk perfdata: `disk:/`, `disk:/opt`, etc., quoted labels with percentage values. RAM perfdata: `memory_raw_used` (percent, no thresholds by default). GiB displays use bytes divided by `1024 ** 3`.
- Uptime perfdata: `snmp_uptime` in seconds (`sysUpTime / 100`). A 32-bit TimeTicks rollover occurs after roughly 497 days; the value is not host OS uptime.
- Interface perfdata: monitored/down counts and aggregate errors/discards only when all counter columns are available. Counter values are snapshots and do not determine status.
- Serial inventory perfdata: `serial_components`; one detail row per non-empty ENTITY-MIB serial value.
- `memory_usage` perfdata: `memory_active_used` (percent), calculated from UCD-SNMP real-memory counters; this is not Linux `MemAvailable`.

## Discovery Evidence

User-supplied SNMP output from instance 1 (`172.23.38.11`) reported:

- Description `Cisco Identity Services Engine` and object identifier `1.3.6.1.4.1.9.1.1426`.
- `sysUpTime = 389536126` centiseconds (approximately 45.09 days).
- 16 processors, discovery indexes `196608` through `196623`, each at 1-2% load.
- Physical RAM: allocation unit 1024 bytes, size 32639152, used 30572648. The resulting 93.7% is raw usage including caches, not a verified memory-pressure metric.
- UCD-SNMP real RAM counters were also exposed: total 32639152 kB, free 1980928 kB, buffers 56372 kB, cached 7019900 kB. `memory_usage` subtracts the latter three from total as an active-use estimate, not `MemAvailable`.
- Required mount descriptions `/`, `/opt`, `/boot`, `/tmp`, `/storedconfig`, `/mnt/encpart`. Indexes varied by row and are not configuration.
- `/opt/podman/containers/storage/overlay` duplicated `/opt` capacity/usage; many shared-memory and transient rows also existed. Default explicit path selection avoids duplicate/noisy checks.
- IF-MIB returned `lo`, `eth0`-`eth5`, `podman*`, and `veth*` names. All were admin/oper up in this snapshot. The virtual interfaces also report `ifType=ethernetCsmacd`, so filtering by ifType alone would include them. The live plugin check selected `eth0`-`eth5`, returned OK, and reported 270 `ifInDiscards` per interface; discards remain informational.
- A direct ENTITY-MIB GET for row 1 returned model `ISE-VM-K9`, a serial number, class `other`, and software revision `Cisco ADE-OS 3.4`; firmware revision was empty. ENTITY-MIB table walks timed out, but GETNEXT of the serial column returned row 1. This software revision is not confirmed as the ISE application release. `CISCO-SMART-LIC-MIB::ciscoSlaEnabled` (`1.3.6.1.4.1.9.9.831.0.4.0`) returned `No Such Object`.

`1.3.6.1.4.1.9.9.109.1.1.1` returned `No Such Object` and is not used. No available-memory, ISE service, persona, HA or firmware mapping is inferred from this data.

Instance 2 (`172.23.38.12`) did not respond to discovery. The deployed `serial-numbers` mode was live-tested on `.11` and returned the chassis serial row at index 1 with model `ISE-VM-K9`.