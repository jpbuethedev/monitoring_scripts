# check_cisco_fmc.py — OIDs, tables and status meanings per mode

SNMP OIDs used by [check_cisco_fmc.py](check_cisco_fmc.py), sourced from the shared `OIDS` dict in [ves_snmp_utils.py](ves_snmp_utils.py). Target platform: Cisco Secure Firewall Management Center (FMC). Unlike [check_cisco_firewall.py](check_cisco_firewall.py)'s ASA/FTD targets, FMC is a Linux (Yocto) appliance, so it exposes CPU/memory/disk via the standard **HOST-RESOURCES-MIB** rather than the IOS-only CISCO-PROCESS-MIB / CISCO-MEMORY-POOL-MIB.

## Nagios exit codes

Every mode maps its SNMP result onto the standard Nagios exit codes (`NAGIOS_STATUS` in [ves_snmp_utils.py](ves_snmp_utils.py)):

| Exit code | Status | Meaning |
|---|---|---|
| `0` | OK | Value(s) within normal range |
| `1` | WARNING | Value(s) at/above `--warning` threshold |
| `2` | CRITICAL | Value(s) at/above `--critical` threshold |
| `3` | UNKNOWN | SNMP error, missing/unpopulated OID, or no credentials given |

All four modes share the same threshold logic (`_threshold_exit_code()`): critical takes precedence over warning, and both thresholds are percentages (default `--warning 80`, `--critical 90`).

## cpu
Average CPU load across all reported processor cores, from HOST-RESOURCES-MIB's processor table.

| OID name | OID | Table / index |
|---|---|---|
| `hrProcessorLoad` | 1.3.6.1.2.1.25.3.3.1.2 | `hrProcessorTable`, indexed by `hrDeviceIndex` (one row per logical CPU core) |

`hrProcessorLoad` is walked (`pysnmp_walk_indexed`) rather than fetched as a scalar, since FMC reports one row per CPU core (confirmed live: 4 rows, indices `196608`-`196611`, on a 4-vCPU appliance). The value is a plain percentage (0-100), no MIB status enum involved.

### Result logic (`check_cpu()`)

| Condition | Exit code |
|---|---|
| Average CPU load ≥ `--critical` (default `90`) | `2` CRITICAL |
| Average CPU load ≥ `--warning` (default `80`) | `1` WARNING |
| Otherwise | `0` OK |
| No CPU rows returned at all (`hrProcessorLoad` unpopulated) | `3` UNKNOWN |

The single busiest core is also checked against the same `--warning`/`--critical` thresholds independently of the average, and the worse of the two exit codes wins — so one core pegged at 95% can't be masked by an otherwise-idle fleet averaging out to a comfortable number. When the busiest core is what drives the status (rather than the average), the summary notes which core and its value, e.g. `(cpu196610 at 97% drives status)`.

Output includes a per-core breakdown (e.g. `cpu196608=2%, cpu196609=4%, ...`) alongside the average; only the average and busiest-core checks drive the exit code, and only the average is published to perfdata (`cpu_avg`).

## memory
Physical RAM usage, from the `hrStorageTable` entry whose type is `hrStorageRam`.

| OID name | OID | Table / index |
|---|---|---|
| `hrStorageType` | 1.3.6.1.2.1.25.2.3.1.2 | `hrStorageTable`, indexed by `hrStorageIndex` |
| `hrStorageDescr` | 1.3.6.1.2.1.25.2.3.1.3 | Same table/index |
| `hrStorageAllocationUnits` | 1.3.6.1.2.1.25.2.3.1.4 | Same table/index — bytes per allocation unit, used as a multiplier |
| `hrStorageSize` | 1.3.6.1.2.1.25.2.3.1.5 | Same table/index — total size, in `hrStorageAllocationUnits` |
| `hrStorageUsed` | 1.3.6.1.2.1.25.2.3.1.6 | Same table/index — used size, in `hrStorageAllocationUnits` |

All five columns are walked and merged by index into a single dict (`_read_storage_table()`): `idx -> (type, descr, used_bytes, size_bytes)`, with `used`/`size` converted from allocation units to raw bytes (`raw_value * hrStorageAllocationUnits`).

### hrStorageType values used

| Constant | OID value | Meaning |
|---|---|---|
| `HR_STORAGE_TYPE_RAM` | 1.3.6.1.2.1.25.2.1.2 (`hrStorageRam`) | Selects the single physical-memory row for `memory` mode |
| `HR_STORAGE_TYPE_FIXED_DISK` | 1.3.6.1.2.1.25.2.1.4 (`hrStorageFixedDisk`) | Selects all mounted-filesystem rows for `disk` mode |

Live-confirmed on FMC: index `1` = "Physical memory" (`hrStorageRam`).

### Result logic (`check_memory()`)

Usage percentage is computed as `used_bytes / size_bytes * 100` for the RAM row.

| Condition | Exit code |
|---|---|
| Usage % ≥ `--critical` (default `90`) | `2` CRITICAL |
| Usage % ≥ `--warning` (default `80`) | `1` WARNING |
| Otherwise | `0` OK |
| No `hrStorageRam`-typed row found | `3` UNKNOWN |

Perfdata: `memory_used=<pct>%;<warn>;<crit>;0;100`. Summary also reports used/total in MB.

## swap
Virtual memory/swap usage, from the `hrStorageTable` entry of type `hrStorageVirtualMemory` whose `descr` contains "swap" (case-insensitive).

**Important quirk (confirmed live on FMC, net-snmp-style HOST-RESOURCES-MIB agent):** `hrStorageVirtualMemory` labels **two** separate rows, not one — a combined "Virtual memory" row (RAM + swap total) and a separate "Swap space" row (the actual swap partition). Naively taking the first `hrStorageVirtualMemory`-typed row returns the wrong (combined) value; `check_swap()` explicitly filters for `descr` containing "swap" to get the real swap partition.

### Result logic (`check_swap()`)

| Condition | Exit code |
|---|---|
| No swap configured (`hrStorageSize` is `0`) | `0` OK ("No swap configured") |
| Usage % ≥ `--critical` (default `90`) | `2` CRITICAL |
| Usage % ≥ `--warning` (default `80`) | `1` WARNING |
| Otherwise | `0` OK |
| No row with "swap" in its descr found among `hrStorageVirtualMemory`-typed rows | `3` UNKNOWN |

Perfdata: `swap_used=<pct>%;<warn>;<crit>;0;100`. Summary also reports used/total in MB.

Live-confirmed on FMC: index `3` = "Virtual memory" (38842.0MB, RAM+swap combined — correctly ignored), index `10` = "Swap space" (6725.8MB, 0% used — correctly selected).

## disk
Usage of every `hrStorageFixedDisk`-typed row (one per mounted filesystem); the worst (highest usage %) mount determines the overall exit code.

Uses the same `hrStorageTable` columns as `memory` above (`hrStorageType`/`Descr`/`AllocationUnits`/`Size`/`Used`), filtered to rows where `hrStorageType == hrStorageFixedDisk` and `hrStorageSize > 0` (zero-size rows, e.g. unmounted/inactive entries, are skipped), and where the mount's `descr` is not listed in `--exclude-mounts` (a comma-separated list of exact mount paths, e.g. `--exclude-mounts /dev/shm,/boot`).

Live-confirmed on FMC: 9 fixed-disk mounts — `/`, `/boot`, `/Volume`, `/dev/shm`, `/var`, `/usr/local/sf`, `/usr/lib64/perl`, `/var/lib/mysql`, `/var/lib/docker`.

### Result logic (`check_disk()`)

Usage percentage is computed per mount as `used_bytes / size_bytes * 100`; mounts are sorted descending by usage, and the highest one drives the exit code.

| Condition | Exit code |
|---|---|
| Worst mount's usage % ≥ `--critical` (default `90`) | `2` CRITICAL |
| Worst mount's usage % ≥ `--warning` (default `80`) | `1` WARNING |
| Otherwise | `0` OK |
| No fixed-disk rows found at all (or all excluded via `--exclude-mounts`) | `3` UNKNOWN |

Perfdata publishes one metric per mount, e.g. `disk=51.8%;80.0;90.0;0;100 var=42.9%;... var_lib_mysql=42.9%;...` — the mount's descr is sanitized into a perfdata-safe label (`perfdata_name()`: non-alphanumeric characters replaced with `_`, e.g. `/var/lib/mysql` → `var_lib_mysql`; `/` alone becomes `disk`).

Below the single Nagios summary/perfdata line, one plain line per mount is printed (sorted by usage, worst first), e.g. `/=51.8%`. With `-v/--verbose`, each of those lines also shows used/total MB, e.g. `/=51.8% (12345.6MB/23456.7MB)`, instead of just the bare percentage.

## Recommended thresholds

The `--warning`/`--critical` defaults (80/90) are generic and apply uniformly to all four modes, but FMC's actual behavior warrants different values per mode:

| Mode | `-w/--warning` | `-c/--critical` | Rationale |
|---|---|---|---|
| `cpu` | 85 | 95 | Snort/detection-engine and policy-apply spikes are normal and short-lived on a single SNMP snapshot; the busiest-core escalation already catches a genuinely stuck core, so the average threshold can be looser. |
| `memory` | 90 | 97 | FMC intentionally keeps physical RAM usage high (page cache/event buffers) — high usage alone isn't a fault, so tight thresholds here just cause noise. |
| `swap` | 5 | 20 | FMC avoids swapping until RAM is genuinely exhausted, so any sustained swap usage is a meaningful sign of real memory pressure, unlike physical RAM usage. |
| `disk` | 80 | 90 | Standard safety margin; combine with `--exclude-mounts /dev/shm` (tmpfs, not meaningful) and treat `/var`/`/var/lib/mysql` (event DB/logs) as the mounts that matter most if space is tight. |

## Live validation

All OIDs and table structures in this document were confirmed against a real FMC device (`ves-fmc`, `10.56.1.221`) via manual `snmpget`/`snmpwalk` and then via full end-to-end runs of `check_cisco_fmc.py` for all four modes, e.g.:

```
OK - Average CPU usage: 3.2% (cpu196608=2%, cpu196609=4%, cpu196610=3%, cpu196611=4%) | cpu_avg=3.2%;80.0;90.0;0;100
OK - Physical memory usage: 61.0% (19588.5MB / 32116.2MB) | memory_used=61.0%;80.0;90.0;0;100
OK - Swap space usage: 0.0% (0.0MB / 6725.8MB) | swap_used=0.0%;80.0;90.0;0;100
OK - Disk usage (worst: /=51.8%) | disk=51.8%;80.0;90.0;0;100 ...
/=51.8%
/Volume=42.9%
/var=42.9%
/usr/local/sf=42.9%
/usr/lib64/perl=42.9%
/var/lib/mysql=42.9%
/var/lib/docker=42.9%
/boot=34.4%
/dev/shm=0.0%
```

`--exclude-mounts /dev/shm` and `-v/--verbose` (per-mount MB detail) were both confirmed live for `disk` mode. An invalid community string correctly times out to `UNKNOWN` (exit `3`) rather than a false CRITICAL/OK, since the plugin can't distinguish "device down" from "wrong credentials" via SNMP alone.

`check_cisco_firewall.py`'s generic `--mode uptime` and `--mode interfaces` (plain MIB-II, not ASA/FTD-specific) also work as-is against the FMC: `uptime` correctly reported the device's real uptime. `interfaces` correctly walked `ifOperStatus`/errors/discards, but flagged a Docker bridge interface (`br-6ca3564a94ae`) as CRITICAL/DOWN — a false positive if deployed against the FMC as-is; would need an interface-name exclude filter first.
