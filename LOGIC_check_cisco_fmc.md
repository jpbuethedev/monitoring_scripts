# How the Cisco FMC check works

## In plain language

This check reads health and identity information from a Cisco Secure Firewall Management Center (FMC) using SNMP. FMC is a Linux-based appliance, so resource checks use standard HOST-RESOURCES-MIB data rather than the IOS/ASA-specific CPU and memory MIBs.

The check is read-only. It does not change the FMC configuration or test whether firewall policies, traffic inspection, or managed devices are functioning. It reports the selected metric and, for resource modes, compares it with warning and critical thresholds.

## What happens during a check

1. **Validate the request.** The target and mode are required. The check also requires SNMPv2c community credentials or an SNMPv3 username. SNMPv3 passwords can be passed as options or through `SNMP_AUTHPW` and `SNMP_PRIVPW` environment variables.
2. **Resolve thresholds.** Each metric mode has its own defaults. Explicit `-w/--warning` and `-c/--critical` values override them. Warning must be lower than critical; resource values must be between 0 and 100, while `timesync` thresholds are non-negative seconds. `sysinfo` does not use thresholds.
3. **Read only the data needed for the selected mode.** A missing table row, SNMP failure, malformed required value, or invalid request cannot be treated as healthy and is reported as UNKNOWN.
4. **Print the monitoring result.** The plugin emits a status and human-readable summary. Metric modes also emit Nagios performance data after `|`.

## What each mode checks

### CPU (`--mode cpu`)

The check walks `hrProcessorLoad` and calculates the average across all returned logical CPUs. It also compares the busiest individual CPU with the same thresholds. The worse status wins, so a saturated core is not hidden by a low average. The summary lists each CPU; performance data publishes the average as `cpu_avg`.

No CPU rows means UNKNOWN.

### Physical memory (`--mode memory`)

The check reads the `hrStorageTable`, selects the row whose type is `hrStorageRam`, and calculates `used / size * 100`. Allocation-unit values are converted to bytes before calculation. The summary includes used and total MB, and performance data publishes `memory_used`.

No physical-memory row means UNKNOWN.

### Swap (`--mode swap`)

The check selects an `hrStorageVirtualMemory` row whose description contains "swap", ignoring case. Some agents use that type for both combined virtual memory (RAM plus swap) and the actual swap partition, so the description is used to select the actual swap row. Usage is calculated from its used and total byte counts.

If the selected row has size zero, the check returns OK with "No swap configured". If no matching swap row exists, it returns UNKNOWN. Performance data publishes `swap_used`.

### Disk (`--mode disk`)

The check examines every `hrStorageFixedDisk` row with a non-zero size. `--include-mounts` optionally limits the set to exact, comma-separated mount descriptions; `--exclude-mounts` then removes exact matches. The mount with the highest usage percentage determines the overall status. Output lists mounts from most-used to least-used, and performance data contains one sanitized metric label per mount.

With `-v/--verbose`, each mount's output also includes used and total MB. Unknown include/exclude names are ignored; they are mentioned only in verbose output. If no eligible mounts remain, the result is UNKNOWN.

### Clock skew (`--mode timesync`)

The check reads the FMC's `hrSystemDate`, including its timezone, and compares it with the monitoring host's UTC clock. It samples the local clock immediately before and after the SNMP request and compares the device time with the midpoint of those samples. The absolute difference, in seconds, determines the result; the summary also says whether the FMC clock is ahead or behind.

This checks clock agreement with the monitoring host, not whether an NTP peer is configured or synchronized. The monitoring host must have an accurate clock. SNMP errors or a missing, timezone-less, or invalid device date produce UNKNOWN.

### System information (`--mode sysinfo`)

The check requires the SNMP system name and description. It also looks for an ENTITY-MIB chassis row and reports its model and serial when available. Missing optional chassis details are shown as `unavailable` and do not change the result; missing required name or description produces UNKNOWN. This mode always returns OK when its required identity values are available and does not accept thresholds.

## Status and thresholds

| Result | Meaning |
|---|---|
| `0` OK | Metric is below warning, swap is not configured, or required system identity was read. |
| `1` WARNING | Metric is at or above warning but below critical. |
| `2` CRITICAL | Metric is at or above critical. |
| `3` UNKNOWN | Credentials are missing, validation fails, an SNMP operation fails, required data is absent or invalid, or an unexpected error occurs. |

Critical is checked before warning, so a value at or above critical is CRITICAL even though it also exceeds warning. Defaults are:

| Mode | Warning | Critical |
|---|---:|---:|
| `cpu` | 85% | 95% |
| `memory` | 90% | 97% |
| `swap` | 5% | 20% |
| `disk` | 80% | 90% |
| `timesync` | 5 seconds | 30 seconds |

CPU and memory use less aggressive defaults because FMC can have bursty CPU activity and high RAM use from caching and event buffers. Swap uses tighter thresholds because swap activity is a more meaningful memory-pressure signal on this platform.

## Output and performance data

For metric modes, text before `|` is the readable result and text after it is performance data for monitoring and graphing. For example:

```text
OK - Average CPU usage: 3.2% (cpu196608=2%, cpu196609=4%) | cpu_avg=3.2%;85.0;95.0;0;100
```

The threshold values can be overridden per invocation. Disk mount filters apply only to disk mode. For the numeric OIDs, table columns, and live-tested examples, see the [FMC OID reference](OIDS_check_cisco_fmc.md) and the [monitoring scripts README](README.md#check_cisco_fmc.py).