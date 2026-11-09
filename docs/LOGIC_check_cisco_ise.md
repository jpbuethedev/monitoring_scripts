# Cisco ISE Check Logic

`check_cisco_ise.py` checks one explicitly addressed Cisco ISE node using the shared SNMPv2c/v3 helpers. Run it separately for each node. It does not infer a peer, HA roles, firmware version, personas or application readiness.

## Modes

- `timesync`: GET timezone-aware `hrSystemDate` and compare device time to the monitoring host's request midpoint. Decode the 11-byte DateAndTime with signed UTC offset and deciseconds; invalid/calendar/leap-second values or absent timezone return UNKNOWN. Report absolute clock skew, direction, and `clock_skew` seconds perfdata. Inclusive defaults are warning 5s and critical 30s; thresholds must be finite and satisfy `0 <= warning < critical` without a percentage cap. The monitoring host must keep accurate time. Network delay and timestamp precision introduce uncertainty. Clock agreement is not proof of NTP synchronization; both NTP MIB probes on `.11` returned `No Such Object`.

- `swap`: GET UCD-SNMP `memTotalSwap` and `memAvailSwap` in kB. Validate nonnegative counters no larger than 4294967295 and free no larger than total; zero total returns UNKNOWN. Report used percentage and used/total GiB with `swap_used` perfdata. Unrounded percentage drives inclusive warning/critical thresholds (defaults 80/90). Occupancy does not measure current paging or prove memory pressure.

- `cpu`: walk `hrProcessorLoad`, validate each load as an integer from 0 to 100, and report the last-minute average plus busiest processor. Compare unrounded values against inclusive warning/critical boundaries (defaults 80/90). The more severe of average and busiest-core status wins. Monitoring retry settings, not this stateless plugin, establish sustained alerts.
- `disk`: walk the five storage columns and join by discovered index. Match fixed-disk rows by exact mount description. Default required paths are `/`, `/opt`, `/boot`, `/tmp`, `/storedconfig`, `/mnt/encpart`. `--include-mounts` replaces that set; `--exclude-mounts` removes paths before validation. A missing, duplicate, non-fixed-disk or invalid selected mount returns UNKNOWN, as does an empty selection. Other rows, including container overlays, are ignored. Allocation units and capacity must be positive, and used units must be between zero and capacity. Bytes equal allocation units multiplied by the corresponding size/used counter. Worst usage drives status (defaults 80/90). Perfdata uses quoted, path-based labels to distinguish `/` from `/opt` and other mounts.
- `memory`: select exactly one `hrStorageRam` row and validate its allocation units, capacity and used count. Report raw used percentage and used/total GiB. Raw usage includes cache/buffers and does not measure Linux available memory. No thresholds means informational OK with perfdata, not proof of healthy memory pressure. Both `-w` and `-c` must be explicitly supplied to enable alerts.
- `memory_usage`: compute estimated active RAM as UCD-SNMP `memTotalReal - memAvailReal - memBuffer - memCached`. Report estimated active percentage and GiB. This excludes free memory, buffers, and cached memory, but it is not Linux `MemAvailable` and does not identify process-specific usage. No thresholds means informational OK; both `-w` and `-c` are required for alerts.
- `uptime`: convert `sysUpTime.0` from centiseconds to seconds and days. This is SNMP-agent uptime, not OS uptime. The 32-bit counter wraps after approximately 497 days; decreases do not necessarily mean a reboot. No alert thresholds or change detection.
- `sysinfo`: require a nonempty system description and numeric system object identifier. Query hostname best effort; a failed/unsupported hostname shows `unavailable` without changing status. No thresholds, model/serial lookup or inferred version.
- `interfaces`: join `ifName`, `ifAdminStatus`, and `ifOperStatus` by dynamic interface index. By default omit `lo`, `podman*`, and `veth*`; `--include-interfaces` selects exact names and overrides the defaults, and `--exclude-interfaces` always removes exact names. An admin-up interface that is not oper-up is CRITICAL; admin-down is informational; admin-testing is WARNING. Alias, speed, error, and discard walks are best-effort and never determine status. Perfdata reports selected/down counts and, only when all counter walks are complete, aggregate errors/discards. Thresholds do not apply.
- `serial-numbers`: walk `entPhysicalSerialNum`, require at least one non-empty serial, and join optional `entPhysicalName`, `entPhysicalClass`, `entPhysicalModelName`, and `entPhysicalDescr` values by entity index. Missing optional columns display as unavailable but do not suppress a serial. No thresholds; this is inventory only, not a license or ISE release check.

### Interface Rate Sampling

`interfaces` takes two counter samples separated by `--rate-interval` (default 5 seconds, finite `0 < seconds <= 60`; interfaces only). Each counter uses its monotonic request midpoint and rate `(second - first) / elapsed`. Counter64 `ifHCInOctets`/`ifHCOutOctets` are multiplied by 8/1000000 for decimal Mbps. Counter32 errors/discards yield counts/second. Only selected interfaces are sampled, without a persistent cache.

Names must match the original selected interface at both samples, and `ifCounterDiscontinuityTime` must be present and unchanged before/after both samples. Four agent-uptime readings must be present and nondecreasing. Failed global guards suppress all rates; failed per-interface guards suppress that interface's rates. Missing, malformed, out-of-range, decreasing or zero-elapsed counters suppress individual rates. Wraps are conservatively omitted, not guessed. These guards depend on correct reporting by the agent.

The original admin/oper snapshot still determines status. Verbose output retains lifetime counters and adds in/out traffic, error and discard rates. Per-interface perfdata suffixes are `in_mbps`, `out_mbps`, `in_errors_s`, `out_errors_s`, `in_discards_s`, `out_discards_s`, with no unit suffix. Aggregate rates appear only when every selected interface has all six rates. Missing fields display `-` and an incomplete-rates note, never a false zero. Runtime includes the sample pause and SNMP requests; per-request timeout is not a whole-check deadline.

Live `.11` walks on 2026-11-03 confirmed both Counter64 traffic columns and discontinuity markers for `eth0`-`eth5` (indexes 2-7), with all markers zero. A staged plugin run on the jump host using Python 3.8 and `--mode interfaces --rate-interval 5 -v` returned OK/exit 0 with complete rates for all six interfaces. `eth0` measured 0.0590503/0.0488503 Mbps in/out; the other five interfaces had zero traffic during that sample. All error/discard rates were zero, while lifetime input discards remained 270 per interface (1620 aggregate). The 39 local tests passed in each repository; reset and malformed-data paths were mocked, not induced on the live device. Temporary staging files and credentials were cleared, and SSH closed. Production files were not changed.

## Results And Credentials

CLI help and argument/threshold validation run before importing `ves_snmp_utils`, pysnmp, pyasn1 or Cryptodome. With no arguments the full help is printed and the process exits UNKNOWN (3); `--help` exits 0. Missing SNMP dependencies or Ctrl+C while loading dependencies produce a clean UNKNOWN result. This avoids crypto initialization for usage requests but does not repair a native-library loading problem for real checks. SNMP request timeouts do not cover Python dependency imports.

The first line is `STATUS - summary | perfdata` (without a perfdata delimiter for sysinfo). `-v` adds processor/mount details. Exit codes are 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN. Invalid CLI configuration, malformed/empty required data and SNMP timeouts return UNKNOWN. Other SNMP errors preserve the shared helper's status. No Python traceback or credential dump is emitted for unexpected failures. Device-supplied summary text is flattened and pipe characters replaced so it cannot inject a new result/perfdata line.

CPU/disk/swap thresholds can be overridden individually; the resulting pair must be finite and satisfy `0 <= warning < critical <= 100`. Both memory modes require both explicit thresholds or neither. Thresholds are rejected for uptime/sysinfo/interfaces/serial-numbers; mount and interface filters are rejected outside their matching modes. The per-request timeout defaults to 5 seconds with the shared helpers' zero retries per request; multi-row walks and optional authentication fallback can take longer than one timeout. This is not a whole-check deadline.

Use `-H/--hostname` for the node and either `-C/--community`/`SNMP_COMMUNITY` or SNMPv3 `--user`. `-P/--port` selects a UDP destination port from 1 to 65535 (default 161); both shared GET and WALK transports honor it, including authentication fallback. Callers without a port attribute still use 161. `-t/--timeout` selects the per-request timeout. `-h/--help` displays short/long usage forms, mode descriptions and examples. SNMPv3 defaults to SHA/AES `authPriv`; `authNoPriv` and `noAuthNoPriv` are available. Authentication/privacy passwords support `SNMP_AUTHPW`/`SNMP_PRIVPW`; explicit flags take precedence. Credentials for both versions retain the existing shared-helper fallback. Protect the process environment and avoid putting real secrets in shell history or documentation.

## Verification Status

Live queries from `172.23.38.11` confirmed CPU/storage tables, system description/object identifier, hostname, agent uptime, and IF-MIB. The six VM interfaces `eth0`-`eth5` and loopback/Podman/veth links were all admin/oper up in the snapshot; virtual links share Ethernet `ifType`, so the default filter uses their names. A direct live plugin run returned OK for six monitored interfaces at 1000 Mbps, with zero errors and 270 input discards per interface. Discards are informational, not alert thresholds. Earlier plugin-mode snapshots showed CPU about 2%, raw RAM about 93%, `/` about 18.6% and `/opt` about 23.8%. These values are snapshots, not expected constants.

`172.23.38.12` timed out; this does not prove host/application failure. The seven existing modes were live-validated against `.11`; UCD-SNMP memory counters were discovered there, but `memory_usage` has not been run live through the plugin. The deployed serial inventory returned one ENTITY-MIB component (`Cisco Application Deployment Engine`, model `ISE-VM-K9`) with OK status. Run `python -B -m unittest discover -s tests -p test_check_cisco_ise.py` from the repository root.

No RADIUS/TACACS+ transaction, ISE API, syslog, replication, certificate, backup or NTP health check is included.

Live `.11` queries on 2026-11-03 confirmed `hrSystemDate` with an explicit UTC offset. Direct staged plugin execution on the jump host's Python 3.8.0 returned OK/exit 0 for `timesync`: 0.315289s behind the monitoring host. The 34 local ISE tests passed; alert boundaries and invalid timestamps were tested with mocks, not induced on the live device.

### Swap Live Test

The user requested live verification from this jump host against `172.23.38.11`. On 2026-11-03, the staged `swap` plugin returned OK/exit 0: 4.9% used (0.38/7.81 GiB), consistent with total 8191912 kB and free 7793564 kB from a separate GET. The temporary staging files were removed, the community cleared, and SSH closed. The following procedure can be reused for future checks.

```bash
ssh -o ControlMaster=no -o ControlPath=none -o MACs=hmac-sha2-256 -o ConnectTimeout=10 -tt -p 11433 wppadm@wpp-nrp-ssh.vestasext.net
```

Stage the updated plugin and shared helper together before testing, and use the supported Python 3.8/PySNMP environment. Enter SSH passwords directly in the terminal. On the jump host, enter the community without echoing it:

```bash
read -r -s -p 'SNMP community (hidden): ' SNMP_COMMUNITY
printf '\n'
export SNMP_COMMUNITY
snmpget -v2c -c "$SNMP_COMMUNITY" -t 5 -r 0 -On 172.23.38.11 1.3.6.1.4.1.2021.4.3.0 1.3.6.1.4.1.2021.4.4.0
/opt/rh/rh-python38/root/usr/bin/python3 ./scripts/check_cisco_ise.py -H 172.23.38.11 --mode swap -w 80 -c 90
printf 'Plugin exit=%s\n' "$?"
unset SNMP_COMMUNITY
```

Compare plugin percentage/GiB and status to the live counters, allowing for changes between requests. Record the result before marking the mode live-verified. Clear credentials and remove only your temporary staging files when finished.