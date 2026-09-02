# check_cisco_firewall.py — OIDs, tables and status meanings per mode

SNMP OIDs used by [check_cisco_firewall.py](check_cisco_firewall.py), sourced from the shared `OIDS` dict in [ves_snmp_utils.py](ves_snmp_utils.py). Target platforms: ASA / FTD / Secure Firewall 3100 (e.g. Firepower 3110).

## Nagios exit codes

Every mode ultimately maps its SNMP result onto the standard Nagios exit codes (`NAGIOS_STATUS` in [ves_snmp_utils.py](ves_snmp_utils.py)):

| Exit code | Status | Meaning |
|---|---|---|
| `0` | OK | Value(s) within normal range / component healthy |
| `1` | WARNING | Value(s) at/above `--warning` threshold, or a component reporting a degraded-but-non-fatal state |
| `2` | CRITICAL | Value(s) at/above `--critical` threshold, or a component reporting a failed/faulty state |
| `3` | UNKNOWN | SNMP error, missing/unsupported OID, or the check couldn't determine a state at all |

## ha_summary
HA state of the primary/secondary hardware units, from `cfwHardwareStatusValue`.

| OID name | OID | Table / index |
|---|---|---|
| `cfwHardwareStatusValue` | 1.3.6.1.4.1.9.9.147.1.2.1.1.1.3 | `cfwHardwareStatusTable`, queried directly at instance `.6` (primary) and `.7` (secondary) — see [Fixed hardware-status indices](#fixed-hardware-status-indices) below |

### cfwHardwareStatusValue meanings (CISCO-FIREWALL-MIB `HardwareStatus`)

| Value | MIB label | Meaning |
|---|---|---|
| `1` | `other` | State not one of the following |
| `2` | `up` | Hardware unit is up/operational (no failover role implied) |
| `3` | `down` | Hardware unit is down |
| `4` | `error` | Hardware unit reporting an error |
| `5` | `overTemp` | Hardware unit has shut down / is impaired due to over-temperature |
| `6` | `busy` | Hardware unit is busy (e.g. initializing) |
| `7` | `noMedia` | No media present |
| `8` | `backup` | Unit acting as a backup |
| `9` | `active` | Unit is the active member of the HA pair |
| `10` | `standby` | Unit is the standby member of the HA pair |
| *(none)* | *(missing instance)* | Reported as "not present" — failover not configured for that role, or a standalone unit |

### Result logic (`check_ha_summary()`)

| Condition | Exit code | Summary |
|---|---|---|
| Both primary and secondary instances missing | `3` UNKNOWN | Failover not configured (standalone unit) |
| Either state in `{down, error, overTemp, noMedia, unknown, not present}` | `2` CRITICAL | Reflects the bad state |
| No unit reports `active` | `2` CRITICAL | "No active unit" |
| More than one unit reports `active`, or more than one reports `standby` | `2` CRITICAL | "Split-brain detected" |
| Either state in `{backup, busy, other}` | `1` WARNING | — |
| Otherwise (one `active` + one `standby`) | `0` OK | — |

The output additionally best-effort annotates the queried unit's own slot and live status, e.g. `[10.56.1.226 = primary unit, currently active]`, using `_determine_unit_role()` (see [Primary/Secondary IP labeling](#primarysecondary-ip-labeling-_determine_unit_role) below) — omitted if the platform doesn't populate `cfwHardwareInformation`.

## ha_pair
Cross-checks HA state by independently querying `cfwHardwareStatusValue` (same OID/instances as `ha_summary` above) from both `--hostname` and `--peer-hostname`, rather than relying on a single unit's view of its peer.

If `--peer-hostname` is omitted, the peer is guessed from `--hostname` using the environment-observed +/-2-last-octet IPv4 convention (e.g. `.226`/`.228`, `.227`/`.229`) — see `PEER_IP_OFFSET_CANDIDATES`/`_guess_peer_candidates()`/`_discover_peer()` in the script. A guessed candidate is never trusted blindly: it must respond via SNMP and report the same primary/secondary values as `--hostname` before being accepted.

### Result logic (`check_ha_pair()`)

| Condition | Exit code | Summary |
|---|---|---|
| `--hostname` unreachable via SNMP | `2` CRITICAL | "Unit `<host>` unreachable via SNMP" |
| `--hostname` has no primary/secondary instances (failover not configured) | `3` UNKNOWN | "Failover is not configured on `<host>`" |
| `--peer-hostname` given but unreachable | `2` CRITICAL | "Peer unit `<peer>` unreachable via SNMP" |
| `--peer-hostname` given but has no primary/secondary instances | `3` UNKNOWN | "Failover is not configured on peer unit `<peer>`" |
| `--peer-hostname` omitted and no IP-heuristic candidate can be confirmed | `1` WARNING | Lists which candidate(s) were tried (or that `--hostname` isn't a plain IPv4 address) |
| The two units' primary/secondary values disagree | `2` CRITICAL | "HA pair state mismatch" |
| Both agree, but either value isn't a failover-safe state (9/10) | `2` CRITICAL | Reflects the reported label (e.g. Standby Cold/Failed) |
| Both agree and both are failover-safe (9/10) | `0` OK | "Both units reachable and agree" |

An auto-detected peer is noted in the output as `(peer <ip> auto-detected via IP heuristic)`.

### Primary/Secondary IP labeling (`_determine_unit_role()`)

Unlike `cfwHardwareStatusValue`/`cfwHardwareStatusDetail`, which are fixed, pair-mirrored entries (identical no matter which paired IP is queried), `cfwHardwareInformation` (column 2 of the same `cfwHardwareStatusTable`, OID `1.3.6.1.4.1.9.9.147.1.2.1.1.1.2`) is self-referential: on real devices its free text includes `(this device)` only on the row (`.6`=primary/`.7`=secondary) matching the unit that actually answered the query.

`_determine_unit_role(args, host)` GETs `cfwHardwareInformation.6` and `.7` from `host` and returns `"primary"`/`"secondary"` if either instance's text contains `"this device"` (case-insensitive), else `None`. `check_ha_pair()` calls this once for `--hostname` and once for the (given or auto-detected) peer, then labels the output as `Primary [<ip>]`/`Secondary [<ip>]`. If the OID isn't populated on a given platform or credentials/timeout fail for these extra GETs, the labels are silently omitted (`None`) rather than guessed — this is purely additive and never affects the exit code.

## cpu
Average CPU load (5s/1m/5m), from CISCO-PROCESS-MIB's CPU history table.

| OID name | OID | Table / index |
|---|---|---|
| `cpmCPUTotal5secRev` | 1.3.6.1.4.1.9.9.109.1.1.1.1.6 | `cpmCPUTotalTable`, indexed by `cpmCPUTotalIndex` (one row per physical/logical CPU) |
| `cpmCPUTotal1minRev` | 1.3.6.1.4.1.9.9.109.1.1.1.1.7 | Same table/index |
| `cpmCPUTotal5minRev` | 1.3.6.1.4.1.9.9.109.1.1.1.1.8 | Same table/index |

All three OIDs are walked (`pysnmp_walk_indexed`) rather than fetched as scalars, since a device with multiple CPU cores/data planes reports one row per core; the script averages all rows for each time window (5s/1m/5m are plain percentages, no MIB enum involved).

### Result logic (`check_cpu()`)

| Condition | Exit code |
|---|---|
| 5-minute average ≥ `--critical` (default `90`) | `2` CRITICAL |
| 5-minute average ≥ `--warning` (default `80`) | `1` WARNING |
| Otherwise | `0` OK |
| No CPU rows returned at all | `3` UNKNOWN |

Only the 5-minute average drives the exit code; 5s/1m are reported for context only.

## memory
System/data-plane memory pool usage. The classic table is tried first; the enhanced table is the fallback for platforms that don't populate the classic one.

| OID name | OID | Table / index | Notes |
|---|---|---|---|
| `ciscoMemPoolName` | 1.3.6.1.4.1.9.9.48.1.1.1.2 | `ciscoMemoryPoolTable`, indexed by `ciscoMemoryPoolType` | CISCO-MEMORY-POOL-MIB (classic ASA) |
| `ciscoMemPoolUsed` | 1.3.6.1.4.1.9.9.48.1.1.1.5 | Same table/index | |
| `ciscoMemPoolFree` | 1.3.6.1.4.1.9.9.48.1.1.1.6 | Same table/index | |
| `cempMemPoolName` | 1.3.6.1.4.1.9.9.221.1.1.1.1.3 | `cempMemPoolTable`, composite-indexed by `entPhysicalIndex` + `cempMemPoolIndex` | CISCO-ENHANCED-MEMPOOL-MIB fallback (newer ASA/FTD/Secure Firewall); queried via `pysnmp_walk_multi_indexed` |
| `cempMemPoolUsed` | 1.3.6.1.4.1.9.9.221.1.1.1.1.7 | Same table/index | |
| `cempMemPoolFree` | 1.3.6.1.4.1.9.9.221.1.1.1.1.8 | Same table/index | |

### Pool selection

The classic table is walked first; if it returns no rows, the script falls back to the enhanced table. Whichever table responded, the reported pool is chosen by matching `*PoolName` (case-insensitive substring) against this preference order, first match wins:

1. `dp system`
2. `system memory`
3. `processor`
4. *(fallback)* the first pool row returned, in whatever order SNMP reported it

Usage percentage is computed as `used / (used + free) * 100` for the selected pool — there's no MIB status enum here, just a raw byte count comparison.

### Result logic (`check_memory()`)

| Condition | Exit code |
|---|---|
| Usage % ≥ `--critical` (default `90`) | `2` CRITICAL |
| Usage % ≥ `--warning` (default `80`) | `1` WARNING |
| Otherwise | `0` OK |
| No pool rows found at all, or selected pool missing used/free values | `3` UNKNOWN |

## connections
Current in-use/peak connection counts, from CISCO-FIREWALL-MIB `cfwConnectionStatValue`.

| OID name | OID | Table / index |
|---|---|---|
| `connActiveConnections` | 1.3.6.1.4.1.9.9.147.1.2.2.2.1.5.40.6 | `cfwConnectionStatTable`, indexed by service=`40` ("entire firewall" aggregate) + stat type `6` (`currentInUse`, `Gauge32`) |
| `connPeakConnections` | 1.3.6.1.4.1.9.9.147.1.2.2.2.1.5.40.7 | Same table, stat type `7` (`high`/peak, `Gauge32`) |

No status/severity enum applies here — both are plain `Gauge32` counts. There is no "failed connections" stat in `cfwConnectionStatTable` on these platforms; only `currentInUse`/`high` are populated (see repo memory notes for the investigation that ruled out the wrong `CISCO-IPSEC-FLOW-MONITOR-MIB` OIDs originally used here).

### Result logic (`check_connections()`)

| Condition | Exit code |
|---|---|
| Current in-use ≥ `--critical` (if given) | `2` CRITICAL |
| Current in-use ≥ `--warning` (if given) | `1` WARNING |
| Otherwise | `0` OK |
| `connActiveConnections` instance missing | `3` UNKNOWN |

`--warning`/`--critical` are optional for this mode (no defaults) — without them the check always reports OK and just publishes the counts as performance data.

## uptime
Time since last reboot, from the standard MIB-II `sysUpTime` scalar (hundredths of a second, converted to `Nd Nh Nm Ns`).

| OID name | OID | Table / index |
|---|---|---|
| `sysUpTime` | 1.3.6.1.2.1.1.3.0 | Scalar (`.0` instance), no table |

### Result logic (`check_uptime()`)

`--warning`/`--critical` here are **minimum** seconds thresholds (i.e. they flag a *recent* reboot), not maximums:

| Condition | Exit code |
|---|---|
| Uptime seconds < `--critical` (if given) | `2` CRITICAL — "(recent reboot detected)" |
| Uptime seconds < `--warning` (if given) | `1` WARNING — "(recent reboot detected)" |
| Otherwise | `0` OK |

Both thresholds are optional; without them the check always reports OK and just publishes the uptime as performance data.

## primary_state / secondary_state
Combined text role and numeric HA state, sharing `_check_combined_state()`. `cfwHardwareStatusDetail`/`cfwHardwareStatusValue` are **fixed, configured-role** entries shared cluster-wide by the HA pair's MIB — querying either paired unit's IP returns identical output.

| OID name | OID | Table / index |
|---|---|---|
| `cfwHardwareStatusDetail` | 1.3.6.1.4.1.9.9.147.1.2.1.1.1.4 | `cfwHardwareStatusTable`, instance `.6` for `primary_state`, `.7` for `secondary_state` |
| `cfwHardwareStatusValue` | 1.3.6.1.4.1.9.9.147.1.2.1.1.1.3 | Same table, same instance selection |

### Fixed hardware-status indices

| Index | Role |
|---|---|
| `6` | Primary unit (fixed configured role, used by `ha_summary` and `primary_state`) |
| `7` | Secondary unit (fixed configured role, used by `ha_summary` and `secondary_state`) |

### Role text (`cfwHardwareStatusDetail`) meanings

The detail string is free text; the script substring-matches it (case-insensitive):

| Text contains | Role reported | Role exit contribution |
|---|---|---|
| `"active"` | "Active unit" | `0` OK |
| `"standby"` (but not `"cold"`) | "Standby unit" | `0` OK |
| Anything else non-empty | The raw text, verbatim | `2` CRITICAL |
| Empty/missing, but numeric state present | "unknown" | `3` UNKNOWN |
| Both text and numeric state missing | — | `3` UNKNOWN — "No role/state information available (failover not configured?)" |

### Numeric state (`cfwHardwareStatusValue`) meanings — `PEER_NUMERIC_STATE_MAP`

This is a platform-specific extension beyond the official CISCO-FIREWALL-MIB `HardwareStatus` textual convention (which only defines values up to `10`) — confirmed against real device output:

| Value | State label | Failover-safe? | State exit contribution |
|---|---|---|---|
| `9` | Active | Yes | `0` OK |
| `10` | Standby Ready | Yes (both units OK) | `0` OK |
| `11` | Standby Cold | No | `2` CRITICAL |
| `12` | Failed | No (both units CRITICAL) | `2` CRITICAL |
| *(any other value)* | "Forming/Unknown" | No | `2` CRITICAL |
| *(missing instance)* | "unknown" | — | `3` UNKNOWN |

### Combined result

The mode's final exit code is `max(role_exit, state_exit)` from the two tables above — either the text role or the numeric state can independently push the result to WARNING/CRITICAL/UNKNOWN.

### Queried-unit annotation

Both modes also best-effort annotate the queried IP's own active/standby status via `_determine_unit_role()` (same helper `ha_pair` uses — see [Primary/Secondary IP labeling](#primarysecondary-ip-labeling-_determine_unit_role) above):

| Condition | Note appended |
|---|---|
| Queried IP's slot (primary/secondary) matches this mode's fixed `hw_index` | `[<ip> = <role> unit, currently <role text>]` — the printed role text describes the queried IP directly |
| Queried IP's slot does *not* match this mode's fixed `hw_index` | `[<ip> = <role> unit, currently <flipped role text>; this result reflects the <primary/secondary>/peer unit]` — the printed role text describes the peer, so it's flipped (Active↔Standby) to also state the queried IP's own status |
| `_determine_unit_role()` can't determine a role, or the role text isn't `Active unit`/`Standby unit` | No note appended |

## sysinfo
Hardware description, hostname and chassis model — purely informational, no thresholds or status enum.

| OID name | OID | Table / index |
|---|---|---|
| `sysDescr` | 1.3.6.1.2.1.1.1.0 | Scalar (`.0` instance) |
| `sysName` | 1.3.6.1.2.1.1.5.0 | Scalar (`.0` instance) |
| `entPhysicalClass` | 1.3.6.1.2.1.47.1.1.1.1.5 | `entPhysicalTable`, indexed by `entPhysicalIndex` — used to find the chassis entry (class `3`, see [entPhysicalClass meanings](#entphysicalclass-meanings-used-by-this-check)) |
| `entPhysicalModelName` | 1.3.6.1.2.1.47.1.1.1.1.13 | Same table/index |

### Result logic (`check_sysinfo()`)

Always exits `0` OK if `sysDescr`/`sysName` are retrieved successfully; any SNMP GET failure on those exits with that error's own code (typically `3` UNKNOWN). The chassis model (`_chassis_model_name()`) is best-effort and never affects the exit code: it walks `entPhysicalClass`/`entPhysicalModelName`, takes the first entry where the class is chassis (`3`), and is silently omitted from the output if either walk fails or no chassis entry with a populated model name is found.

## hardware
Fan tray / power supply operational status, plus best-effort voltage/RPM sensor readings.

| OID name | OID | Table / index | Notes |
|---|---|---|---|
| `entPhysicalClass` | 1.3.6.1.2.1.47.1.1.1.1.5 | `entPhysicalTable`, indexed by `entPhysicalIndex` | Identifies fan (`7`) vs power supply (`6`) entries — see [entPhysicalClass meanings](#entphysicalclass-meanings-used-by-this-check) |
| `entPhysicalDescr` | 1.3.6.1.2.1.47.1.1.1.1.2 | Same table/index | Component name/description |
| `cefcFanTrayOperStatus` | 1.3.6.1.4.1.9.9.117.1.4.1.1.1 | `cefcFanTrayStatusTable`, indexed by `entPhysicalIndex` | Required |
| `cefcFRUPowerOperStatus` | 1.3.6.1.4.1.9.9.117.1.1.2.1.2 | `cefcFRUPowerStatusTable`, indexed by `entPhysicalIndex` | Required |
| `entSensorType` | 1.3.6.1.4.1.9.9.91.1.1.1.1.1 | `entSensorValueTable`, indexed by `entPhysicalIndex` | Best-effort; not every platform populates this MIB |
| `entSensorValue` | 1.3.6.1.4.1.9.9.91.1.1.1.1.4 | Same table/index | Best-effort; raw reading, scaled by `entSensorScale` |
| `entSensorScale` | 1.3.6.1.4.1.9.9.91.1.1.1.1.2 | Same table/index | Best-effort; see [Sensor scale/type meanings](#sensor-scaletype-meanings) |

### entPhysicalClass meanings (used by this check)

| Value | Meaning |
|---|---|
| `3` | `chassis` — the chassis entry, used by `sysinfo` to look up `entPhysicalModelName` |
| `6` | `powerSupply` — a power supply unit entry |
| `7` | `fan` — a fan tray entry |
| *(other ENTITY-MIB values exist)* | Ignored by this check |

Filtering by `entPhysicalClass` (rather than matching keywords in `entPhysicalDescr`) is used because the description text is inconsistent/truncated across platforms (e.g. Secure Firewall 3100 PSU descriptions don't contain "psu"/"power supply").

### cefcFanTrayOperStatus value meanings

| Value | MIB label | Meaning | Script severity |
|---|---|---|---|
| `1` | `unknown` | System can't currently determine the fan tray's status | WARNING |
| `2` | `up` | Fan tray present and operating normally | OK |
| `3` | `down` | Fan tray present but not operating / failed | WARNING (downgraded — see note) |
| `4` | `warning` | Fan tray operating outside normal parameters (degraded) | CRITICAL |

Note: `down(3)` is deliberately downgraded to WARNING instead of CRITICAL because production Secure Firewall 3100 / FTD 7.4.2 units have been observed consistently reporting `down(3)` for the fan tray even when the hardware is otherwise healthy. `warning(4)` is kept at CRITICAL since it reflects a real problem. See `FAN_TRAY_STATUS_MAP`/`FAN_TRAY_STATUS_SEVERITY` in [check_cisco_firewall.py](check_cisco_firewall.py).

### cefcFRUPowerOperStatus value meanings (CISCO-ENTITY-FRU-CONTROL-MIB `PowerOperType`)

| Value | MIB label | Meaning | Script severity |
|---|---|---|---|
| `1` | `offEnvOther` | Off due to another environmental reason | CRITICAL |
| `2` | `on` | Powered on and operating normally | OK |
| `3` | `offAdmin` | Administratively powered off | CRITICAL |
| `4` | `offDenied` | Power denied (insufficient power available) | CRITICAL |
| `5` | `offEnvPower` | Off due to power supply failure | CRITICAL |
| `6` | `offEnvTemp` | Off due to over-temperature | CRITICAL |
| `7` | `offEnvFan` | Off due to fan failure | CRITICAL |
| `8` | `failed` | Power supply has failed | CRITICAL |
| `9` | `onButFanFail` | On but its own cooling fan has failed | CRITICAL |
| `10` | `offCooling` | Off due to insufficient cooling/airflow | CRITICAL |
| `11` | `offConnectorRating` | Off — connector power rating exceeded | CRITICAL |
| `12` | `onButInlinePowerFail` | On but inline (PoE) power has failed | CRITICAL |

Only value `2` (`on`) is treated as OK; every other value is CRITICAL — there's no WARNING tier for power supplies.

### Sensor scale/type meanings

Used only to compute human-readable voltage/RPM values for display (not part of the pass/fail decision):

| `entSensorType` value | Meaning |
|---|---|
| `3` | `voltsAC` — starts a new PSU electrical reading block |
| `4` | `voltsDC` — starts a new PSU electrical reading block |
| `10` | `rpm` — a fan tachometer reading |
| *(others)* | amps/watts/temperature/etc., read but not surfaced individually |

`entSensorValue` is scaled by `entSensorScale` using `raw * 10^((scale-9)*3)` (scale `9` = `units`, i.e. no scaling — see `_group_sensor_readings()`). Because `entPhysicalContainedIn` does not extend to the sensor rows on this platform, readings can't be tied to a specific fan/PSU by index; instead each PSU's electrical block (starting at a `voltsAC`/`voltsDC` reading) consumes any following `rpm` readings as its internal fan, and any leftover `rpm` readings are treated as chassis fan tachometers, then evenly distributed across the fan tray / PSU rows found via `cefcFanTrayOperStatus`/`cefcFRUPowerOperStatus`.

### Result logic (`check_hardware()`)

| Condition | Exit code |
|---|---|
| No fan/PSU components found at all | `0` OK — "No fan tray/power supply components reported by this unit (expected on a secondary/non-primary logical instance)" |
| One or more components not OK | `max` severity across all components (WARNING or CRITICAL per the tables above) |
| All components OK | `0` OK |

Note: some units (e.g. a secondary logical FTD instance sharing chassis with another instance) never report any `entPhysicalClass` fan/PSU rows at all — confirmed live on 10.56.1.227/.229. That's expected on those units, not a fault, so the script exits OK with no fan/PSU components rather than UNKNOWN.

## interfaces
Admin/oper status of all real interfaces (ASA-internal pseudo-interfaces excluded), plus informational link speed and error/discard counters.

| OID name | OID | Table / index |
|---|---|---|
| `ifName` | 1.3.6.1.2.1.31.1.1.1.1 | `ifXTable`, indexed by `ifIndex` |
| `ifAdminStatus` | 1.3.6.1.2.1.2.2.1.7 | `ifTable`, indexed by `ifIndex` |
| `ifOperStatus` | 1.3.6.1.2.1.2.2.1.8 | `ifTable`, indexed by `ifIndex` |
| `ifAlias` | 1.3.6.1.2.1.31.1.1.1.18 | `ifXTable`, indexed by `ifIndex` |
| `ifHighSpeed` | 1.3.6.1.2.1.31.1.1.1.15 | `ifXTable`, indexed by `ifIndex` (Mbps) |
| `ifInErrors` | 1.3.6.1.2.1.2.2.1.14 | `ifTable`, indexed by `ifIndex` |
| `ifOutErrors` | 1.3.6.1.2.1.2.2.1.20 | `ifTable`, indexed by `ifIndex` |
| `ifInDiscards` | 1.3.6.1.2.1.2.2.1.13 | `ifTable`, indexed by `ifIndex` |
| `ifOutDiscards` | 1.3.6.1.2.1.2.2.1.19 | `ifTable`, indexed by `ifIndex` |

### ifAdminStatus meanings (MIB-II `IF-MIB`)

| Value | Meaning |
|---|---|
| `1` | `up` — administratively enabled |
| `2` | `down` — administratively disabled/shut down |
| `3` | `testing` — in test mode, no operational packets can pass |

### ifOperStatus meanings (MIB-II `IF-MIB`)

| Value | Meaning |
|---|---|
| `1` | `up` |
| `2` | `down` |
| `3` | `testing` |
| `4` | `unknown` |
| `5` | `dormant` |
| `6` | `notPresent` |
| `7` | `lowerLayerDown` |

Only `ifAdminStatus`/`ifOperStatus` values `1`/`2` are treated specially by this check (see below); other values are simply reported as "UP" (i.e. not flagged down) since they don't represent an admin-up-but-operationally-failed interface.

### Link speed and error/discard counters

Each monitored interface's output line is followed by `ifHighSpeed` (Mbps, omitted if `0`/unavailable) and the four `ifIn/OutErrors`/`ifIn/OutDiscards` counters, e.g.:

```
GigabitEthernet0/0 (WAN): UP, 1000Mbps, errors(in/out)=0/0, discards(in/out)=3/0
```

These four counters are also summed across all monitored interfaces and reported as `errors_total`/`discards_total` in the perfdata. All of this is walked best-effort — if any of these OIDs aren't populated on a platform, the walk silently degrades to an empty set rather than failing the check. **This data is purely informational: it never affects the UP/DOWN determination or the overall exit code.**

### Excluded pseudo-interfaces

Any `ifName` containing one of these substrings (case-insensitive) is skipped entirely — not reported, not counted:

`internal-data`, `nlp_int_tap`, `ccl_ha_nlp_int_tap`, `ha_ctl_nlp_int_tap`, `ethernet1/4`

These are ASA/FTD-internal pseudo-interfaces present on every unit regardless of configuration, not real monitored links. All other interfaces are monitored dynamically (no fixed named-interface list), since `nameif` naming varies significantly across firewall pairs/models.

### Result logic (`check_interfaces()`)

| Condition (per monitored interface) | Reported as |
|---|---|
| `ifAdminStatus == 1` (up) AND `ifOperStatus != 1` (not up) | DOWN |
| Otherwise | UP |

| Overall condition | Exit code |
|---|---|
| One or more interfaces DOWN | `2` CRITICAL |
| All monitored interfaces UP | `0` OK |
| No interfaces left after excluding pseudo-interfaces | `3` UNKNOWN |

Perfdata: `interfaces_total`, `interfaces_down`, `errors_total`, `discards_total` (the latter two are informational and don't affect the exit code above).

## Verifying against native Cisco commands

SSH to the device lands in FXOS on the Secure Firewall 3100 series. For everything except `hardware`, run `connect ftd` then `system support diagnostic-cli` then `enable` to get the classic ASA-style `show` command set.

| Mode | Native command | Where to run |
|---|---|---|
| `ha_summary` / `primary_state` / `secondary_state` | `show failover` or `show failover state` | FTD diagnostic-cli |
| `ha_pair` | `show failover` (or `show failover state`) run separately on **both** `--hostname` and `--peer-hostname` — confirm both agree on which unit is Active vs Standby Ready and that neither reports Failed/Standby Cold. `show failover history` is useful if a mismatch suggests a recent transition. There's no single native command equivalent to the cross-query the script performs; it must be checked on both units | FTD diagnostic-cli (both units) |
| `cpu` | `show cpu usage` | FTD diagnostic-cli |
| `memory` | `show memory` or `show memory detail` | FTD diagnostic-cli |
| `connections` | `show conn count` | FTD diagnostic-cli |
| `uptime` | `show version` | FTD diagnostic-cli |
| `sysinfo` | `show version` + `show hostname` | FTD diagnostic-cli |
| `hardware` | `show environment` + `show inventory` | FXOS (chassis owns the hardware on the 3100 series) |
| `interfaces` | `show interface ip brief` (or `show interface` for detail) + `show nameif` | FTD diagnostic-cli |
