# How the Cisco WLC interface check works

## In plain language

[check_cisco_wlc.py](check_cisco_wlc.py) reads interface inventory, component serial numbers, link states, traffic counters and Smart Licensing data from a Cisco C9800 WLC using [ves_snmp_utils.py](ves_snmp_utils.py). It never changes the device. The six modes separate inventory from health evaluation for interfaces and licenses. These are not end-to-end forwarding, wireless client or subscription-validity tests.

For options and invocation examples, see the [README](README.md). NTP synchronization remains in [check_cisco_wlc_ntp.py](check_cisco_wlc_ntp.py).

## Common execution flow

1. Parse the required hostname and mode. No arguments prints help and exits 3; `--help` exits 0 without querying SNMP. Argparse rejects missing required options or invalid argument types/choices with its own exit 2.
2. Require a community or SNMPv3 username and a positive per-request timeout. CLI SNMPv3 passwords take precedence over `SNMP_AUTHPW`/`SNMP_PRIVPW`. The shared helper tries v3 first and may fall back to v2c when both credentials are supplied.
3. Validate interface selection and usage-only thresholds. Explicit selection in another mode is UNKNOWN. Empty/whitespace-only selection is UNKNOWN. Usage requires a finite interval of at least 1 second and `0 <= warning < critical <= 100`.
4. Query the selected mode. Walks return dictionaries keyed by integer interface index; names are not used to join counters. An SNMP operation failure prints the helper's message and retains its status. Timeouts are generally UNKNOWN; other helper failures can be CRITICAL.
5. Print a summary, performance data where available, and pipe-delimited table rows. Unexpected Python exceptions and interrupts become UNKNOWN.

Interface names/descriptions are flattened to one line, with embedded pipe characters changed to `/`. Both name and description inventories are used so an interface present in either can be listed. This also means selection is against the displayed, normalized text.

## Inventory: list-interfaces

The check walks names, descriptions, aliases, admin state, operational state and reported Mbps capacity. All interfaces are included: physical, VLAN, Null and administratively disabled. No rows means UNKNOWN. Otherwise it returns OK, even with down interfaces, because inventory does not evaluate link health.

The table columns are `Index | Name | Description | Alias | Admin | Oper | Speed (Mbps)`. Missing names fall back to descriptions; empty descriptions/aliases display `-`. Missing states display `unavailable`; unrecognized numeric states display `unknown(number)`. Missing/zero speed displays `unavailable`. Malformed numeric values may instead trigger the top-level UNKNOWN handler.

`interfaces_total` counts inventory indices. `interfaces_up` counts operational-up rows in that inventory, irrespective of admin state or interface type. Neither metric is an alarm threshold.

## Serial inventory: list-serial-numbers

Walk `entPhysicalSerialNum`, normalize text and discard empty/whitespace-only values. No serial-bearing rows means UNKNOWN. Otherwise, walk names, descriptions, models and classes and join them by entity index. Sort output numerically by index, not by serial or name. Repeated serials are not deduplicated.

The table is `Index | Component | Class | Model | Serial number | Description`. A missing component name falls back to its description, then `entity <index>`. Missing models/classes display `unavailable`; missing descriptions display `-`. ENTITY-MIB class 3 is chassis, 9 is module and 12 is CPU. Other standard classes are also labeled; unrecognized numeric classes display `unknown(number)`. SNMP failures retain helper status and malformed values may trigger the top-level UNKNOWN handler.

Successful enumeration returns OK with `serial_components` counting rows, not distinct serial strings. It is inventory only, not a serial-change alarm or expected-device comparison. It does not hard-code chassis index 1, filter only chassis, assume that all entities belong to the queried controller, or apply `--include-interfaces`.

Live walks found `94XUH16ISL6` on `.12` chassis index 1 and `9UFX9AYELRJ` on `.13` chassis index 1. `.12` also exposed index 23 named `Chassis 2` with `.13`'s serial. This is consistent with peer inventory; ownership is not inferred in code. Both exposed R0 serial `JAB1303001C`, so that module serial is not a unique controller identifier. Replay tests covered both datasets, empty serials, duplicate serial strings and missing metadata. The new mode has not yet been run live.

| ENTITY-MIB object | Column OID |
|---|---|
| entPhysicalSerialNum | `1.3.6.1.2.1.47.1.1.1.1.11` |
| entPhysicalName | `1.3.6.1.2.1.47.1.1.1.1.7` |
| entPhysicalDescr | `1.3.6.1.2.1.47.1.1.1.1.2` |
| entPhysicalModelName | `1.3.6.1.2.1.47.1.1.1.1.13` |
| entPhysicalClass | `1.3.6.1.2.1.47.1.1.1.1.5` |

## Licensing: list-licenses and license-health

Both modes read `ciscoSlaEnabled` as TruthValue: 1 means enabled, 2 disabled. Absent, nonnumeric or invalid values are UNKNOWN; SNMP errors retain helper status. Disabled is OK with an explicit inventory-only message in `list-licenses`, but CRITICAL in `license-health`; neither walks entitlement rows in that case and no count metrics are emitted.

When enabled, walk tags, requested quantities, enforcement states and optional short feature names. Use the union of column indices, including index 0; this prevents missing rows in one column from being silently discarded. Each row requires a nonempty tag, an integer quantity in the MIB's unsigned 32-bit range, and a recognized enforcement state. Missing feature names fall back to the tag, then an index label if the tag is also absent. Blank/invalid required values produce an unavailable row, not a success or a zero quantity. Distinct indices are retained even if tags repeat.

`list-licenses` returns OK for structurally complete known states, including noncompliant ones. It prints the state but does not impose compliance alarms. Incomplete rows or unknown state numbers return UNKNOWN. The known legacy `notApplicable` state can be inventoried even though it cannot establish health.

`license-health` applies this explicit policy to structurally valid rows:

| State | Label | Health result |
|---|---|---|
| 1 | initialized | WARNING |
| 2 | waiting | WARNING |
| 3 | authorized | OK |
| 4 | outOfCompliance | CRITICAL |
| 5 | overage | OK: MIB defines permitted overage as still compliant |
| 6 | evaluationPeriod | WARNING |
| 7 | evaluationExpired | CRITICAL |
| 8 | authorizationExpired | CRITICAL |
| 9 | gracePeriodExpired | CRITICAL |
| 10 | disabled | CRITICAL |
| 11 | reservedAuthorized | OK |
| 12 | invalidTag | CRITICAL |
| 13 | notAuthorized | CRITICAL |
| 14 | notApplicable | UNKNOWN: obsolete/indeterminate policy-mode state |
| 15 | inUse | OK: policy-mode usage state, not subscription certification |
| 16 | notInUse | OK only if quantity is 0; nonzero requests are UNKNOWN |

Aggregate severity is confirmed CRITICAL first, then UNKNOWN, then WARNING, then OK. `notApplicable` and inconsistent `notInUse` rows are structurally valid but health-indeterminate. An SNMP operation failure aborts immediately rather than being merged into row status. There are no license thresholds or expiry calculations; traffic `-w/-c` do not affect licensing.

### Empty table handling

Only if every queried entitlement column is empty, query the current `cRFStatusUnitState`. State 9 produces OK with an explicit inventory/health-skipped message. Active, transitional, invalid or unavailable role data produces UNKNOWN. SNMP errors retain their own status; they are not a standby exception. The role is not guessed from the IP or a previous run. Partial tables cannot qualify as empty; populated standby tables are evaluated normally.

### Licensing output and metrics

The table is `Feature | Entitlement tag | Requested quantity | Enforcement status`, with decoded labels and numeric states. Requested quantity is not purchased quantity, AP capacity or unused license balance. Summary metrics for populated tables are `license_entitlements` (union-row count), `license_checked` (structurally valid rows), `license_problem` (health WARNING/CRITICAL rows), and `license_unknown` (invalid or health-indeterminate rows). Structurally valid but indeterminate rows can count in both checked and unknown. Inventory never counts enforcement states as problems. Empty standby skips emit only `license_entitlements=0 license_checked=0`; this is observed local table size, not a zero Smart Account balance.

| Object | Numeric OID |
|---|---|
| ciscoSlaEnabled | `1.3.6.1.4.1.9.9.831.0.4.0` |
| ciscoSlaEntitlementRequestCount | `1.3.6.1.4.1.9.9.831.0.5.1.1.2` |
| ciscoSlaEntitlementTag | `1.3.6.1.4.1.9.9.831.0.5.1.1.3` |
| ciscoSlaEntitlementEnforceMode | `1.3.6.1.4.1.9.9.831.0.5.1.1.5` |
| ciscoSlaEntitlementFeatureName | `1.3.6.1.4.1.9.9.831.0.5.1.1.7` |

Live walks found `.12` exposing `DNA_NWSTACK_E` / `air-network-essentials` and `AIR-DNA-E` / `air-dna-essentials`, each requested quantity 1 and authorized(3). `.13` exposed enablement but no entitlement rows. Legacy licensing end-date, maximum-count and remaining-count columns returned No Such Object on both; Smart authorization and certificate-expiry instances were absent. No licence-pool balance or subscription expiry can be derived from these results. Use CSSM or a licensing inventory integration for those values. Authorization expiry is distinct from subscription expiry.

The new modes were tested by replaying the captured data and synthetic states, not run live. Tests covered all defined enforcement states, disabled/unsupported enablement, missing columns, partial rows, zero-index records, optional-name fallback, HA empty-table rules and SNMP errors. A successful health result means only that the exposed states satisfy the policy above.

## Link health: interface-health

First query the local redundancy state, not the peer state:

| cRFStatusUnitState | Decision |
|---|---|
| 14, active | Evaluate local interface states |
| 9, standbyHot | OK with explicit evaluation-skipped message and `interfaces_checked=0` |
| Other numeric state | WARNING; do not evaluate interfaces |
| Missing/non-numeric state | UNKNOWN |

The standby skip prevents treating role-dependent data-interface states as faults. It does not prove standby link health or validate the HA peer. A standalone controller whose agent does not expose this role cannot be evaluated by this mode.

On the active unit, walk interface names/descriptions and admin/oper states. Exclude interfaces whose description contains `null` (case-insensitive) or whose short name starts with `nu` or `vo`, matching the observed Null0/VoIP-Null0 interfaces. Exclude admin-down rows. This is a name-based exclusion, not an `ifType` test.

For remaining rows, recognized admin and oper values count as checked. Both must be up (1); testing/dormant/notPresent/lowerLayerDown and other recognized non-up states are failures. Absent or unrecognized numeric state values go into the unavailable list. Numeric-conversion failures abort to the top-level UNKNOWN handler.

| Active-unit result | Status |
|---|---|
| At least one confirmed non-up interface | CRITICAL |
| No confirmed failure, but missing/unrecognized state data | UNKNOWN |
| No eligible valid-status rows | UNKNOWN |
| Every evaluated row admin-up/oper-up | OK |

The table contains name/admin/oper state for non-excluded rows. `interfaces_checked` counts valid-status rows, including failing ones; `interfaces_problem` counts confirmed non-up rows; `interfaces_unknown` counts unavailable rows. A confirmed CRITICAL outranks missing rows that were collected normally, but errors aborting the check return immediately. There is no traffic-rate, error-counter or packet-loss test in this mode.

## Traffic: interface-usage

### Select interfaces

Walk names, descriptions, admin states and capacity. With no filter, evaluate admin-up non-Null interfaces; VLANs are eligible. Missing or invalid admin state on a candidate aborts with UNKNOWN. Admin testing is not eligible. Operational state is not used to select traffic rows, and HA role is not queried: standby traffic may be sampled and zero traffic is valid.

`--include-interfaces` is split on commas, trimmed and deduplicated. Every nonempty token must match an exact case-sensitive `ifName` or `ifDescr`. `Gi2` and `GigabitEthernet2` identify the same observed index; specifying both does not double-count it. A mixed list containing one unknown name returns UNKNOWN rather than monitoring only its valid part. Explicitly selecting a disabled/testing or Null interface also returns UNKNOWN. Selecting no eligible interfaces is UNKNOWN.

The filter is applied before eligibility/status checks on unselected rows. Walks still retrieve whole columns, but only selected rows contribute rate errors, table rows or perfdata. A failed whole-column SNMP operation still aborts the check.

### Sample counters

Read 64-bit inbound and outbound octet columns. For each direction separately, record the midpoint between monotonic timestamps before/after its walk. Also read each interface's discontinuity timestamp and device uptime. Wait `--interval` seconds (default 5), then repeat. The actual elapsed sampling time includes request overhead; the configured delay alone is not the denominator.

If the second uptime is less than or equal to the first, return UNKNOWN immediately. This conservatively rejects reboots, uptime wraps or clocks that did not advance. Each evaluated interface also requires matching discontinuity timestamps across samples, a positive capacity and counters that do not decrease. Missing values or these validation failures make that row unavailable. No 32-bit fallback, wrap correction, automatic retry or persisted counter state is used.

For each direction:

```text
elapsed_seconds = second_walk_midpoint - first_walk_midpoint
rate_bps = (second_octets - first_octets) * 8 / elapsed_seconds
capacity_bps = ifHighSpeed * 1,000,000
utilization_percent = rate_bps / capacity_bps * 100
display_Mbps = rate_bps / 1,000,000
```

Inbound and outbound percentages are compared separately, not summed. The maximum determines that interface's status: at/above critical is CRITICAL; otherwise at/above warning is WARNING; otherwise OK. The worst interface wins, except an unavailable row makes an otherwise OK/WARNING result UNKNOWN. A confirmed CRITICAL row still takes precedence over unavailable rows. Failures aborting sampling itself return immediately, before per-row evaluation.

For example, an increase of 500,000,000 octets over 5 actual seconds gives 800,000,000 bps (800 Mbps). With a reported 1000 Mbps capacity, utilization is 80%, exactly the default warning boundary. This is a calculation example, not a live observation.

### Output

Usage table columns are `Name | In Mbps | Out Mbps | In % | Out %`. Rates display three decimal places, percentages two; comparisons use unrounded values. Unavailable rows show the reason and emit no rate/utilization metrics. Valid rows publish:

| Metric | Meaning |
|---|---|
| `ifN_in_bps`, `ifN_out_bps` | Bits/second, with min 0 and max reported capacity |
| `ifN_in_pct`, `ifN_out_pct` | Percent, with warning/critical limits and displayed bounds 0-100 |

N is the SNMP interface index, not the name. Indices may change after reconfiguration/reboot. Percentages are not clamped at 100; inaccurate speeds/counters can produce larger values. Graph labels do not imply measured speed or a guaranteed physical bottleneck. VLAN and physical counters may describe overlapping traffic and should not be summed as independent totals.

## OIDs used

Scalar instances include `.0`; table columns are indexed by ifIndex.

| Object | Numeric OID | Modes |
|---|---|---|
| ifName | `1.3.6.1.2.1.31.1.1.1.1` | All |
| ifDescr | `1.3.6.1.2.1.2.2.1.2` | All |
| ifAlias | `1.3.6.1.2.1.31.1.1.1.18` | Inventory |
| ifAdminStatus | `1.3.6.1.2.1.2.2.1.7` | All |
| ifOperStatus | `1.3.6.1.2.1.2.2.1.8` | Inventory, health |
| ifHighSpeed | `1.3.6.1.2.1.31.1.1.1.15` | Inventory, usage |
| cRFStatusUnitState | `1.3.6.1.4.1.9.9.176.1.1.2.0` | Health |
| ifHCInOctets | `1.3.6.1.2.1.31.1.1.1.6` | Usage |
| ifHCOutOctets | `1.3.6.1.2.1.31.1.1.1.10` | Usage |
| ifCounterDiscontinuityTime | `1.3.6.1.2.1.31.1.1.1.19` | Usage |
| sysUpTime | `1.3.6.1.2.1.1.3.0` | Usage |

## Observed devices and validation scope

Live walks on C9800-CL IOS-XE 17.15.6 showed the following snapshot. HA roles can change; these are not fixed IP-to-role assumptions in the code.

| Interface | Admin, both | Oper on .12 (active) | Oper on .13 (standbyHot) |
|---|---|---|---|
| Gi1 | Down | Down | Down |
| Gi2 | Up | Up | Down |
| Vo0 / VoIP-Null0 | Up | Up | Up |
| Nu0 / Null0 | Up | Up | Down |
| Vl1 | Down | Down | Down |
| Vl2555 | Up | Up | Up |

User-supplied live usage output from `172.23.36.12` showed valid Gi2/Vl2555 rates and OK. On `172.23.36.13`, Gi2 had valid rates but a Vl2555 counter decreased, producing UNKNOWN. Its cause is not established; it must not be assumed to be a genuine 64-bit wrap or harmless standby artifact. The filter permits intentionally monitoring only Gi2 without weakening reset validation for selected rows.

Replay/synthetic tests covered rate calculations, threshold boundaries, HA skip/health failures, missing values, resets and interface-filter cases. Filtered live execution and live SNMPv3 verification have not been demonstrated in this session. These observations do not establish behavior on every C9800 version.

## Software-version discovery

Version discovery was performed manually over SNMP on 2026-10-14. It is not an additional plugin mode and does not affect any mode's exit status.

1. Read `sysDescr.0` (`1.3.6.1.2.1.1.1.0`) for the running IOS-XE software description, release number and build.
2. Walk `entPhysicalName` (`1.3.6.1.2.1.47.1.1.1.1.7`) and `entPhysicalSoftwareRev` (`1.3.6.1.2.1.47.1.1.1.1.10`), joining rows by entity index. Do not require a chassis-level revision: it was empty on these units while module revisions were populated.
3. Treat `entPhysicalFirmwareRev` (`1.3.6.1.2.1.47.1.1.1.1.9`) as a separate field. Empty strings or the literal `Unknown` do not identify firmware or the running operating system.

| Target | sysDescr version/build | R0 software (index 20) | F0 software (index 40) |
|---|---|---|---|
| `172.23.36.12` | `17.15.6`, `fc2` | `17.15.06` | `17.15.06` |
| `172.23.36.13` | `17.15.6`, `fc2` | `17.15.06` | `17.15.06` |

Both descriptions identified C9800-CL software and compilation time `Wed 22-Jul-26 03:38`. The module format pads the final numeric component with a zero; these observed values are consistent with the same release. They are not independent evidence of a separate `17.15.06` upgrade. No generic version-normalization or comparison algorithm is implemented.

Chassis software revisions and most firmware revisions were empty; F0 firmware was the literal `Unknown` on both units. Component indices above are observed data, not hard-coded discovery rules. Both units returned the same `sysName` (`SP-99941-VES-ESX11-WLC1.localwpp.net`), so IP and the previously discovered local chassis serial distinguish the query targets.

The snapshot confirms what SNMP reported at query time, not current vendor support, recommended upgrade level, vulnerability exposure or ongoing HA version agreement. The plugin does not compare against an expected release, compare peers or alarm on version differences. See the [README](README.md) for manual query commands.

## Operational limits

Allow an overall monitoring timeout longer than the sample delay plus all SNMP requests; `--timeout` is not a global deadline. Missing passwords/dependencies or unsupported MIB columns must be resolved in the execution environment. The script uses the existing pysnmp helper/API and Python 3.8 deployment convention, not a new dependency environment.

This check does not monitor AP/client interfaces, interface error/discard rates, historical peaks, HA peer health, packet delivery or NTP state. It does not suppress all standby usage or treat a zero traffic rate as a fault. Inventory success and standby health skips must not be interpreted as a guarantee of forwarding health.