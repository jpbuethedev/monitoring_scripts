# How the Cisco WLC interface check works

## In plain language

[check_cisco_wlc.py](check_cisco_wlc.py) reads interface inventory, link states and traffic counters from a Cisco C9800 WLC using [ves_snmp_utils.py](ves_snmp_utils.py). It never changes the device. The three modes answer different questions: what interfaces exist, whether enabled links on the active controller are up, and how much reported capacity traffic uses. These are not end-to-end forwarding or wireless client tests.

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

## Operational limits

Allow an overall monitoring timeout longer than the sample delay plus all SNMP requests; `--timeout` is not a global deadline. Missing passwords/dependencies or unsupported MIB columns must be resolved in the execution environment. The script uses the existing pysnmp helper/API and Python 3.8 deployment convention, not a new dependency environment.

This check does not monitor AP/client interfaces, interface error/discard rates, historical peaks, HA peer health, packet delivery or NTP state. It does not suppress all standby usage or treat a zero traffic rate as a fault. Inventory success and standby health skips must not be interpreted as a guarantee of forwarding health.