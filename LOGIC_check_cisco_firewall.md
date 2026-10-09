# How the Cisco firewall check works

## In plain language

This plugin reads status from a Cisco ASA, FTD, or Secure Firewall appliance over SNMP. It is read-only: it does not change failover roles, interface state, or device configuration. Each run selects one mode, so it reports a focused result rather than a single overall test of every firewall function.

The check requires a target hostname or IP and either an SNMPv2c community or SNMPv3 username. SNMPv3 uses `authPriv`, SHA authentication, and AES privacy by default; passwords may be supplied using `SNMP_AUTHPW` and `SNMP_PRIVPW` environment variables rather than command-line options.

## What happens during a check

1. The plugin validates the required target, mode, and SNMP credentials.
2. It reads only the SNMP values needed for the selected mode. Some modes treat optional detail as best-effort, while missing required values result in UNKNOWN or a mode-specific failure.
3. The mode converts the values into a Nagios status and prints a summary. Metric modes also publish performance data after `|`.
4. Unexpected errors and Ctrl+C are caught and returned as UNKNOWN rather than a Python traceback.

## HA modes

### `ha_summary`

Reads the primary and secondary HA state entries from one firewall. A normal pair has one Active unit (`9`) and one Standby Ready unit (`10`). Missing failover entries mean failover is not configured and return UNKNOWN. No active unit, duplicate active/standby roles, down/error states, Standby Cold (`11`), or Failed (`12`) return CRITICAL. Transitional or less-specific states such as `busy`, `backup`, and `other` return WARNING.

When possible, the plugin also labels which unit answered the SNMP request and whether that unit is currently active or standby. This identity note is informational and does not change the result.

### `ha_pair`

Queries the configured target and its peer independently, then compares the primary/secondary state values reported by both. Both units must be reachable, agree on the pair's state, and report failover-safe states: Active (`9`) and Standby Ready (`10`). Disagreement, unsafe states, or both devices identifying as the same configured role returns CRITICAL. A peer that cannot be reached is CRITICAL; a unit that does not expose failover state is UNKNOWN.

`--peer-hostname` can specify the peer directly. If omitted, the plugin tries addresses two places above and below the target's last IPv4 octet, based on the convention seen in this environment. A candidate is accepted only if it responds and reports matching pair state; guesses are never trusted without that live check. If no candidate can be confirmed, the result is WARNING. The optional role cross-check uses device-reported "this device" text to ensure the two addresses identify complementary primary/secondary units; if the platform omits that text, the cross-check is skipped and noted.

### `primary_state` and `secondary_state`

Report the fixed configured primary or secondary slot, not simply the role of the IP queried. The pair's MIB exposes the same primary/secondary entries from either unit, so the result is the same whichever paired address is queried. If it can identify the queried unit, the plugin notes whether the requested slot is local or the peer.

The numeric state is checked against the text role. A disagreement forces CRITICAL; missing or unrecognized role text is called out as an unavailable cross-check. Active (`9`) and Standby Ready (`10`) are failover-safe. Standby Cold (`11`), Failed (`12`), and unknown numeric states are CRITICAL. If both role and state data are absent, the result is UNKNOWN.

## Resource and identity modes

### `cpu`

Walks CPU history and calculates the average for the 5-second, 1-minute, and 5-minute windows. The 5-minute average alone determines status; the shorter windows are included for context. Defaults are WARNING at 80% and CRITICAL at 90%. Missing CPU data returns UNKNOWN.

### `memory`

Reads the system/data-plane memory pool. It tries the classic memory-pool table first, then falls back to the enhanced table if the classic table is empty. It prefers a pool named `dp system`, then `system memory`, then `processor`, and finally the first available pool. Usage is used bytes divided by used plus free bytes. Defaults are WARNING at 80% and CRITICAL at 90%; unavailable pool data returns UNKNOWN.

### `connections`

Checks the current in-use connection count. Optional `--warning` and `--critical` values are connection-count thresholds; there are no defaults, so without them the check reports OK while still publishing the count. Peak connections are retrieved for performance data and shown in the summary only with `--verbose`; inability to read the peak does not fail the check. Missing current-count data returns UNKNOWN.

### `uptime`

Reports time since reboot. Optional warning and critical thresholds are minimum uptime in seconds: a value below the critical threshold is CRITICAL, and below warning is WARNING. This intentionally flags a recent reboot rather than excessive uptime. Without thresholds, the mode reports OK and publishes uptime.

### `sysinfo`

Reports hostname and system description. Chassis model is best-effort: if the platform does not expose the chassis entity/model, that detail is omitted without changing the result. Successful required reads return OK.

## Hardware and interfaces

### `hardware`

Checks fan-tray and power-supply operational states. It summarizes the worst component status and prints a component table. Fan-tray `down` is WARNING because some production Secure Firewall 3100 devices report that state despite otherwise healthy hardware; the MIB-defined `unknown` state is also WARNING. A fan-tray `warning` state or an unrecognized numeric status is CRITICAL. A power supply is OK only when it reports `on`; every other reported state is CRITICAL.

Sensor voltage and RPM readings are best-effort display details and do not determine severity. Some logical FTD instances do not expose fan or power-supply rows; when no components are reported, the plugin returns OK because that can be expected for a secondary logical instance sharing a chassis.

### `interfaces`

Monitors interfaces discovered from SNMP, excluding internal pseudo-interfaces and container/bridge interfaces. An interface is DOWN only when it is administratively enabled but its operational state is not up. Other state combinations are reported as UP. Any monitored interface DOWN makes the overall result CRITICAL; no remaining interfaces returns UNKNOWN.

Link speed and error/discard counters are informational only and do not change interface status or the overall result. The table sorts DOWN interfaces first. `--html-table` renders the hardware/interface table as HTML for compatible monitoring frontends; plain delimited text is the default and is easier to inspect in a terminal.

## Nagios results

| Code | Status | Meaning |
|---|---|---|
| `0` | OK | Requested check is healthy or informational data was read successfully. |
| `1` | WARNING | A warning threshold or degraded state was reached. |
| `2` | CRITICAL | A critical threshold, unsafe HA state, failed component, or down interface was detected. |
| `3` | UNKNOWN | Required data is missing, the request lacks credentials, or the plugin cannot determine a result. |

These rules are mode-specific. For example, an SNMP-unreachable device is UNKNOWN in checks using the shared SNMP helper, but `ha_pair` explicitly reports an unreachable queried unit as CRITICAL. See the [firewall OID reference](OIDS_check_cisco_firewall.md) for exact OIDs, state maps, exclusions, and examples, and the [monitoring scripts README](README.md) for invocation examples.