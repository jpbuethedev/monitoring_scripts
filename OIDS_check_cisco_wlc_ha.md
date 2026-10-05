# check_cisco_wlc_ha.pl: OIDs and state meanings

This plugin monitors Cisco 9800 wireless LAN controller high availability (SSO) using numeric scalar OIDs from CISCO-RF-MIB and CISCO-LWAPP-HA-MIB. It sends SNMP GET requests; it does not walk a table. MIB files are not required on the monitoring host.

## CISCO-RF-MIB

These four scalar instances are queried on every run.

| Object | Numeric OID | Use in the plugin |
|---|---|---|
| `cRFStatusUnitState` | `1.3.6.1.4.1.9.9.176.1.1.2.0` | State/role of the controller being queried. |
| `cRFStatusPeerUnitState` | `1.3.6.1.4.1.9.9.176.1.1.4.0` | State/role reported for the peer controller. |
| `cRFStatusDuplexMode` | `1.3.6.1.4.1.9.9.176.1.1.6.0` | Whether the redundancy peer is detected. |
| `cRFStatusLastSwactReason` | `1.3.6.1.4.1.9.9.176.1.1.8.0` | Last switchover reason; informational only. |

### RF state values recognized by the script

`cRFStatusUnitState` and `cRFStatusPeerUnitState` are decoded using this subset. Other values are printed as `state_<number>` and evaluated as unexpected/transitional.

| Value | Label | Plugin handling |
|---:|---|---|
| `1` | `notKnown` | Not a recognized active/standby role. |
| `2` | `disabled` | Not a recognized active/standby role. |
| `3` | `initialization` | Transitional/abnormal local role, or unexpected peer role. |
| `4` | `negotiation` | Transitional/abnormal local role, or unexpected peer role. |
| `5` | `standbyCold` | Not the expected hot-standby peer role. |
| `9` | `standbyHot` | Expected peer role when local unit is active; the local standby role. |
| `14` | `active` | Expected peer role when local unit is standby-hot; the local active role. |
| `17` | `standbyWarm` | Not the expected hot-standby peer role. |

The plugin does not classify unknown numeric RF states using a complete MIB enum table. It preserves the numeric value in output and treats it as unexpected.

### Duplex values

| Value | Script interpretation | Result effect |
|---:|---|---|
| `1` | Peer detected (`duplex=true`) | Expected state. |
| `2` | Peer not detected (`duplex=false`) | CRITICAL in all modes. |
| Other | Unexpected duplex value | UNKNOWN by default; CRITICAL with `--strict` or `--hard-strict`. |

The `duplex` performance-data value is normalized to `1` only for raw value `1`; all other raw values produce `0`. The human-readable output retains the raw value when it is unexpected.

### Last switchover reason values recognized by the script

This value is informational and never changes the Nagios status by itself. Unmapped values are printed as `reason_<number>`.

| Value | Label |
|---:|---|
| `1` | `unsupported` |
| `2` | `none` |
| `3` | `notKnown` |
| `4` | `userInitiated` |
| `5` | `userForced` |
| `6` | `activeUnitFailed` |
| `7` | `activeUnitRemoved` |
| `8` | `activeGWdown` |
| `9` | `activeRMIportdown` |

## CISCO-LWAPP-HA-MIB

| Object | Numeric OID | Use in the plugin |
|---|---|---|
| `cLHaPeerHotStandbyEvent` | `1.3.6.1.4.1.9.9.843.1.3.4.0` | Read only when `cRFStatusUnitState` reports `active` (`14`). The script interprets `1` as reachable and `0` as down. |

| Value | Script interpretation | Result effect |
|---:|---|---|
| `1` | HA peer reachable | Expected. |
| `0` | HA peer down | CRITICAL in all modes. |
| `-1` | HA peer GET failed | UNKNOWN normally; CRITICAL with `--strict` or `--hard-strict`. |
| Other | Unexpected HA peer value | UNKNOWN normally and with `--strict`; CRITICAL with `--hard-strict`. |

On a standby-hot controller this OID is deliberately not queried. Its `peer_up` performance value is `-2` to indicate “not evaluated”; `-1` means the active-side GET failed. Poll the active controller if this HA peer reachability signal is required.

## Role-dependent checks

| Local RF state | Expected peer RF state | Additional checks |
|---|---|---|
| `active` (`14`) | `standbyHot` (`9`) | HA peer event must be `1`; duplex should be `1`. |
| `standbyHot` (`9`) | `active` (`14`) | HA peer event is skipped; duplex should be `1`. |
| Any other value | No stable role expectation | WARNING by default; CRITICAL with `--strict` or `--hard-strict`. |

An unexpected peer state contributes WARNING by default and CRITICAL in strict modes. An unexpected duplex value contributes UNKNOWN by default and CRITICAL in strict modes. The highest resulting severity is returned. RF GET/session failures return UNKNOWN before these checks run.

## Performance data

| Label | Value |
|---|---|
| `peer_up` | Raw HA peer event on active; `-1` for failed GET; `-2` when skipped on standby. |
| `duplex` | `1` if the raw value is `1`, otherwise `0`. |
| `unit_state` | Raw local RF state value. |
| `peer_state` | Raw peer RF state value. |
| `last_swact_reason` | Raw last switchover reason value. |

All values are emitted as Nagios performance data for collection/graphing; no thresholds are applied to these metrics.

## Optional AP inventory (`--ap-serial`)

When `--ap-serial` is enabled, the plugin walks the serial-number column and joins each row to the AP-name column using the shared table index. It tries CISCO-LWAPP-AP-MIB first and falls back to AIRESPACE-WIRELESS-MIB if the Cisco LWAPP serial table is empty.

| MIB | Object | Numeric OID | Use |
|---|---|---|---|
| CISCO-LWAPP-AP-MIB | `cLApName` | `1.3.6.1.4.1.9.9.513.1.1.1.1.5` | AP name table column. |
| CISCO-LWAPP-AP-MIB | `cLApSerialNumber` | `1.3.6.1.4.1.9.9.513.1.1.1.1.17` | AP serial-number table column; primary source. |
| AIRESPACE-WIRELESS-MIB | `bsnAPName` | `1.3.6.1.4.1.14179.2.2.1.1.3` | AP name column used with the fallback table. |
| AIRESPACE-WIRELESS-MIB | `bsnAPSerialNumber` | `1.3.6.1.4.1.14179.2.2.1.1.17` | AP serial-number column used when the primary table has no rows. |

AP inventory is appended to the status text as `AP_Serials: name=serial, ...`. If neither serial table returns rows, the plugin reports that AP serials are unavailable; this optional inventory result does not independently change the HA status.