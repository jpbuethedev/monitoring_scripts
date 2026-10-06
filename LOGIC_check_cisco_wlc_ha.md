# How the Cisco WLC HA check works

## In plain language

A Cisco 9800 wireless controller can work as part of a pair. One controller is **active** and handles the work; the other is **standby-hot** and is ready to take over. This check asks the controller whether it can see its partner and whether both controllers report the expected roles.

The check only reads status. It does not change controller settings, restart equipment, or trigger a switchover. It checks controller redundancy, not whether wireless access points or user traffic are working correctly.

## What happens during a check

1. **Connect to the controller.** The check uses SNMP, a standard way for monitoring software to ask network equipment for status. SNMPv3 is used by default; SNMPv2c can be selected instead.
2. **Read the pair's status.** The check asks for the local controller's role, the partner's reported role, whether the partner is detected, and the reason for the last switchover.
3. **Check the expected pairing.** An active controller should see a standby-hot partner. A standby-hot controller should see an active partner. Both should report that the partner is detected.
4. **Check peer reachability when possible.** When the queried controller is active, the check makes an additional peer-reachability request. When it is standby-hot, this extra request is skipped because that signal is intended to be read from the active controller.
5. **Print a monitoring result.** The output includes a status (`OK`, `WARNING`, `CRITICAL`, or `UNKNOWN`), a plain-language summary, and numeric values that monitoring software can record over time.

## Which status questions it asks

An OID is the numeric address SNMP uses to ask a device for one particular piece of information. You normally do not need to enter these numbers yourself; the list is here to show exactly what the check reads.

### Pair health

These four values are read on every run:

| OID name | Numeric OID | In everyday terms |
|---|---|---|
| `cRFStatusUnitState` | `1.3.6.1.4.1.9.9.176.1.1.2.0` | What role is this controller in: active, standby, or another state? |
| `cRFStatusPeerUnitState` | `1.3.6.1.4.1.9.9.176.1.1.4.0` | What role does this controller report for its partner? |
| `cRFStatusDuplexMode` | `1.3.6.1.4.1.9.9.176.1.1.6.0` | Can this controller detect its partner on the redundancy link? |
| `cRFStatusLastSwactReason` | `1.3.6.1.4.1.9.9.176.1.1.8.0` | Why did the last role change (shown for information only)? |

This additional value is read only when the controller being checked is active:

| OID name | Numeric OID | In everyday terms |
|---|---|---|
| `cLHaPeerHotStandbyEvent` | `1.3.6.1.4.1.9.9.843.1.3.4.0` | Is the active controller's standby partner reachable? |

### Optional access-point inventory

These four table columns are read only when `--ap-serial` is used. The check first tries the Cisco 9800 table. If its serial-number table has no rows, it tries the AIRESPACE table instead. The name and serial columns are matched by the same table row/index.

| MIB / source | OID name | Numeric OID | In everyday terms |
|---|---|---|---|
| Cisco 9800 AP table | `cLApName` | `1.3.6.1.4.1.9.9.513.1.1.1.1.5` | Name of an access point. |
| Cisco 9800 AP table | `cLApSerialNumber` | `1.3.6.1.4.1.9.9.513.1.1.1.1.17` | Serial number of an access point. |
| AIRESPACE fallback table | `bsnAPName` | `1.3.6.1.4.1.14179.2.2.1.1.3` | Access-point name if the Cisco 9800 table is unavailable or empty. |
| AIRESPACE fallback table | `bsnAPSerialNumber` | `1.3.6.1.4.1.14179.2.2.1.1.17` | Access-point serial number from the fallback table. |

## What counts as normal

| Controller being checked | Its role | Partner's role | Partner detected? | Extra peer check |
|---|---|---|---|---|
| Active controller | Active | Standby-hot | Yes | Must report reachable |
| Standby controller | Standby-hot | Active | Yes | Skipped |

The words `active` and `standbyHot` are the controller's labels for those roles. Other role labels usually mean the pair is starting, negotiating, disabled, or in another state that this check does not treat as a normal steady state.

## How to read the result

The table describes each condition on its own. The check can report more than one observation in the same output line.

| What the check finds | Normal mode | `--strict` | `--hard-strict` |
|---|---|---|---|
| Partner is reported down | CRITICAL | CRITICAL | CRITICAL |
| Partner is not detected | CRITICAL | CRITICAL | CRITICAL |
| Partner role is not the expected role | WARNING | CRITICAL | CRITICAL |
| Local role is neither active nor standby-hot | WARNING | CRITICAL | CRITICAL |
| An unrecognized partner-detection value is returned | UNKNOWN | CRITICAL | CRITICAL |
| Active controller cannot read the extra peer signal | UNKNOWN | CRITICAL | CRITICAL |
| Active controller returns an unexpected peer-signal value | UNKNOWN | UNKNOWN | CRITICAL |
| SNMP connection or main status read fails | UNKNOWN | UNKNOWN | UNKNOWN |
| Optional AP serial list cannot be read | Reported as unavailable; does not change HA status | Same | Same |

`--strict` raises role or partner-detection inconsistencies from WARNING/UNKNOWN to CRITICAL. `--hard-strict` includes strict behavior and also treats any unexpected value from the active controller's peer-reachability check as CRITICAL. Neither option can turn a failed SNMP connection or failed main status read into a confirmed healthy/unhealthy result, so those remain UNKNOWN.

The last switchover reason is included for context. It does not by itself change the result.

## Optional AP serial list

With `--ap-serial`, the check also tries to list access point names and serial numbers. It first asks using the Cisco 9800 AP table and falls back to a compatible wireless-controller table if needed. This is an inventory aid only: it does not check whether each access point is healthy. If the tables are unavailable or empty, the check says the serial list is unavailable; that alone does not make HA critical.

## Output example

```text
OK - Role=ACTIVE(active); HA Peer: reachable; RF: peer detected (duplex=true); RF PeerState: standbyHot; LastSwact: none | peer_up=1 duplex=1 unit_state=14 peer_state=9 last_swact_reason=2
```

Everything before `|` is the readable summary. Everything after it is performance data for monitoring and graphs:

- `peer_up`: `1` means reachable, `0` means down, `-1` means the active-side request failed, and `-2` means the request was skipped on standby.
- `duplex`: `1` means the partner was detected; `0` means it was not, or the returned value was unexpected.
- `unit_state` and `peer_state`: numeric role values reported by the controllers.
- `last_swact_reason`: numeric code for the last switchover reason.

## Connection settings

The target address is required. SNMPv3 is the default and uses `authPriv` with SHA authentication and AES privacy by default; the monitoring setup supplies the username and passwords. For SNMPv2c, the default community is `public`, which should be changed to the value configured for the device. The default timeout is 5 seconds and the default SNMP port is 161.

For the full option list and command examples, see the [monitoring scripts README](README.md#check_cisco_wlc_hapl).
