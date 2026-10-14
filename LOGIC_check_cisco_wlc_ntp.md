# How the Cisco WLC NTP check works

## In plain language

This check asks a Cisco C9800 Wireless LAN Controller (WLC) over SNMP whether its own clock is synchronized to an NTP server, and how far off it is. It reads the standard NTPv4-MIB, which the C9800 populates, rather than the Cisco-specific CISCO-NTP-MIB, whose peer offset column is empty on this platform.

The check is read-only. It does not change the WLC configuration, and it does not contact the NTP servers itself. It reports what the WLC says about its own NTP state.

It answers three questions, in this order:

1. Is the WLC synchronized at all?
2. If so, how large is its clock offset from the server it is using?
3. How many of its configured NTP servers are actually usable?

## What happens during a check

1. **Validate the request.** The target is required, and so are SNMPv2c community credentials or an SNMPv3 username. SNMPv3 passwords can be passed as options or through the `SNMP_AUTHPW` and `SNMP_PRIVPW` environment variables. `--warning` must be non-negative and lower than `--critical`, and `--min-peers` must not be negative. Any violation is reported as UNKNOWN.
2. **Read the device's NTP status.** Four single values are required: the current mode, the stratum, the ID of the server currently in use, and the dispersion. If the device does not return them (for example because NTPv4-MIB is not populated), the result is UNKNOWN.
3. **Read the configured NTP servers.** The check walks the association table for each server's address and stratum. A server missing a stratum is skipped.
4. **Decide the status.** The rules are described below.
5. **Print the result.** One summary line with performance data after `|`, followed by one line per configured server.

## How the status is decided

### Step 1: Is the WLC synchronized?

The WLC reports a mode:

| Mode | Meaning | Result |
|---:|---|---|
| 1 | NTP not running | CRITICAL |
| 2 | Not synchronized | CRITICAL |
| 3 | No servers configured | CRITICAL |
| 4 | Synchronized to its own local clock only | CRITICAL |
| 5 | Synchronized to a reference clock | continue to step 2 |
| 6 | Synchronized to a remote server | continue to step 2 |
| 7 | Unknown | UNKNOWN |

Even in mode 5 or 6, a device stratum of 16 is treated as unsynchronized and is CRITICAL. When the WLC is not synchronized, the offset is not read, because a device that is not synchronized reports an offset of 0 that carries no information.

### Step 2: How large is the offset?

The WLC reports the offset between its clock and the server it is using, as text such as `-0.4433 ms`. The check compares the absolute value (the sign is ignored) with the thresholds:

| Absolute offset | Result |
|---|---|
| at or above `--critical` (default 500 ms) | CRITICAL |
| at or above `--warning` (default 100 ms) | WARNING |
| below `--warning` | OK |

Critical is checked before warning.

### Step 3: How many servers are usable?

A configured server is counted as usable when its stratum is below 16. A server at stratum 16 has not been reached, or the WLC does not trust it. A server that has never been contacted shows `.INIT.` as its reference ID.

| Usable servers | Result |
|---|---|
| none | CRITICAL |
| fewer than `--min-peers` (default 2) | at least WARNING |
| `--min-peers` or more | no effect |

The default of 2 means a single failed server out of several does not raise an alert, but losing redundancy does.

### The final result

The final status is the worst of the offset result (step 2) and the server-count result (step 3). If step 1 already returned CRITICAL, that is the final result and steps 2 and 3 do not change it, although the server lines are still printed to help find the cause.

## What stratum means

Stratum is a server's distance from a primary time source. The check applies it to the device itself and to each configured server.

| Stratum | Meaning | How the check treats it |
|---|---|---|
| 0 | Unspecified / invalid | Not special-cased: a server reporting 0 counts as usable |
| 1 | Primary server, directly attached to a reference clock (GPS, radio, atomic) | Usable server |
| 2-15 | Secondary server, one hop further from the reference clock for each step | Usable server |
| 16 | Unsynchronized / not reachable | Unusable server; on the device itself this is CRITICAL |

## Output and performance data

The first line is the status and summary, followed by `|` and the performance data. Each configured server follows on its own line. The server the WLC is currently using is marked `(selected)`, and an unusable server is marked `(unusable)`.

Synchronized WLC, one of four servers unreachable (real output from 172.23.36.12):

```text
OK - NTP synchronized to remote server 10.56.140.125 (stratum 2), offset -0.4433 ms, 3/4 peer(s) usable | offset_ms=0.4433ms;100;500;0; stratum=2;;;0;16 peers_usable=3;;;0;4 dispersion_ms=10.548ms;;;0;
  * NTP Peer - 10.56.139.121 stratum 16 (unusable)
  * NTP Peer - 10.56.139.122 stratum 2
  * NTP Peer - 10.56.140.124 stratum 1
  * NTP Peer - 10.56.140.125 stratum 1 (selected)
```

Unsynchronized WLC (real output from 172.23.36.13):

```text
CRITICAL - NTP not synchronized (stratum 16), 0/4 peer(s) usable | stratum=16;;;0;16 peers_usable=0;;;0;4 dispersion_ms=15660.464ms;;;0;
  * NTP Peer - 10.56.139.121 stratum 16 (unusable)
  * NTP Peer - 10.56.139.122 stratum 16 (unusable)
  * NTP Peer - 10.56.140.124 stratum 16 (unusable)
  * NTP Peer - 10.56.140.125 stratum 16 (unusable)
```

| Performance data | Meaning |
|---|---|
| `offset_ms` | Absolute clock offset in milliseconds, with the warning and critical thresholds. Only present when the WLC is synchronized. |
| `stratum` | The WLC's own stratum, from 0 to 16. |
| `peers_usable` | Number of usable servers, out of the number configured. |
| `dispersion_ms` | The WLC's estimate of the maximum error of its clock. About 16000 ms is the "never synchronized" value. |

## Result codes

| Result | Meaning |
|---|---|
| `0` OK | Synchronized, offset below warning, and enough usable servers. |
| `1` WARNING | Offset at or above warning, or fewer usable servers than `--min-peers`. |
| `2` CRITICAL | Not synchronized, stratum 16, offset at or above critical, or no usable server. SNMP errors other than a timeout, such as invalid SNMPv3 credentials, are also reported as CRITICAL. |
| `3` UNKNOWN | Request validation failed, the device did not answer within the timeout, NTPv4-MIB is not populated, the mode is unknown, or an unexpected error occurred. |

## What this check does not do

- It does not check the NTP servers directly. It relies on the stratum values the WLC reports for them.
- It does not use CISCO-NTP-MIB. The peer offset column is empty on the C9800, so the `check_ves_ntp_timesync.py` script from `wpp-service-checks-python` cannot be used for it.
- It has not been tested on platforms other than the C9800-CL (IOS-XE 17.15.6). Firepower/FTD devices do not expose NTP state over SNMP at all.

For usage, parameters and examples, see the [README](README.md#check_cisco_wlc_ntppy).
