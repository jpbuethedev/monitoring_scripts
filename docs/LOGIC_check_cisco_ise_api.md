# Cisco ISE API Checks

Python 3.8+ using only the standard library. API requests are read-only GETs
except `ldap-bind`, which explicitly runs an active LDAP bind diagnostic via
a dedicated PUT endpoint without changing identity-source configuration.
Available modes: `deployment` (default), `certificates`, `backup`, `licenses`,
`pan-ha`, `version`, `tasks`, `ldap-bind`.

## Usage

```text
check_cisco_ise_api.py -H HOST -u USER -p PASSWORD --mode deployment
check_cisco_ise_api.py --hostname HOST --username USER --password PASSWORD --mode deployment
```

`-H/--hostname` accepts the API server's DNS name or IP address, not a full URL.
The plugin selects the API path for the requested mode. `-p` is the password;
uppercase `-P` remains the HTTPS port.

| Mode | Endpoint | Default warning / critical |
|---|---|---|
| deployment | `/api/v1/deployment/node` | Node status, no numeric thresholds |
| certificates | `/api/v1/certs/system-certificate/{hostName}` | 30 / 10 days remaining |
| backup | `/api/v1/backup-restore/config/last-backup-status` | 48 / 72 hours since job start |
| licenses | `/api/v1/license/system/tier-state`, optionally `/api/v1/license/system/eval-license` | 30 / 10 evaluation days remaining |
| pan-ha | `/api/v1/deployment/pan-ha` | Expected configuration, enabled by default |
| version | `/api/v1/patch` | Informational unless exact expectations are supplied |
| tasks | `/api/v1/task` or `/api/v1/task/{taskId}` | 30 / 60 minutes for unfinished non-failed resources |
| ldap-bind | PUT `/ers/config/ldap/{id}/testbindprimary` or `testbindsecondary` | Explicit bind result, no numeric thresholds |

`-w/--warning` and `-c/--critical` override either default independently.
Thresholds must be finite. Expiry thresholds require `0 <= critical < warning`;
backup/task age thresholds require `0 <= warning < critical`. Boundaries are inclusive.
Thresholds are rejected for deployment, pan-ha, version, and ldap-bind. `--expected-nodes`
applies only to deployment; `--node` applies only to certificates; `--expect-ha`
applies only to pan-ha; `--expect-version` and `--expect-patch` apply only to
version; `--task-id` applies only to tasks. `--ldap-id`, `--ldap-name`, and
`--ldap-server` apply only to ldap-bind.

## Deployment

| API nodeStatus | Plugin status |
|---|---|
| Connected | OK (0) |
| InProgress | WARNING (1) |
| Disconnected, NotInSync, NotUpgraded, RegistrationFailed, ReplicationStopped | CRITICAL (2) |
| NotApplicable, unknown or missing status | UNKNOWN (3) |

The worst recognized node status determines the result. Invalid data anywhere
returns UNKNOWN, including empty responses and duplicate/missing hostnames.
`--expected-nodes N` returns CRITICAL when a valid response has a different
node count. Without this option, there is no assumption about deployment size.
Perfdata: `nodes_total`, `nodes_connected`, `nodes_problem` (all counts).

This checks deployment connectivity and synchronization, not RADIUS/TACACS+
authentication, actual persona readiness, or configured service availability.
It does not change ISE configuration or repair synchronization problems.

## Certificates

By default, the plugin discovers all node hostnames from the deployment API and
checks each node's system certificates through the selected API server. This
does not require SSH to the nodes. Repeat `--node HOSTNAME` to select exact ISE
node hostnames instead. `-H` remains the API endpoint, not the certificate node
selector. Both `172.23.38.11` and `172.23.38.12` can be used as API endpoints,
subject to API access and permissions on each server.

Every returned system certificate is included, including self-signed and unused
certificates. Trusted CA-store certificates are not included. Certificate
validity uses `validFrom` and `expirationDate`: not-yet-valid certificates are
CRITICAL; remaining validity at or below 10 days is CRITICAL and at or below
30 days is WARNING by default. The summary gives the problem count and worst
certificate. Perfdata: `certificates_total`, `certificates_problem`,
`certificate_days_remaining` (minimum remaining days, possibly negative).

Pagination uses `nextPage` as a continuation signal but constructs subsequent
requests locally rather than following URLs with credentials. Empty node data,
missing pagination metadata, missing or repeated certificate IDs, invalid dates,
or exceeding 100 pages per node returns UNKNOWN. A failure reading any selected
node returns UNKNOWN; successful nodes are not treated as complete coverage.

## Backup

Checks the last configuration-backup operation reported by ISE. `COMPLETED`
is OK until its start age reaches the configured warning or critical threshold.
`IN_PROGRESS` is WARNING, escalating to CRITICAL at the critical start age.
`ERROR`, cancellation, or a reported error is CRITICAL regardless of age.
Restore operations and explicitly operational-database backups return UNKNOWN
rather than being mistaken for a successful configuration backup.

Age uses `startDate`, not completion time or the last successful historical
backup. A running or failed latest job does not prove that an earlier successful
backup exists. This mode does not inspect repository contents or test restore
integrity. Missing, invalid, timezone-less, or future start dates return UNKNOWN
when age is needed. It never schedules or triggers a backup.
Perfdata: `backup_age_hours` when available and `backup_failed`.

## Licenses

Checks enabled tiers only. `COMPLIANT`, `FULL_COMPLIANCE`, and
`RESERVED_IN_COMPLIANCE` are OK. `NONCOMPLIANT`, `EVALUATION_EXPIRED`, and
`RELEASED_ENTITLEMENT` are CRITICAL. For `EVALUATION`, the plugin also queries
`daysRemaining`: at or below the critical threshold is CRITICAL; at or below
the warning threshold is WARNING. Otherwise that evaluation tier is OK.
Disabled tiers do not cause compliance or expiry alerts.

Unknown states, missing required data, duplicate tier names, no enabled tiers,
and missing/invalid evaluation days return UNKNOWN. Perfdata:
`license_tiers_enabled`, `license_tiers_problem`, and `evaluation_days_remaining`
only when an enabled tier is in evaluation. Days are encoded in metric names,
not an unsupported Nagios unit suffix.

This mode does not claim to verify purchased subscription-expiry dates,
entitlement capacity, registration connectivity, or future authorization renewal.
Those require additional API evidence beyond the fields used here.

## PAN-HA

Checks `response.isEnabled` against `--expect-ha enabled|disabled` (default:
enabled). A match returns OK; a mismatch is CRITICAL. A missing or non-boolean
value returns UNKNOWN. Perfdata: `pan_ha_enabled` (0 or 1).

This verifies the automatic PAN failover configuration only. It does not
measure PAN/peer reachability, replication health, health-check node readiness,
or actual failover capability. Disabling automatic failover may be intentional;
set `--expect-ha disabled` for such a deployment rather than treating the
default CRITICAL result as proof of a fault. No configuration is changed.

## Version

Reports the API endpoint's ISE application release from `iseVersion`, not the
API envelope's `version` field. The `patchVersion` array contains installed
patch numbers; an empty array is valid and means no patches (latest patch 0).
Hot patches are not included.

By default this is informational and returns OK for a valid inventory.
`--expect-version RELEASE` performs an exact string comparison and
`--expect-patch NUMBER` compares the highest installed patch number, not a
minimum requirement. Either mismatch is CRITICAL. These expectations can be
used together. Missing release/patch data or malformed/duplicate patch numbers
returns UNKNOWN. Perfdata: `ise_patch`, `ise_patches_installed`.

This is the selected endpoint's inventory, not an automatic cluster-wide
comparison. Run against .11 and .12 separately to compare nodes. It does not
check Cisco's current recommended release or decide if security fixes are missing.

## Tasks

By default, checks the task array returned by `/api/v1/task`, documented as the
last 24 hours. An empty array is valid and returns OK with zero counts. Repeat
`--task-id ID` to query exact task IDs instead; every response must match its
requested ID. A missing/expired ID or API failure returns UNKNOWN.

The API schema leaves `executionStatus` as a free-form string with no enum.
The plugin displays status text for problematic tasks but does not guess its
meaning or use it to change severity. Alerts are based on resource counters:

- A positive `failCount` is CRITICAL regardless of age.
- `successCount + failCount < resourcesCount` identifies unfinished resources.
- Non-failed unfinished tasks at or above 30 minutes from `startTime` are
  WARNING; at or above 60 minutes they are CRITICAL. Younger unfinished tasks
  are OK, meaning no resource failure or overdue work, not successful completion.
- All resources accounted for with no failures is OK. Missing, negative,
  non-integer or inconsistent counts, duplicate IDs, missing status text, or
  zero-resource tasks return UNKNOWN rather than assuming completion.

Age requires a timezone-aware ISO timestamp or a supported ISE UTC date, using
the same parser as backup/certificates. Unparseable or future start times return
UNKNOWN when age is needed. A task already known to have failed resources does
not need a timestamp to alert. No task is created, cancelled, or retried.

Perfdata: `tasks_total`, `tasks_failed` (tasks with failed resources),
`tasks_pending`, and `task_pending_minutes` (oldest non-failed unfinished task)
when applicable. `-w/-c` are minutes in this mode. This check is not a full
task-state interpreter: a failure present only in free-form text, without a
positive failure counter, is not interpreted as CRITICAL. It cannot prove that
expected tasks ran, and failures disappear from the default check when they
leave the API's 24-hour window. Nonempty-task and age behavior is unit-tested
but has not been live-verified because both devices returned empty task lists.

## LDAP Bind

This mode actively asks ISE to bind to a configured LDAP server. It is not a
passive status read. Use exactly one selector: `--ldap-id UUID` or
`--ldap-name EXACT_NAME`. There is no default that tests all identity sources.
Name lookup reads only the LDAP inventory (`SearchResult` resource names/IDs),
using safe locally constructed pagination, and requires one exact match. The
plugin does not fetch or print stored LDAP credentials.

`--ldap-server primary|secondary|both` selects the configured server; default
is primary. Both tests run sequentially, primary first, and both must succeed
for OK. The mode stops at the first explicit bind failure, malformed result,
or API/transport error, without retrying or attempting later servers. If primary
fails in `both` mode, secondary is not tested and its metrics are omitted. Use
separate primary/secondary services when independent results are needed.

Dedicated requests are bodyless PUTs. The shared transport rejects all other
non-GET paths and methods, including LDAP configuration updates. API credentials
are supplied as usual; ISE uses the bind configuration already stored in the
selected identity source. The API account needs permission to execute this
ERS diagnostic; read-only inventory permission alone may not suffice.

The verified response is `OperationResult.resultValue` with exactly one
`name=message` entry. Recognized messages are intentionally narrow:

- `Ldap bind succeeded to ...` is OK.
- `Ldap bind failed...` with a word/punctuation boundary is CRITICAL.
- Missing, extra, ambiguous, or unrecognized result messages return UNKNOWN.
  HTTP 200 without a recognized result is not proof of success. HTTP/API/TLS
  errors and request timeouts also return UNKNOWN.

Failure text variants and secondary behavior have synthetic unit tests, not
live failure verification. They must be checked against real failure responses
before claiming coverage of every failure format. An unrecognized failure
returns UNKNOWN rather than false OK. Raw result messages are not printed.

Perfdata: `ldap_bind_checks_total`, `ldap_bind_checks_failed`, and
`ldap_primary_bind` / `ldap_secondary_bind` (1=success, 0=explicit failure) for
tested servers. A recognized `Response time Nms` suffix adds
`ldap_primary_response_ms` / `ldap_secondary_response_ms`; this is the time
reported by ISE, not the HTTP round-trip time. Missing latency is informational,
and `-w/-c` are not applicable to this mode.

This tests the configured LDAP bind through ISE, not end-user authentication,
group-based authorization, AD join health, or complete directory availability.
The API response does not identify the execution node, so successful requests
through .11 and .12 do not establish reachability from every PSN.

Use conservative intervals and monitoring retries. Repeated failed binds can
produce directory logs, load, or service-account lockouts. A request timing out
does not prove ISE cancelled the underlying test; the plugin never retries it.
TLS settings control the monitoring-host-to-ISE connection; the LDAP connection's
TLS/bind behavior follows the identity source's configuration in ISE.

## Credentials and TLS

Use an ISE API account authorized for the requested resource or diagnostic. Provide its
username with `-u/--username` or `ISE_API_USERNAME`. Provide its password through
`-p/--password` (overrides `ISE_API_PASSWORD`), through `ISE_API_PASSWORD`, or use
`--ask-password` for interactive diagnostics only. `--password` and
`--ask-password` cannot be combined. Command-line passwords may be visible in
process listings and shell history; prefer environment variables or an
interactive prompt when practical. Protect environment variables and monitoring
configuration containing credentials.

TLS certificate and hostname verification are enabled by default. `--ca-file`
selects a trusted PEM CA bundle; use a DNS hostname matching the certificate.
`--insecure` explicitly disables verification and is noted in successful output.
It is a diagnostic workaround, not a replacement for renewing expired certificates.
HTTP redirects are blocked and environment proxies are not used.

`-P/--port` defaults to 443. `-t/--timeout` defaults to 10 seconds per socket
operation, not an overall check deadline. Configure the monitoring runner's
overall timeout separately. API errors, TLS failures, timeouts, invalid JSON,
and responses larger than 2 MiB return UNKNOWN without printing credentials.

Interactive diagnostic example from the repository root:

```bash
python3 scripts/check_cisco_ise_api.py -H 172.23.38.11 -u ise_api \
  --ask-password --expected-nodes 2 --insecure
python3 scripts/check_cisco_ise_api.py -H 172.23.38.11 -u ise_api \
  --ask-password --mode certificates -w 30 -c 10 --insecure
python3 scripts/check_cisco_ise_api.py -H 172.23.38.12 -u ise_api \
  --ask-password --mode certificates --node SP-99941-ISE02 --insecure
python3 scripts/check_cisco_ise_api.py -H 172.23.38.11 -u ise_api \
  --ask-password --mode backup -w 48 -c 72 --insecure
python3 scripts/check_cisco_ise_api.py -H 172.23.38.11 -u ise_api \
  --ask-password --mode licenses -w 30 -c 10 --insecure
python3 scripts/check_cisco_ise_api.py -H 172.23.38.11 -u ise_api \
  --ask-password --mode pan-ha --expect-ha disabled --insecure
python3 scripts/check_cisco_ise_api.py -H 172.23.38.11 -u ise_api \
  --ask-password --mode version --expect-version 3.4.0.608 --expect-patch 0 --insecure
python3 scripts/check_cisco_ise_api.py -H 172.23.38.12 -u ise_api \
  --ask-password --mode tasks -w 30 -c 60 --insecure
python3 scripts/check_cisco_ise_api.py -H 172.23.38.11 -u ise_api \
  --ask-password --mode tasks --task-id TASK_ID --insecure
python3 scripts/check_cisco_ise_api.py -H 172.23.38.11 -u ise_api \
  --ask-password --mode ldap-bind --ldap-name NAGIOS_PROD_LDAP --insecure
python3 scripts/check_cisco_ise_api.py -H 172.23.38.12 -u ise_api \
  --ask-password --mode ldap-bind --ldap-id 8346cf20-75f1-11f1-ab0d-c666efb4ca7f \
  --ldap-server secondary --insecure
```

For unattended checks, supply `ISE_API_PASSWORD` securely and omit
`--ask-password`; omit `--insecure` once the server certificate is repaired.
No arguments prints help and exits 3; `--help` exits 0.

## Verified Endpoint

On 2026-11-10, authenticated Swagger discovery and the deployment GET on
172.23.38.11 returned HTTP 200 through the monitoring SSH host. The live
response reported SP-99941-ISE01 as Connected and SP-99941-ISE02 as NotInSync.
The endpoint's TLS certificate was expired. This response is covered by a
regression test; it must yield CRITICAL, not a healthy-cluster result.
The new plugin was also executed in memory on the SSH host under production
Python 3.8 and returned CRITICAL with one connected node and one NotInSync node.
No plugin file or credentials were saved on that host.

During discovery on .11, the system-certificate response included expired
certificates, backup status was COMPLETED with a UTC startDate that day, and
enabled ESSENTIAL/ADVANTAGE tiers were in EVALUATION with 6 days remaining.
These fields and enum mappings were checked against this server's Swagger
specifications. Regression tests cover the observed response shapes and dates.

Subsequent in-memory plugin tests against both .11 and .12 reached HTTPS but
returned HTTP 401 with the supplied credentials. The new modes are therefore
unit-tested but certificates, backup and licenses have not yet been successfully
live-verified as plugin modes. Authentication retries were
stopped to avoid account lockout. TLS verification was explicitly bypassed for
these diagnostic requests; .12's certificate validity was not separately checked.

Later on 2026-11-10, authentication succeeded and the new pan-ha/version/tasks
modes were executed in memory under production Python 3.8 against both .11
and .12. Each returned:

| Mode | Live result on both endpoints | Exit |
|---|---|---|
| pan-ha | Automatic failover disabled, expected enabled by default | CRITICAL (2) |
| version | ISE 3.4.0.608, no installed patches | OK (0) |
| tasks | Empty last-24-hour task list | OK (0) |

PAN-HA/Patch/Task Service response shapes were checked against this server's
Swagger definitions. TLS verification was explicitly bypassed for these
diagnostic runs. This does not confirm the .12 certificate is valid or invalid.
No remote plugin file or password was persisted.

On 2026-11-10, the ERS LDAP inventory on .11 returned NAGIOS_PROD_LDAP
(8346cf20-75f1-11f1-ab0d-c666efb4ca7f) and NAGIOS_PROD_LDAP_1. A single
direct primary bind-test PUT for NAGIOS_PROD_LDAP returned HTTP 200 and
`Ldap bind succeeded to 193.47.71.154:636`, with 93 ms reported latency.
The completed plugin was then run in memory under Python 3.8, selecting that
source by name and testing primary through both API endpoints:

| Endpoint | Live ldap-bind result | ISE-reported latency | Exit |
|---|---|---|---|
| 172.23.38.11 | primary succeeded | 111 ms | OK (0) |
| 172.23.38.12 | primary succeeded | 82 ms | OK (0) |

Diagnostic TLS verification was explicitly disabled. No LDAP configuration
was changed. Secondary tests and negative bind cases were not run live to
avoid unnecessary authentication attempts; those branches have unit tests.

Run focused tests from the repository root:

```bash
python3 -B -m unittest discover -s tests -p test_check_cisco_ise_api.py -v
```