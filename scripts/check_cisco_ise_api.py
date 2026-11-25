#!/opt/rh/rh-python38/root/usr/bin/python3
"""Nagios/Icinga Cisco ISE API checks, including explicit active LDAP bind tests."""

import argparse
import base64
import getpass
import ipaddress
import json
import math
import os
import re
import ssl
import sys
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener
from uuid import UUID

NAGIOS_STATUS = ("OK", "WARNING", "CRITICAL", "UNKNOWN")
NODE_STATUS = {
    "Connected": 0,
    "InProgress": 1,
    "Disconnected": 2,
    "NotInSync": 2,
    "NotUpgraded": 2,
    "RegistrationFailed": 2,
    "ReplicationStopped": 2,
}
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class CheckError(Exception):
    pass


class CheckParser(argparse.ArgumentParser):
    def error(self, message):
        raise CheckError(message)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def text(value):
    return " ".join(str(value).replace("|", "/").split())


def fetch_json(args, password, path, method="GET"):
    if method != "GET" and not (method == "PUT" and re.fullmatch(
            r"/ers/config/ldap/[0-9a-fA-F-]{36}/testbind(primary|secondary)", path)):
        raise CheckError("Only GET and dedicated LDAP bind-test PUT requests are allowed")
    try:
        ipaddress.ip_address(args.hostname)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", args.hostname):
            raise CheckError("Hostname must be a DNS name or IP address, not a URL")
    host = "[{}]".format(args.hostname) if ":" in args.hostname else args.hostname
    url = "https://{}:{}{}".format(host, args.port, path)
    context = ssl.create_default_context(cafile=args.ca_file)
    if args.insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    credentials = base64.b64encode(
        (args.username + ":" + password).encode("utf-8")).decode("ascii")
    headers = {
        "Accept": "application/json", "Authorization": "Basic " + credentials,
    }
    if method == "PUT":
        headers["Content-Type"] = "application/json"
    request = Request(url, headers=headers, method=method)
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirect())
    try:
        with opener.open(request, timeout=args.timeout) as response:
            if response.status != 200:
                raise CheckError("ISE API returned HTTP {}".format(response.status))
            payload = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as error:
        raise CheckError("ISE API returned HTTP {}{}".format(
            error.code, " (check credentials and API permissions)" if error.code in (401, 403) else ""))
    except (URLError, OSError, ValueError):
        raise CheckError("ISE API connection failed (check connectivity, timeout and TLS certificate)")
    if len(payload) > MAX_RESPONSE_BYTES:
        raise CheckError("ISE API response exceeds 2 MiB")
    try:
        return json.loads(payload)
    except (ValueError, UnicodeError):
        raise CheckError("ISE API returned invalid JSON")


def fetch_deployment(args, password):
    return fetch_json(args, password, "/api/v1/deployment/node")


def api_date(value, label):
    if not isinstance(value, str) or not value.strip():
        raise CheckError("Missing " + label)
    try:
        if re.match(r"^\d{4}-\d{2}-\d{2}T", value):
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            result = parsedate_to_datetime(value)
    except (ValueError, TypeError, OverflowError):
        raise CheckError("Invalid " + label)
    if result.tzinfo is None or result.utcoffset() is None:
        raise CheckError("Missing timezone in " + label)
    return result.astimezone(timezone.utc)


def response_object(payload, label):
    result = payload.get("response") if isinstance(payload, dict) else None
    if not isinstance(result, dict) or not result:
        raise CheckError("Missing or invalid " + label)
    return result


def mode_thresholds(args):
    if args.mode in ("deployment", "pan-ha", "version", "ldap-bind"):
        if args.warning is not None or args.critical is not None:
            raise CheckError("Thresholds are not applicable to " + args.mode)
        return None, None
    if args.mode == "backup":
        warning = 48.0 if args.warning is None else args.warning
        critical = 72.0 if args.critical is None else args.critical
        if not (math.isfinite(warning) and math.isfinite(critical) and 0 <= warning < critical):
            raise CheckError("Backup age thresholds must satisfy 0 <= warning < critical (hours)")
        return warning, critical
    if args.mode == "tasks":
        warning = 30.0 if args.warning is None else args.warning
        critical = 60.0 if args.critical is None else args.critical
        if not (math.isfinite(warning) and math.isfinite(critical) and 0 <= warning < critical):
            raise CheckError("Task age thresholds must satisfy 0 <= warning < critical (minutes)")
        return warning, critical
    warning = 30.0 if args.warning is None else args.warning
    critical = 10.0 if args.critical is None else args.critical
    if not (math.isfinite(warning) and math.isfinite(critical) and 0 <= critical < warning):
        raise CheckError("Expiry thresholds must satisfy 0 <= critical < warning (days)")
    return warning, critical


def fetch_certificates(args, password):
    if args.node:
        names = args.node
    else:
        payload = fetch_deployment(args, password)
        nodes = payload.get("response") if isinstance(payload, dict) else None
        if not isinstance(nodes, list) or not nodes or any(not isinstance(node, dict) for node in nodes):
            raise CheckError("Invalid deployment inventory for certificate discovery")
        names = [node.get("hostname") for node in nodes]
    if any(not isinstance(name, str) or not name.strip() for name in names):
        raise CheckError("Missing certificate node hostname")
    if len({name.casefold() for name in names}) != len(names):
        raise CheckError("Duplicate certificate node hostname")
    certificates = []
    for name in names:
        seen = set()
        for page in range(1, 101):
            path = "/api/v1/certs/system-certificate/{}?page={}&size=100".format(quote(name, safe=""), page)
            payload = fetch_json(args, password, path)
            rows = payload.get("response") if isinstance(payload, dict) else None
            if not isinstance(rows, list) or not rows or "nextPage" not in payload:
                raise CheckError("Missing certificates or pagination metadata for " + text(name))
            for certificate in rows:
                identifier = certificate.get("id") if isinstance(certificate, dict) else None
                if not isinstance(identifier, str) or not identifier or identifier in seen:
                    raise CheckError("Invalid or repeated certificate ID for " + text(name))
                seen.add(identifier)
                certificates.append((name, certificate))
            if payload["nextPage"] is None:
                break
        else:
            raise CheckError("Certificate pagination exceeded 100 pages for " + text(name))
    return certificates


def check_certificates(certificates, warning, critical, now=None):
    now = datetime.now(timezone.utc) if now is None else now
    if not certificates:
        raise CheckError("No system certificates returned")
    results = []
    for node, certificate in certificates:
        expiry = api_date(certificate.get("expirationDate"), "certificate expirationDate")
        starts = api_date(certificate.get("validFrom"), "certificate validFrom")
        if expiry < starts:
            raise CheckError("Certificate expiration precedes validity start")
        days = (expiry - now).total_seconds() / 86400
        code = 2 if days <= critical or starts > now else 1 if days <= warning else 0
        label = "{}/{}".format(text(node), text(certificate.get("friendlyName") or certificate["id"]))
        results.append((code, days, label))
    worst = min(results, key=lambda item: (-item[0], item[1]))
    minimum = min(item[1] for item in results)
    problems = sum(item[0] != 0 for item in results)
    summary = "Certificates: {} checked, {} problems; {} remaining {:.1f} days".format(
        len(results), problems, worst[2], worst[1])
    if worst[0] == 2 and worst[1] > critical:
        summary += " (not yet valid)"
    metrics = "'certificates_total'={} 'certificates_problem'={} 'certificate_days_remaining'={:.3f};@~:{:g};@~:{:g};;".format(
        len(results), problems, minimum, warning, critical)
    return max(item[0] for item in results), summary, metrics


def check_backup(payload, warning, critical, now=None):
    backup = response_object(payload, "last backup status")
    status, action = backup.get("status"), backup.get("action")
    if status not in ("COMPLETED", "ERROR", "IN_PROGRESS"):
        raise CheckError("Missing or unsupported backup status")
    if action not in ("BACKUP", "CANCEL"):
        raise CheckError("Last operation is not a backup or backup cancellation")
    if backup.get("type") not in (None, "CONFIGURATION_DB"):
        raise CheckError("Last backup is not a configuration backup")
    error = backup.get("error")
    if error is not None and not isinstance(error, (str, bool)):
        raise CheckError("Invalid backup error field")
    failed = status == "ERROR" or action == "CANCEL" or error not in (None, False, "", "false")
    if failed:
        summary = "Backup: failed or cancelled; {}".format(text(backup.get("message") or status))
        return 2, summary, "'backup_failed'=1"
    now = datetime.now(timezone.utc) if now is None else now
    started = api_date(backup.get("startDate"), "backup startDate")
    age = (now - started).total_seconds() / 3600
    if age < 0:
        raise CheckError("Backup startDate is in the future")
    code = 2 if age >= critical else 1 if age >= warning or status == "IN_PROGRESS" else 0
    summary = "Backup: {}; started {:.1f} hours ago; name={}; repository={}".format(
        status, age, text(backup.get("name") or "unavailable"), text(backup.get("repository") or "unavailable"))
    metrics = "'backup_age_hours'={:.3f};{:g};{:g};0; 'backup_failed'=0".format(age, warning, critical)
    return code, summary, metrics


def check_licenses(tiers, evaluation, warning, critical):
    if not isinstance(tiers, list) or not tiers:
        raise CheckError("Missing or invalid license tier list")
    seen = set()
    enabled = []
    healthy = ("COMPLIANT", "FULL_COMPLIANCE", "RESERVED_IN_COMPLIANCE")
    unhealthy = ("NONCOMPLIANT", "EVALUATION_EXPIRED", "RELEASED_ENTITLEMENT")
    for tier in tiers:
        if not isinstance(tier, dict):
            raise CheckError("Invalid license tier")
        name, status = tier.get("name"), tier.get("status")
        if not isinstance(name, str) or not name.strip() or name in seen:
            raise CheckError("Missing or duplicate license tier name")
        seen.add(name)
        if status not in ("ENABLED", "DISABLED"):
            raise CheckError("Missing or unsupported license tier status")
        if status == "DISABLED":
            continue
        compliance = tier.get("compliance")
        if compliance not in healthy + unhealthy + ("EVALUATION",):
            raise CheckError("Missing or unsupported compliance for " + text(name))
        enabled.append((name, compliance))
    if not enabled:
        raise CheckError("No enabled license tiers returned")
    days = None
    if any(compliance == "EVALUATION" for _, compliance in enabled):
        days = evaluation.get("daysRemaining") if isinstance(evaluation, dict) else None
        if isinstance(days, bool) or not isinstance(days, int):
            raise CheckError("Missing or invalid evaluation daysRemaining")
    codes = []
    for _, compliance in enabled:
        if compliance == "EVALUATION":
            codes.append(2 if days <= critical else 1 if days <= warning else 0)
        else:
            codes.append(2 if compliance in unhealthy else 0)
    summary = "Licenses: {} enabled tiers; {}".format(
        len(enabled), ", ".join("{}={}".format(text(name), compliance) for name, compliance in enabled))
    metrics = "'license_tiers_enabled'={} 'license_tiers_problem'={}".format(len(enabled), sum(code != 0 for code in codes))
    if days is not None:
        summary += "; evaluation {} days remaining".format(days)
        metrics += " 'evaluation_days_remaining'={};@~:{:g};@~:{:g};;".format(days, warning, critical)
    return max(codes), summary, metrics


def ldap_uuid(value):
    if not isinstance(value, str):
        raise CheckError("Missing or invalid LDAP resource ID")
    try:
        return str(UUID(value))
    except ValueError:
        raise CheckError("Invalid LDAP resource ID")


def resolve_ldap_id(args, password):
    if args.ldap_id is not None:
        return ldap_uuid(args.ldap_id)
    seen = set()
    matches = []
    expected_total = None
    for page in range(1, 101):
        payload = fetch_json(args, password, "/ers/config/ldap/?page={}&size=100".format(page))
        search = payload.get("SearchResult") if isinstance(payload, dict) else None
        if not isinstance(search, dict):
            raise CheckError("Invalid LDAP inventory response")
        total, resources = search.get("total"), search.get("resources")
        if isinstance(total, bool) or not isinstance(total, int) or total < 0 or not isinstance(resources, list):
            raise CheckError("Invalid LDAP inventory counts or resources")
        if expected_total is not None and total != expected_total:
            raise CheckError("LDAP inventory changed during pagination")
        expected_total = total
        for resource in resources:
            if not isinstance(resource, dict) or not isinstance(resource.get("name"), str) or not resource["name"].strip():
                raise CheckError("Missing LDAP resource name")
            identifier = ldap_uuid(resource.get("id"))
            if identifier in seen:
                raise CheckError("Repeated LDAP resource ID during pagination")
            seen.add(identifier)
            if resource["name"] == args.ldap_name:
                matches.append(identifier)
        if len(seen) > total:
            raise CheckError("LDAP inventory exceeds reported total")
        if len(seen) == total:
            break
        if not resources or not search.get("nextPage"):
            raise CheckError("Incomplete LDAP inventory pagination")
    else:
        raise CheckError("LDAP inventory pagination exceeded 100 pages")
    if len(matches) != 1:
        raise CheckError("LDAP name must match exactly one configured identity source")
    return matches[0]


def check_ldap_bind(results, label):
    if not results:
        raise CheckError("No LDAP bind-test results")
    seen = set()
    details = []
    metrics = []
    failed = 0
    for server, payload in results:
        if server not in ("primary", "secondary") or server in seen:
            raise CheckError("Invalid or repeated LDAP bind-test server")
        seen.add(server)
        operation = payload.get("OperationResult") if isinstance(payload, dict) else None
        values = operation.get("resultValue") if isinstance(operation, dict) else None
        if not isinstance(values, list):
            raise CheckError("Missing LDAP bind OperationResult.resultValue")
        messages = [item.get("value") for item in values if isinstance(item, dict) and item.get("name") == "message"]
        if len(values) != 1 or len(messages) != 1 or not isinstance(messages[0], str):
            raise CheckError("Missing or ambiguous LDAP bind result message")
        message = messages[0].strip()
        success = re.match(r"^Ldap bind succeeded to \S+", message) is not None
        failure = re.match(r"^Ldap bind failed(?:\s|[.:]|$)", message) is not None
        if not success and not failure:
            raise CheckError("Unrecognized LDAP {} bind result (not proof of success)".format(server))
        failed += int(failure)
        detail = "{} {}".format(server, "succeeded" if success else "failed")
        metrics.append("'ldap_{}_bind'={}".format(server, int(success)))
        latency = re.search(r"(?:^|,\s*)Response time ([0-9]{1,12})ms(?:$|,)", message) if success else None
        if latency is not None:
            elapsed = int(latency.group(1))
            detail += " ({} ms)".format(elapsed)
            metrics.append("'ldap_{}_response_ms'={}".format(server, elapsed))
        details.append(detail)
    summary = "LDAP bind {}: {} (active ISE bind test)".format(text(label), ", ".join(details))
    metrics.insert(0, "'ldap_bind_checks_total'={} 'ldap_bind_checks_failed'={}".format(len(results), failed))
    return 2 if failed else 0, summary, " ".join(metrics)


def run_ldap_bind(args, password):
    identifier = resolve_ldap_id(args, password)
    servers = ("primary", "secondary") if args.ldap_server == "both" else (args.ldap_server or "primary",)
    results = []
    for server in servers:
        path = "/ers/config/ldap/{}/testbind{}".format(identifier, server)
        payload = fetch_json(args, password, path, method="PUT")
        result = (server, payload)
        result_code = check_ldap_bind([result], args.ldap_name or identifier)[0]
        results.append(result)
        if result_code == 2:
            break
    return check_ldap_bind(results, args.ldap_name or identifier)


def fetch_tasks(args, password):
    if not args.task_id:
        return fetch_json(args, password, "/api/v1/task")
    tasks = []
    for identifier in args.task_id:
        task = fetch_json(args, password, "/api/v1/task/" + quote(identifier, safe=""))
        if not isinstance(task, dict) or task.get("id") != identifier:
            raise CheckError("Task response does not match the requested ID")
        tasks.append(task)
    return tasks


def check_tasks(tasks, warning, critical, now=None):
    if not isinstance(tasks, list):
        raise CheckError("Invalid task list")
    now = datetime.now(timezone.utc) if now is None else now
    seen = set()
    failed = 0
    pending = 0
    ages = []
    details = []
    for task in tasks:
        if not isinstance(task, dict):
            raise CheckError("Invalid task entry")
        identifier, status = task.get("id"), task.get("executionStatus")
        if not isinstance(identifier, str) or not identifier.strip() or identifier in seen:
            raise CheckError("Missing or duplicate task ID")
        seen.add(identifier)
        if not isinstance(status, str) or not status.strip():
            raise CheckError("Missing task executionStatus")
        counts = [task.get(field) for field in ("resourcesCount", "successCount", "failCount")]
        if any(isinstance(count, bool) or not isinstance(count, int) or count < 0 for count in counts):
            raise CheckError("Missing or invalid resource counters for task " + text(identifier))
        total, succeeded, failures = counts
        if succeeded + failures > total:
            raise CheckError("Inconsistent resource counters for task " + text(identifier))
        if total == 0:
            raise CheckError("Task {} has no resources; completion cannot be determined from counters".format(text(identifier)))
        if failures:
            failed += 1
        unfinished = succeeded + failures < total
        if unfinished:
            pending += 1
            if not failures:
                started = api_date(task.get("startTime"), "task startTime")
                age = (now - started).total_seconds() / 60
                if age < 0:
                    raise CheckError("Task startTime is in the future")
                ages.append(age)
        if failures or unfinished:
            details.append("{}={} ({}/{} succeeded, {} failed)".format(
                text(identifier), text(status), succeeded, total, failures))
    oldest = max(ages, default=None)
    code = 2 if failed or (oldest is not None and oldest >= critical) else 1 if oldest is not None and oldest >= warning else 0
    summary = "Tasks: {} checked, {} with failed resources, {} unfinished (resource counters)".format(len(tasks), failed, pending)
    if oldest is not None:
        summary += "; oldest non-failed unfinished task {:.1f} minutes".format(oldest)
    if details:
        summary += "; " + ", ".join(details)
    metrics = "'tasks_total'={} 'tasks_failed'={} 'tasks_pending'={}".format(len(tasks), failed, pending)
    if oldest is not None:
        metrics += " 'task_pending_minutes'={:.3f};{:g};{:g};0;".format(oldest, warning, critical)
    return code, summary, metrics


def check_version(payload, expected_version=None, expected_patch=None):
    if not isinstance(payload, dict):
        raise CheckError("Invalid ISE version response")
    version, patches = payload.get("iseVersion"), payload.get("patchVersion")
    if not isinstance(version, str) or not version.strip() or not isinstance(patches, list):
        raise CheckError("Missing ISE application version or patch inventory")
    installed = set()
    for patch in patches:
        number = patch.get("patchNumber") if isinstance(patch, dict) else None
        if isinstance(number, bool) or not isinstance(number, int) or number < 1 or number in installed:
            raise CheckError("Invalid or duplicate installed patch number")
        installed.add(number)
    latest = max(installed, default=0)
    summary = "ISE version {}; installed patches: {}".format(
        text(version), ", ".join(str(number) for number in sorted(installed)) or "none")
    code = 0
    if expected_version is not None and version != expected_version:
        code = 2
        summary += "; expected version " + text(expected_version)
    if expected_patch is not None and latest != expected_patch:
        code = 2
        summary += "; expected latest patch {}".format(expected_patch)
    return code, summary, "'ise_patch'={} 'ise_patches_installed'={}".format(latest, len(installed))


def check_pan_ha(payload, expected="enabled"):
    settings = response_object(payload, "PAN-HA configuration")
    enabled = settings.get("isEnabled")
    if not isinstance(enabled, bool):
        raise CheckError("Missing or invalid PAN-HA isEnabled")
    state = "enabled" if enabled else "disabled"
    code = 0 if state == expected else 2
    summary = "PAN-HA automatic failover {}; expected {} (configuration only)".format(state, expected)
    return code, summary, "'pan_ha_enabled'={}".format(int(enabled))


def check_deployment(payload, expected_nodes=None):
    nodes = payload.get("response") if isinstance(payload, dict) else None
    if not isinstance(nodes, list) or not nodes:
        raise CheckError("ISE API returned no deployment nodes or an invalid response")
    names = set()
    details = []
    codes = []
    for node in nodes:
        if not isinstance(node, dict):
            raise CheckError("ISE API returned an invalid node")
        name, status = node.get("hostname"), node.get("nodeStatus")
        if not isinstance(name, str) or not name.strip() or name.casefold() in names:
            raise CheckError("ISE API returned a missing or duplicate node hostname")
        if not isinstance(status, str) or status not in NODE_STATUS:
            raise CheckError("Node {} has missing or unsupported nodeStatus: {}".format(
                text(name), text(status)))
        names.add(name.casefold())
        codes.append(NODE_STATUS[status])
        details.append("{}={}".format(text(name), status))
    connected = codes.count(0)
    code = max(codes)
    summary = "Deployment: {}/{} nodes connected; {}".format(
        connected, len(nodes), ", ".join(details))
    if expected_nodes is not None and len(nodes) != expected_nodes:
        code = 2
        summary += "; expected {} nodes".format(expected_nodes)
    metrics = "'nodes_total'={} 'nodes_connected'={} 'nodes_problem'={}".format(
        len(nodes), connected, len(nodes) - connected)
    return code, summary, metrics


def parser():
    result = CheckParser(description=__doc__, epilog=(
        "Use -H HOST -u USER -p PASSWORD --mode deployment. "
        "ISE_API_USERNAME and ISE_API_PASSWORD or --ask-password are also supported. "
        "Command-line passwords may be visible in process listings and shell history. "
        "Read-only checks except ldap-bind, which actively tests the configured LDAP bind via PUT. "
        "LDAP bind tests are not end-user authentication checks."))
    result.add_argument("-H", "--hostname", required=True, help="ISE API DNS hostname or IP address (not a URL)")
    result.add_argument("-P", "--port", type=int, default=443)
    result.add_argument("-u", "--username", default=os.environ.get("ISE_API_USERNAME"))
    credentials = result.add_mutually_exclusive_group()
    credentials.add_argument("-p", "--password", default=os.environ.get("ISE_API_PASSWORD"),
                             help="API password (overrides ISE_API_PASSWORD)")
    credentials.add_argument("--ask-password", action="store_true", help="Prompt interactively instead of using ISE_API_PASSWORD")
    result.add_argument("--mode", choices=("deployment", "certificates", "backup", "licenses", "pan-ha", "version", "tasks", "ldap-bind"), default="deployment")
    ldap = result.add_mutually_exclusive_group()
    ldap.add_argument("--ldap-id", help="Exact configured LDAP resource UUID (ldap-bind mode)")
    ldap.add_argument("--ldap-name", help="Exact configured LDAP identity-source name (ldap-bind mode)")
    result.add_argument("--ldap-server", choices=("primary", "secondary", "both"), help="LDAP server to bind-test (ldap-bind default: primary)")
    result.add_argument("--expect-ha", choices=("enabled", "disabled"), help="Expected automatic PAN failover configuration (pan-ha default: enabled)")
    result.add_argument("--expect-version", help="Exact expected ISE application release (version mode)")
    result.add_argument("--expect-patch", type=int, help="Exact expected latest installed patch, 0 for none (version mode)")
    result.add_argument("--task-id", action="append", help="Exact task ID; repeat to select tasks (default: tasks from the last 24 hours)")
    result.add_argument("--node", action="append", help="Certificate node hostname; repeat to select nodes (default: all deployment nodes)")
    result.add_argument("-w", "--warning", type=float, help="Warning: certificate/evaluation days remaining (30), backup hours (48), unfinished task minutes (30)")
    result.add_argument("-c", "--critical", type=float, help="Critical: certificate/evaluation days remaining (10), backup hours (72), unfinished task minutes (60)")
    result.add_argument("--expected-nodes", type=int, help="Return CRITICAL if the returned node count differs")
    result.add_argument("-t", "--timeout", type=float, default=10, help="Socket timeout in seconds (default: 10)")
    tls = result.add_mutually_exclusive_group()
    tls.add_argument("--ca-file", help="Trusted CA bundle in PEM format")
    tls.add_argument("--insecure", action="store_true", help="Explicitly disable TLS certificate verification")
    return result


def main(argv=None):
    try:
        arguments = sys.argv[1:] if argv is None else argv
        argument_parser = parser()
        if not arguments:
            argument_parser.print_help()
            return 3
        args = argument_parser.parse_args(arguments)
        if not 1 <= args.port <= 65535:
            raise CheckError("Port must be between 1 and 65535")
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise CheckError("Timeout must be finite and greater than zero")
        if args.expected_nodes is not None and args.expected_nodes < 1:
            raise CheckError("Expected node count must be greater than zero")
        if args.expected_nodes is not None and args.mode != "deployment":
            raise CheckError("--expected-nodes applies only to deployment")
        if args.node and args.mode != "certificates":
            raise CheckError("--node applies only to certificates")
        if args.expect_ha is not None and args.mode != "pan-ha":
            raise CheckError("--expect-ha applies only to pan-ha")
        if (args.expect_version is not None or args.expect_patch is not None) and args.mode != "version":
            raise CheckError("--expect-version and --expect-patch apply only to version")
        if args.expect_version is not None and not args.expect_version.strip():
            raise CheckError("Expected version must not be empty")
        if args.expect_patch is not None and args.expect_patch < 0:
            raise CheckError("Expected patch must be non-negative")
        if args.task_id:
            if args.mode != "tasks":
                raise CheckError("--task-id applies only to tasks")
            if any(not identifier.strip() for identifier in args.task_id) or len(set(args.task_id)) != len(args.task_id):
                raise CheckError("Task IDs must be non-empty and unique")
        if args.mode == "ldap-bind":
            if args.ldap_id is None and args.ldap_name is None:
                raise CheckError("ldap-bind requires --ldap-id or --ldap-name")
            if args.ldap_id is not None:
                args.ldap_id = ldap_uuid(args.ldap_id)
            if args.ldap_name is not None and not args.ldap_name.strip():
                raise CheckError("LDAP name must not be empty")
        elif args.ldap_id is not None or args.ldap_name is not None or args.ldap_server is not None:
            raise CheckError("LDAP selection options apply only to ldap-bind")
        warning, critical = mode_thresholds(args)
        if not args.username or ":" in args.username or any(ord(char) < 32 for char in args.username):
            raise CheckError("A valid --username or ISE_API_USERNAME is required")
        password = getpass.getpass("ISE API password: ") if args.ask_password else args.password
        if not password:
            raise CheckError("Use --password, set ISE_API_PASSWORD or use --ask-password")
        if args.mode == "ldap-bind":
            code, summary, metrics = run_ldap_bind(args, password)
        elif args.mode == "pan-ha":
            code, summary, metrics = check_pan_ha(
                fetch_json(args, password, "/api/v1/deployment/pan-ha"), args.expect_ha or "enabled")
        elif args.mode == "version":
            code, summary, metrics = check_version(
                fetch_json(args, password, "/api/v1/patch"), args.expect_version, args.expect_patch)
        elif args.mode == "tasks":
            code, summary, metrics = check_tasks(fetch_tasks(args, password), warning, critical)
        elif args.mode == "certificates":
            code, summary, metrics = check_certificates(fetch_certificates(args, password), warning, critical)
        elif args.mode == "backup":
            code, summary, metrics = check_backup(
                fetch_json(args, password, "/api/v1/backup-restore/config/last-backup-status"), warning, critical)
        elif args.mode == "licenses":
            tiers = fetch_json(args, password, "/api/v1/license/system/tier-state")
            evaluation = None
            if isinstance(tiers, list) and any(isinstance(tier, dict) and tier.get("status") == "ENABLED"
                                             and tier.get("compliance") == "EVALUATION" for tier in tiers):
                evaluation = fetch_json(args, password, "/api/v1/license/system/eval-license")
            code, summary, metrics = check_licenses(tiers, evaluation, warning, critical)
        else:
            code, summary, metrics = check_deployment(fetch_deployment(args, password), args.expected_nodes)
        if args.insecure:
            summary += "; TLS verification disabled"
        print("{} - {} | {}".format(NAGIOS_STATUS[code], summary, metrics))
        return code
    except (CheckError, OSError, ValueError, EOFError, KeyboardInterrupt) as error:
        message = text(error) if isinstance(error, CheckError) else "Check failed (check configuration, TLS CA file or interrupted input)"
        print("UNKNOWN - " + message)
        return 3


if __name__ == "__main__":
    sys.exit(main())