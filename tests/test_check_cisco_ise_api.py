import contextlib
import importlib.util
import io
import os
import ssl
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

SCRIPT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "check_cisco_ise_api.py")
SPEC = importlib.util.spec_from_file_location("check_cisco_ise_api", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Cannot load the ISE API plugin")
ise = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ise)


class ISEAPITests(unittest.TestCase):
    def payload(self, *statuses):
        return {"response": [{"hostname": "ise{}".format(index), "nodeStatus": status}
                             for index, status in enumerate(statuses)]}

    def test_documented_states(self):
        for status, expected in ise.NODE_STATUS.items():
            with self.subTest(status=status):
                code, summary, metrics = ise.check_deployment(self.payload("Connected", status))
                self.assertEqual(code, expected)
                self.assertIn(status, summary)
                self.assertIn("'nodes_total'=2", metrics)

    def test_live_response_regression(self):
        code, summary, metrics = ise.check_deployment(self.payload("Connected", "NotInSync"))
        self.assertEqual(code, 2)
        self.assertIn("1/2 nodes connected", summary)
        self.assertIn("'nodes_problem'=1", metrics)

    def test_invalid_or_unknown_data(self):
        for payload in (None, [], {}, {"response": []}, {"response": {}},
                        {"response": [None]}, {"response": [{}]},
                        self.payload("NotApplicable"), self.payload("FutureState"),
                        self.payload(None), self.payload(["Connected"]),
                        {"response": [{"hostname": " ", "nodeStatus": "Connected"}]}):
            with self.subTest(payload=payload), self.assertRaises(ise.CheckError):
                ise.check_deployment(payload)

    def test_duplicate_nodes(self):
        payload = self.payload("Connected", "Connected")
        payload["response"][1]["hostname"] = "ISE0"
        with self.assertRaises(ise.CheckError):
            ise.check_deployment(payload)

    def test_expected_nodes(self):
        self.assertEqual(ise.check_deployment(self.payload("Connected"), 2)[0], 2)
        self.assertEqual(ise.check_deployment(self.payload("Connected"), 1)[0], 0)

    def run_main(self, extra=(), environment=None):
        output = io.StringIO()
        with patch.dict(os.environ, environment or {}, clear=True), contextlib.redirect_stdout(output):
            code = ise.main(["-H", "172.23.38.11", "-u", "ise_api"] + list(extra))
        return code, output.getvalue()

    def test_cli_and_secret_handling(self):
        with patch.object(ise, "fetch_deployment", return_value=self.payload("Connected")):
            code, output = self.run_main(environment={"ISE_API_PASSWORD": "test-secret"})
        self.assertEqual(code, 0)
        self.assertNotIn("test-secret", output)
        self.assertEqual(self.run_main()[0], 3)

    def test_password_aliases_and_precedence(self):
        for option in ("-p", "--password"):
            for environment in ({}, {"ISE_API_PASSWORD": "environment-secret"}):
                with self.subTest(option=option, environment=environment), \
                        patch.object(ise, "fetch_deployment", return_value=self.payload("Connected")) as fetch:
                    code, output = self.run_main((option, "cli-secret", "--mode", "deployment"), environment)
                    self.assertEqual(code, 0)
                    self.assertEqual(fetch.call_args[0][1], "cli-secret")
                    self.assertNotIn("cli-secret", output)
                    self.assertNotIn("environment-secret", output)

    def test_long_form_invocation(self):
        with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(io.StringIO()), \
                patch.object(ise, "fetch_deployment", return_value=self.payload("Connected")) as fetch:
            code = ise.main(["--hostname", "ise.example.net", "--username", "api-user",
                             "--password", "cli-secret", "--mode", "deployment"])
        self.assertEqual(code, 0)
        self.assertEqual(fetch.call_args[0][0].hostname, "ise.example.net")
        self.assertEqual(fetch.call_args[0][0].username, "api-user")
        self.assertEqual(fetch.call_args[0][1], "cli-secret")

    def test_password_input_selection(self):
        with patch.object(ise.getpass, "getpass", return_value="prompt-secret") as prompt, \
                patch.object(ise, "fetch_deployment", return_value=self.payload("Connected")) as fetch:
            code, output = self.run_main(("--ask-password",), {"ISE_API_PASSWORD": "environment-secret"})
            self.assertEqual(code, 0)
            prompt.assert_called_once()
            self.assertEqual(fetch.call_args[0][1], "prompt-secret")
            self.assertNotIn("prompt-secret", output)
        with patch.object(ise, "fetch_deployment") as fetch:
            self.assertEqual(self.run_main(("-p", ""), {"ISE_API_PASSWORD": "environment-secret"})[0], 3)
            self.assertEqual(self.run_main(("-p", "cli-secret", "--ask-password"))[0], 3)
            fetch.assert_not_called()

    def test_invalid_arguments_do_not_query(self):
        for extra in (("--timeout", "nan"), ("--timeout", "0"), ("--port", "65536"),
                      ("--expected-nodes", "0"), ("--mode", "unknown"),
                      ("--ca-file", "ca.pem", "--insecure")):
            with self.subTest(extra=extra), patch.object(ise, "fetch_deployment") as fetch:
                self.assertEqual(self.run_main(extra, {"ISE_API_PASSWORD": "secret"})[0], 3)
                fetch.assert_not_called()

    def certificate(self, days=90, starts=-90, identifier="cert1"):
        now = datetime(2026, 11, 10, tzinfo=timezone.utc)
        return {"id": identifier, "friendlyName": "EAP", "expirationDate": (now + timedelta(days=days)).isoformat(),
                "validFrom": (now + timedelta(days=starts)).isoformat()}

    def test_certificate_thresholds_and_validity(self):
        now = datetime(2026, 11, 10, tzinfo=timezone.utc)
        for days, expected in ((31, 0), (30, 1), (10, 2), (-1, 2)):
            with self.subTest(days=days):
                result = ise.check_certificates([("ise1", self.certificate(days))], 30, 10, now)
                self.assertEqual(result[0], expected)
                self.assertIn("certificate_days_remaining", result[2])
        self.assertEqual(ise.check_certificates([("ise1", self.certificate(starts=1))], 30, 10, now)[0], 2)
        certificate = self.certificate()
        for value in (None, "bad", "2026-11-10T00:00:00", "Tue Nov 10 00:00:00 XYZ 2026"):
            certificate["expirationDate"] = value
            with self.subTest(value=value), self.assertRaises(ise.CheckError):
                ise.check_certificates([("ise1", certificate)], 30, 10, now)

    def test_live_certificate_dates(self):
        self.assertEqual(ise.api_date("Wed Nov 04 13:28:18 UTC 2026", "date"),
                         datetime(2026, 11, 4, 13, 28, 18, tzinfo=timezone.utc))

    def test_certificate_pagination_and_scope(self):
        args = SimpleNamespace(node=["ise1"])
        pages = [{"response": [self.certificate(identifier="first")], "nextPage": "https://untrusted.invalid/"},
                 {"response": [self.certificate(identifier="second")], "nextPage": None}]
        with patch.object(ise, "fetch_json", side_effect=pages) as fetch:
            self.assertEqual(len(ise.fetch_certificates(args, "secret")), 2)
            self.assertEqual(fetch.call_args_list[1][0][2], "/api/v1/certs/system-certificate/ise1?page=2&size=100")
        for payload in ({"response": []}, {"response": [self.certificate()]},
                        {"response": [self.certificate(), self.certificate()], "nextPage": None}):
            with self.subTest(payload=payload), patch.object(ise, "fetch_json", return_value=payload), \
                    self.assertRaises(ise.CheckError):
                ise.fetch_certificates(args, "secret")
        args.node = None
        with patch.object(ise, "fetch_deployment", return_value=self.payload("Connected", "NotInSync")), \
                patch.object(ise, "fetch_json", return_value={"response": [self.certificate()], "nextPage": None}):
            self.assertEqual(len(ise.fetch_certificates(args, "secret")), 2)

    def test_certificate_cli(self):
        with patch.object(ise, "fetch_certificates", return_value=[("ise1", self.certificate())]), \
            patch.object(ise, "check_certificates", return_value=(0, "Certificates checked", "")):
            self.assertEqual(self.run_main(("--mode", "certificates", "-p", "secret"))[0], 0)
        for extra in (("--mode", "certificates", "-w", "5", "-c", "10"),
                      ("--mode", "certificates", "-w", "nan"), ("--node", "ise1"),
                      ("--mode", "certificates", "--expected-nodes", "2")):
            self.assertEqual(self.run_main(extra, {"ISE_API_PASSWORD": "secret"})[0], 3)

    def backup(self, status="COMPLETED", hours=12):
        now = datetime(2026, 11, 10, 12, tzinfo=timezone.utc)
        return {"response": {"status": status, "action": "BACKUP", "error": None,
                             "startDate": (now - timedelta(hours=hours)).isoformat()}}

    def test_backup_age_and_states(self):
        now = datetime(2026, 11, 10, 12, tzinfo=timezone.utc)
        for status, hours, expected in (("COMPLETED", 12, 0), ("COMPLETED", 48, 1),
                                        ("COMPLETED", 72, 2), ("ERROR", 12, 2),
                                        ("IN_PROGRESS", 1, 1), ("IN_PROGRESS", 72, 2)):
            with self.subTest(status=status, hours=hours):
                self.assertEqual(ise.check_backup(self.backup(status, hours), 48, 72, now)[0], expected)
        payload = self.backup()
        payload["response"]["error"] = "repository failed"
        self.assertEqual(ise.check_backup(payload, 48, 72, now)[0], 2)
        payload["response"]["action"] = "CANCEL"
        self.assertEqual(ise.check_backup(payload, 48, 72, now)[0], 2)

    def test_backup_invalid_data(self):
        now = datetime(2026, 11, 10, 12, tzinfo=timezone.utc)
        for field, value in (("status", "NEW_STATE"), ("action", "RESTORE"),
                             ("startDate", "bad"), ("startDate", "2026-11-11T00:00:00Z"),
                             ("error", {}), ("type", "OPERATIONAL_DB")):
            payload = self.backup()
            payload["response"][field] = value
            with self.subTest(field=field), self.assertRaises(ise.CheckError):
                ise.check_backup(payload, 48, 72, now)
        for payload in ({}, {"response": []}, {"response": {}}):
            with self.assertRaises(ise.CheckError):
                ise.check_backup(payload, 48, 72, now)

    def tier(self, compliance="COMPLIANT", status="ENABLED", name="ESSENTIAL"):
        return {"name": name, "status": status, "compliance": compliance}

    def test_license_compliance_and_evaluation(self):
        for compliance, expected in (("COMPLIANT", 0), ("FULL_COMPLIANCE", 0),
                                     ("RESERVED_IN_COMPLIANCE", 0), ("NONCOMPLIANT", 2),
                                     ("EVALUATION_EXPIRED", 2), ("RELEASED_ENTITLEMENT", 2)):
            with self.subTest(compliance=compliance):
                self.assertEqual(ise.check_licenses([self.tier(compliance)], None, 30, 10)[0], expected)
        for days, expected in ((31, 0), (30, 1), (10, 2), (6, 2), (0, 2), (-1, 2)):
            with self.subTest(days=days):
                code, summary, metrics = ise.check_licenses([self.tier("EVALUATION")], {"daysRemaining": days}, 30, 10)
                self.assertEqual(code, expected)
                self.assertIn("evaluation", summary)
                self.assertIn("evaluation_days_remaining", metrics)

    def test_disabled_tiers_and_invalid_license_data(self):
        self.assertEqual(ise.check_licenses([self.tier(), self.tier("EVALUATION_EXPIRED", "DISABLED", "PREMIER")],
                                            None, 30, 10)[0], 0)
        for tiers in ([], {}, [None], [self.tier("UNKNOWN")], [self.tier(status="NEW")],
                      [self.tier(status="DISABLED")], [self.tier(), self.tier()]):
            with self.subTest(tiers=tiers), self.assertRaises(ise.CheckError):
                ise.check_licenses(tiers, None, 30, 10)
        for evaluation in (None, {}, {"daysRemaining": True}, {"daysRemaining": "6"}):
            with self.subTest(evaluation=evaluation), self.assertRaises(ise.CheckError):
                ise.check_licenses([self.tier("EVALUATION")], evaluation, 30, 10)

    def test_backup_and_license_cli_routing(self):
        with patch.object(ise, "fetch_json", return_value=self.backup()) as fetch, \
                patch.object(ise, "check_backup", return_value=(0, "Backup completed", "")):
            self.assertEqual(self.run_main(("--mode", "backup", "-p", "secret"))[0], 0)
            self.assertEqual(fetch.call_args[0][2], "/api/v1/backup-restore/config/last-backup-status")
        with patch.object(ise, "fetch_json", side_effect=[[self.tier("EVALUATION")], {"daysRemaining": 6}]) as fetch:
            code, output = self.run_main(("--mode", "licenses", "-p", "secret"))
            self.assertEqual(code, 2)
            self.assertIn("6 days remaining", output)
            self.assertEqual(fetch.call_count, 2)
        with patch.object(ise, "fetch_json", return_value=[self.tier()]) as fetch:
            self.assertEqual(self.run_main(("--mode", "licenses", "-p", "secret"))[0], 0)
            self.assertEqual(fetch.call_count, 1)

    def test_mode_threshold_validation(self):
        for mode, warning, critical in (("backup", 72, 48), ("backup", -1, 72),
                                        ("licenses", 10, 30), ("licenses", 30, -1),
                                        ("certificates", float("inf"), 10), ("deployment", 1, 2)):
            with self.subTest(mode=mode), self.assertRaises(ise.CheckError):
                ise.mode_thresholds(SimpleNamespace(mode=mode, warning=warning, critical=critical))
        self.assertEqual(ise.mode_thresholds(SimpleNamespace(mode="backup", warning=None, critical=None)), (48, 72))
        self.assertEqual(ise.mode_thresholds(SimpleNamespace(mode="licenses", warning=None, critical=None)), (30, 10))

    def test_pan_ha_configuration(self):
        for enabled, expected, code in ((True, "enabled", 0), (False, "enabled", 2),
                                        (False, "disabled", 0), (True, "disabled", 2)):
            with self.subTest(enabled=enabled, expected=expected):
                result = ise.check_pan_ha({"response": {"isEnabled": enabled}}, expected)
                self.assertEqual(result[0], code)
                self.assertIn("configuration only", result[1])
        for payload in ({}, {"response": {}}, {"response": {"isEnabled": "false"}},
                        {"response": {"isEnabled": 0}}, {"response": {"isEnabled": None}}):
            with self.subTest(payload=payload), self.assertRaises(ise.CheckError):
                ise.check_pan_ha(payload)

    def test_pan_ha_cli(self):
        with patch.object(ise, "fetch_json", return_value={"response": {"isEnabled": False}}) as fetch:
            self.assertEqual(self.run_main(("--mode", "pan-ha", "-p", "secret"))[0], 2)
            self.assertEqual(self.run_main(("--mode", "pan-ha", "--expect-ha", "disabled", "-p", "secret"))[0], 0)
            self.assertEqual(fetch.call_args[0][2], "/api/v1/deployment/pan-ha")
        self.assertEqual(self.run_main(("--mode", "pan-ha", "-w", "1", "-p", "secret"))[0], 3)
        self.assertEqual(self.run_main(("--expect-ha", "enabled", "-p", "secret"))[0], 3)

    def test_version_inventory_and_expectations(self):
        payload = {"iseVersion": "3.4.0.608", "patchVersion": []}
        code, summary, metrics = ise.check_version(payload)
        self.assertEqual(code, 0)
        self.assertIn("3.4.0.608", summary)
        self.assertIn("'ise_patch'=0", metrics)
        self.assertEqual(ise.check_version(payload, "3.4.0.608", 0)[0], 0)
        self.assertEqual(ise.check_version(payload, "3.3.0.430")[0], 2)
        self.assertEqual(ise.check_version(payload, expected_patch=1)[0], 2)
        payload["patchVersion"] = [{"patchNumber": 2}, {"patchNumber": 1}]
        self.assertEqual(ise.check_version(payload, expected_patch=2)[0], 0)
        self.assertIn("'ise_patch'=2", ise.check_version(payload)[2])

    def test_version_invalid_data(self):
        for payload in ({}, [], {"version": "1.0.0", "patchVersion": []},
                        {"iseVersion": "", "patchVersion": []}, {"iseVersion": "3.4", "patchVersion": None}):
            with self.subTest(payload=payload), self.assertRaises(ise.CheckError):
                ise.check_version(payload)
        for patches in ([None], [{}], [{"patchNumber": True}], [{"patchNumber": "1"}],
                        [{"patchNumber": -1}], [{"patchNumber": 1}, {"patchNumber": 1}]):
            with self.subTest(patches=patches), self.assertRaises(ise.CheckError):
                ise.check_version({"iseVersion": "3.4.0.608", "patchVersion": patches})

    def test_version_cli(self):
        with patch.object(ise, "fetch_json", return_value={"iseVersion": "3.4.0.608", "patchVersion": []}) as fetch:
            self.assertEqual(self.run_main(("--mode", "version", "-p", "secret"))[0], 0)
            self.assertEqual(self.run_main(("--mode", "version", "--expect-version", "3.4.0.608",
                                            "--expect-patch", "0", "-p", "secret"))[0], 0)
            self.assertEqual(fetch.call_args[0][2], "/api/v1/patch")
        for extra in (("--mode", "version", "--expect-patch", "-1"), ("--expect-version", "3.4"),
                      ("--mode", "version", "-w", "1"), ("--mode", "version", "--expect-version", "")):
            self.assertEqual(self.run_main(extra, {"ISE_API_PASSWORD": "secret"})[0], 3)

    def task(self, succeeded=1, failed=0, total=2, age=10, identifier="task1"):
        now = datetime(2026, 11, 10, 12, tzinfo=timezone.utc)
        return {"id": identifier, "executionStatus": "free-form API status", "resourcesCount": total,
                "successCount": succeeded, "failCount": failed, "startTime": (now - timedelta(minutes=age)).isoformat()}

    def test_task_counts_and_age_thresholds(self):
        now = datetime(2026, 11, 10, 12, tzinfo=timezone.utc)
        self.assertEqual(ise.check_tasks([], 30, 60, now)[0], 0)
        self.assertEqual(ise.check_tasks([self.task(succeeded=2)], 30, 60, now)[0], 0)
        for age, expected in ((10, 0), (30, 1), (60, 2)):
            with self.subTest(age=age):
                result = ise.check_tasks([self.task(age=age)], 30, 60, now)
                self.assertEqual(result[0], expected)
                self.assertIn("resource counters", result[1])
                self.assertIn("task_pending_minutes", result[2])
        task = self.task(failed=1, succeeded=0)
        task.pop("startTime")
        self.assertEqual(ise.check_tasks([task], 30, 60, now)[0], 2)

    def test_task_invalid_data(self):
        now = datetime(2026, 11, 10, 12, tzinfo=timezone.utc)
        for field, value in (("id", None), ("executionStatus", ""), ("resourcesCount", -1),
                             ("successCount", True), ("failCount", "0"), ("startTime", "bad"),
                             ("startTime", "2026-11-11T00:00:00Z")):
            task = self.task()
            task[field] = value
            with self.subTest(field=field), self.assertRaises(ise.CheckError):
                ise.check_tasks([task], 30, 60, now)
        for tasks in ({}, [None], [self.task(), self.task()], [self.task(succeeded=3)],
                      [self.task(succeeded=0, total=0)]):
            with self.subTest(tasks=tasks), self.assertRaises(ise.CheckError):
                ise.check_tasks(tasks, 30, 60, now)

    def test_task_fetch_and_cli_scope(self):
        args = SimpleNamespace(task_id=["task/1"])
        task = self.task(identifier="task/1", succeeded=2)
        with patch.object(ise, "fetch_json", return_value=task) as fetch:
            self.assertEqual(ise.fetch_tasks(args, "secret"), [task])
            self.assertEqual(fetch.call_args[0][2], "/api/v1/task/task%2F1")
        with patch.object(ise, "fetch_json", return_value=self.task()), self.assertRaises(ise.CheckError):
            ise.fetch_tasks(args, "secret")
        with patch.object(ise, "fetch_json", return_value=[]) as fetch:
            self.assertEqual(self.run_main(("--mode", "tasks", "-p", "secret"))[0], 0)
            self.assertEqual(fetch.call_args[0][2], "/api/v1/task")
        for extra in (("--task-id", "task1"), ("--mode", "tasks", "--task-id", ""),
                      ("--mode", "tasks", "--task-id", "task1", "--task-id", "task1"),
                      ("--mode", "tasks", "-w", "60", "-c", "30"), ("--mode", "tasks", "-w", "nan")):
            self.assertEqual(self.run_main(extra, {"ISE_API_PASSWORD": "secret"})[0], 3)
        self.assertEqual(ise.mode_thresholds(SimpleNamespace(mode="tasks", warning=None, critical=None)), (30, 60))

    def ldap_result(self, message=None):
        message = message if message is not None else (
            "Ldap bind succeeded to 193.47.71.154:636, Number of Subjects greater than 100, "
            "Number of Groups greater than 100, Response time 93ms")
        return {"OperationResult": {"resultValue": [{"value": message, "name": "message"}]}}

    def test_ldap_bind_live_success_and_explicit_failure(self):
        code, summary, metrics = ise.check_ldap_bind([("primary", self.ldap_result())], "NAGIOS_PROD_LDAP")
        self.assertEqual(code, 0)
        self.assertIn("primary succeeded (93 ms)", summary)
        self.assertIn("'ldap_primary_response_ms'=93", metrics)
        results = [("primary", self.ldap_result()), ("secondary", self.ldap_result("Ldap bind failed to ldap.example:636"))]
        self.assertEqual(ise.check_ldap_bind(results, "test")[0], 2)
        self.assertEqual(ise.check_ldap_bind([("primary", self.ldap_result("Ldap bind succeeded to ldap.example:636"))], "test")[0], 0)

    def test_ldap_bind_unknown_is_not_success(self):
        ambiguous = self.ldap_result()
        ambiguous["OperationResult"]["resultValue"].append({"name": "message", "value": "another result"})
        conflicting = self.ldap_result()
        conflicting["OperationResult"]["resultValue"].append({"name": "error", "value": "unexpected error"})
        for payload in ({}, [], {"OperationResult": {}}, self.ldap_result("Accepted"),
                        self.ldap_result("Secondary server not configured"), ambiguous, conflicting,
                        self.ldap_result("Ldap bind succeeded to ")):
            with self.subTest(payload=payload), self.assertRaises(ise.CheckError):
                ise.check_ldap_bind([("primary", payload)], "test")

    def test_ldap_name_resolution_pagination(self):
        identifier = "8346cf20-75f1-11f1-ab0d-c666efb4ca7f"
        second = "cd187520-eca0-11f0-b570-005056b3e604"
        args = SimpleNamespace(ldap_id=None, ldap_name="NAGIOS_PROD_LDAP")
        pages = [{"SearchResult": {"total": 2, "resources": [{"id": second, "name": "other"}],
                                   "nextPage": {"href": "https://untrusted.invalid/"}}},
                 {"SearchResult": {"total": 2, "resources": [{"id": identifier, "name": args.ldap_name}]}}]
        with patch.object(ise, "fetch_json", side_effect=pages) as fetch:
            self.assertEqual(ise.resolve_ldap_id(args, "secret"), identifier)
            self.assertEqual(fetch.call_args_list[1][0][2], "/ers/config/ldap/?page=2&size=100")
        for payload in ({}, {"SearchResult": {"total": 0, "resources": []}},
                        {"SearchResult": {"total": 2, "resources": [{"id": identifier, "name": args.ldap_name}]}},
                        {"SearchResult": {"total": 2, "resources": [{"id": identifier, "name": args.ldap_name}] * 2}}):
            with self.subTest(payload=payload), patch.object(ise, "fetch_json", return_value=payload), \
                    self.assertRaises(ise.CheckError):
                ise.resolve_ldap_id(args, "secret")

    def test_ldap_bind_cli_and_safe_scope(self):
        identifier = "8346cf20-75f1-11f1-ab0d-c666efb4ca7f"
        for server, calls in (("primary", 1), ("secondary", 1), ("both", 2)):
            with self.subTest(server=server), patch.object(ise, "fetch_json", return_value=self.ldap_result()) as fetch:
                code, output = self.run_main(("--mode", "ldap-bind", "--ldap-id", identifier,
                                              "--ldap-server", server, "-p", "secret"))
                self.assertEqual(code, 0)
                self.assertEqual(fetch.call_count, calls)
                self.assertTrue(all(call.kwargs == {"method": "PUT"} for call in fetch.call_args_list))
                self.assertNotIn("secret", output)
        with patch.object(ise, "fetch_json", return_value=self.ldap_result("Ldap bind failed: rejected")) as fetch:
            self.assertEqual(self.run_main(("--mode", "ldap-bind", "--ldap-id", identifier,
                                            "--ldap-server", "both", "-p", "secret"))[0], 2)
            self.assertEqual(fetch.call_count, 1)
        for extra in (("--mode", "ldap-bind"), ("--mode", "ldap-bind", "--ldap-id", "invalid"),
                      ("--mode", "ldap-bind", "--ldap-name", ""), ("--ldap-id", identifier),
                      ("--ldap-server", "primary"), ("--mode", "ldap-bind", "--ldap-id", identifier, "-w", "10"),
                      ("--mode", "ldap-bind", "--ldap-id", identifier, "--ldap-name", "test")):
            with self.subTest(extra=extra), patch.object(ise, "fetch_json") as fetch:
                self.assertEqual(self.run_main(extra, {"ISE_API_PASSWORD": "secret"})[0], 3)
                fetch.assert_not_called()

    def test_only_ldap_bind_put_is_allowed(self):
        args = SimpleNamespace(hostname="172.23.38.11", port=443, timeout=10,
                               username="ise_api", insecure=False, ca_file=None)
        response = MagicMock()
        response.status = 200
        response.read.return_value = b"{}"
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        identifier = "8346cf20-75f1-11f1-ab0d-c666efb4ca7f"
        with patch.object(ise, "build_opener", return_value=opener):
            for server in ("primary", "secondary"):
                path = "/ers/config/ldap/{}/testbind{}".format(identifier, server)
                ise.fetch_json(args, "secret", path, method="PUT")
                request = opener.open.call_args[0][0]
                self.assertEqual(request.get_method(), "PUT")
                self.assertIsNone(request.data)
                self.assertEqual(request.get_header("Content-type"), "application/json")
            opener.open.reset_mock()
            for method, path in (("POST", "/api/v1/task"), ("DELETE", "/ers/config/ldap/" + identifier),
                                  ("PUT", "/ers/config/ldap/" + identifier),
                                  ("PUT", "/api/v1/deployment/pan-ha"),
                                  ("PUT", "/ers/config/ldap/{}/testbindprimary?extra=1".format(identifier))):
                with self.subTest(method=method, path=path), self.assertRaises(ise.CheckError):
                    ise.fetch_json(args, "secret", path, method=method)
            opener.open.assert_not_called()

    def test_transport(self):
        args = SimpleNamespace(hostname="172.23.38.11", port=443, timeout=10,
                               username="ise_api", insecure=False, ca_file=None)
        response = MagicMock()
        response.status = 200
        response.read.return_value = b'{"response": []}'
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch.object(ise, "build_opener", return_value=opener) as build:
            self.assertEqual(ise.fetch_deployment(args, "secret"), {"response": []})
            context = build.call_args[0][1]._context
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            request = opener.open.call_args[0][0]
            self.assertEqual(request.full_url, "https://172.23.38.11:443/api/v1/deployment/node")
            self.assertIsNone(request.data)
            for error in (HTTPError(request.full_url, 401, "Unauthorized", {}, None),
                          URLError("secret must not leak"), TimeoutError()):
                opener.open.side_effect = error
                with self.assertRaises(ise.CheckError) as raised:
                    ise.fetch_deployment(args, "secret")
                self.assertNotIn("secret", str(raised.exception))
            opener.open.side_effect = None
            for body in (b"not json", b"x" * (ise.MAX_RESPONSE_BYTES + 1)):
                response.read.return_value = body
                with self.assertRaises(ise.CheckError):
                    ise.fetch_deployment(args, "secret")
            args.insecure = True
            response.read.return_value = b"{}"
            ise.fetch_deployment(args, "secret")
            self.assertEqual(build.call_args[0][1]._context.verify_mode, ssl.CERT_NONE)

    def test_redirects_blocked(self):
        self.assertIsNone(ise.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other-host/"))

    def test_help(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ise.main([]), 3)
            with self.assertRaises(SystemExit) as raised:
                ise.main(["--help"])
            self.assertEqual(raised.exception.code, 0)


if __name__ == "__main__":
    unittest.main()