"""
Tests for the Sandbox module.
"""

import base64
import unittest

from mcp.types import ToolAnnotations

from falcon_mcp.modules import sandbox
from falcon_mcp.modules.sandbox import SandboxModule, _trim_sandbox
from tests.modules.utils.test_modules import TestModules

REPORT = "a" * 32 + "_" + "b" * 32
SHA = "c" * 64


def _ok(resources, total=None, status=200):
    body = {"resources": resources, "errors": []}
    if total is not None:
        body["meta"] = {"pagination": {"offset": 0, "limit": 10, "total": total}}
    return {"status_code": status, "body": body}


SUBMIT_DEFAULTS = {
    "url": None,
    "sha256": None,
    "environment_id": 160,
    "network_settings": "default",
    "submit_name": None,
    "command_line": None,
    "action_script": None,
    "document_password": None,
    "system_date": None,
    "system_time": None,
    "user_tags": None,
}


class TestSandboxModule(TestModules):
    """Test cases for the Sandbox module."""

    def setUp(self):
        self.setup_module(SandboxModule)

    def test_register_tools(self):
        self.assert_tools_registered(
            [
                "falcon_search_sandbox_reports",
                "falcon_get_sandbox_report",
                "falcon_search_sandbox_submissions",
                "falcon_check_sandbox_samples",
                "falcon_submit_to_sandbox",
                "falcon_upload_sandbox_sample",
                "falcon_delete_sandbox_report",
                "falcon_delete_sandbox_sample",
            ]
        )

    def test_write_annotations(self):
        self.module.register_tools(self.mock_server)
        for name, destructive, idempotent in (
            ("falcon_submit_to_sandbox", False, False),
            ("falcon_upload_sandbox_sample", False, True),
            ("falcon_delete_sandbox_report", True, True),
            ("falcon_delete_sandbox_sample", True, True),
        ):
            with self.subTest(tool=name):
                self.assert_tool_annotations(
                    name,
                    ToolAnnotations(
                        readOnlyHint=False,
                        destructiveHint=destructive,
                        idempotentHint=idempotent,
                        openWorldHint=True,
                    ),
                )

    # --- reads ---------------------------------------------------------------

    def test_search_reports_returns_summaries_in_order(self):
        self.mock_client.command.side_effect = [
            _ok(["r1", "r2"], total=2),
            _ok([{"id": "r2", "verdict": "suspicious"}, {"id": "r1", "verdict": "malicious"}]),
        ]

        result = self.module.search_sandbox_reports(
            filter="verdict:'malicious'", limit=10, offset=None, sort="created_timestamp.desc"
        )

        query, summaries = self.mock_client.command.call_args_list
        self.assertEqual(query[0][0], "QueryReports")
        self.assertEqual(summaries[0][0], "GetSummaryReports")
        self.assertEqual(summaries[1]["parameters"]["ids"], ["r1", "r2"])
        self.assertEqual([r["id"] for r in result["results"]], ["r1", "r2"])

    def test_get_report_is_trimmed(self):
        full = {
            "id": REPORT,
            "verdict": "malicious",
            "sandbox": [
                {
                    "sha256": SHA,
                    "threat_score": 90,
                    "extracted_interesting_strings": [{"value": "x"}] * 500,
                    "visualization": "big",
                    "signatures": [
                        {"name": "a", "threat_level_human": "malicious", "relevance": 5, "description": "d" * 5000},
                        {"name": "b", "threat_level_human": "informative"},
                    ],
                    "mitre_attacks": [
                        {"attack_id": "T1055", "tactic": "Defense Evasion", "technique": "Process Injection", "malicious_identifiers": ["x"]},
                        {"attack_id": "T1082", "tactic": "Discovery", "technique": "System Information Discovery", "informative_identifiers": ["y"]},
                    ],
                    "processes": [{"name": "evil.exe", "command_line": "x" * 5000, "modules": ["m"] * 100}],
                    "http_requests": [{"method": "GET", "url": "http://e", "header": "H" * 1000}],
                    "contacted_hosts": [{"address": "203.0.113.5", "port": 443}],
                }
            ],
        }
        self.mock_client.command.return_value = _ok([full])

        result = self.module.get_sandbox_report(report_id=REPORT, include_informative=False)

        sb = result["sandbox"][0]
        self.assertNotIn("extracted_interesting_strings", sb)
        self.assertNotIn("visualization", sb)
        self.assertEqual([s["name"] for s in sb["signatures"]], ["a"])
        self.assertEqual(sb["omitted"], {"signatures": 1})
        self.assertEqual(len(sb["signatures"][0]["description"]), 303)
        self.assertEqual([m["attack_id"] for m in sb["mitre_attacks"]], ["T1055"])
        self.assertEqual(len(sb["processes"][0]["command_line"]), 1000)
        self.assertNotIn("modules", sb["processes"][0])
        self.assertNotIn("header", sb["network"]["http_requests"][0])
        self.assertEqual(sb["network"]["contacted_hosts"][0]["port"], 443)

    def test_include_informative(self):
        sb = _trim_sandbox(
            {
                "signatures": [{"name": "b", "threat_level_human": "informative"}],
                "mitre_attacks": [{"attack_id": "T1082", "informative_identifiers": ["y"]}],
            },
            include_informative=True,
        )
        self.assertEqual(len(sb["signatures"]), 1)
        self.assertEqual(sb["mitre_attacks"][0]["severity"], "informative")

    def test_get_report_bad_and_missing_ids(self):
        self.assertIn("error", self.module.get_sandbox_report(report_id="nope", include_informative=False))
        self.mock_client.command.assert_not_called()

        self.mock_client.command.return_value = _ok([])
        result = self.module.get_sandbox_report(report_id=REPORT, include_informative=False)
        self.assertIn("No sandbox report", result["error"])

    def test_submissions_by_id_and_by_filter(self):
        self.mock_client.command.return_value = _ok([{"id": "s1", "state": "running"}])
        result = self.module.search_sandbox_submissions(
            filter=None, ids=["s1", "s2"], limit=10, offset=None, sort=None
        )
        self.assertEqual(self.mock_client.command.call_args[0][0], "GetSubmissions")
        self.assertEqual(result["not_found"], ["s2"])

        self.mock_client.command.reset_mock()
        self.mock_client.command.side_effect = [
            _ok(["s1"], total=1),
            _ok([{"id": "s1", "state": "success"}]),
        ]
        result = self.module.search_sandbox_submissions(
            filter="state:'success'", ids=None, limit=10, offset=None, sort=None
        )
        self.assertEqual(self.mock_client.command.call_args_list[0][0][0], "QuerySubmissions")
        self.assertEqual(result["results"][0]["state"], "success")

    def test_check_samples(self):
        self.mock_client.command.return_value = _ok([{"sha256": SHA}])
        other = "d" * 64

        result = self.module.check_sandbox_samples(sha256s=[SHA.upper(), other])

        self.mock_client.command.assert_called_once_with(
            "QuerySampleV1", body={"sha256s": [SHA, other]}
        )
        self.assertEqual(result, {"found": [SHA], "not_found": [other]})

    def test_check_samples_unknown_hash_comes_back_as_not_found(self):
        """The API reports unknown hashes as an error message under HTTP 200."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [], "errors": [{"message": "Sample not found."}]},
        }
        result = self.module.check_sandbox_samples(sha256s=[SHA])
        self.assertEqual(result, {"found": [], "not_found": [SHA]})

    def test_check_samples_rejects_bad_hashes(self):
        self.assertIn("error", self.module.check_sandbox_samples(sha256s=["md5ish"]))
        self.mock_client.command.assert_not_called()

    # --- writes --------------------------------------------------------------

    def test_submit_url(self):
        self.mock_client.command.return_value = _ok([{"id": "s1", "state": "created"}])

        result = self.module.submit_to_sandbox(
            **{
                **SUBMIT_DEFAULTS,
                "url": "https://example.com/x",
                "network_settings": "simulated",
                "user_tags": ["case-7", " "],
            }
        )

        self.mock_client.command.assert_called_once_with(
            "Submit",
            body={
                "sandbox": [
                    {
                        "environment_id": 160,
                        "network_settings": "simulated",
                        "url": "https://example.com/x",
                    }
                ],
                "user_tags": ["case-7"],
            },
        )
        self.assertEqual(result["id"], "s1")
        self.assertEqual(result["environment"], "Windows 10, 64-bit")

    def test_submit_hash_with_options(self):
        self.mock_client.command.return_value = _ok([{"id": "s2", "state": "created"}])

        self.module.submit_to_sandbox(
            **{
                **SUBMIT_DEFAULTS,
                "sha256": SHA.upper(),
                "environment_id": 140,
                "submit_name": "invoice.docm",
                "document_password": "infected",
                "system_date": "2026-11-14",
                "system_time": "09:30",
            }
        )

        job = self.mock_client.command.call_args[1]["body"]["sandbox"][0]
        self.assertEqual(job["sha256"], SHA)
        self.assertEqual(job["environment_id"], 140)
        self.assertEqual(job["submit_name"], "invoice.docm")
        self.assertNotIn("url", job)

    def test_submit_validation(self):
        cases = {
            "neither": {},
            "both": {"url": "https://e.com", "sha256": SHA},
            "bad url": {"url": "javascript:alert(1)"},
            "bad hash": {"sha256": "abc"},
            "bad environment": {"url": "https://e.com", "environment_id": 999},
            "bad network": {"url": "https://e.com", "network_settings": "vpn"},
            "bad script": {"url": "https://e.com", "action_script": "rm"},
            "long command line": {"url": "https://e.com", "command_line": "x" * 2049},
            "bad date": {"url": "https://e.com", "system_date": "14/11/2026"},
        }
        for label, kwargs in cases.items():
            with self.subTest(case=label):
                self.mock_client.command.reset_mock()
                result = self.module.submit_to_sandbox(**{**SUBMIT_DEFAULTS, **kwargs})
                self.assertIn("error", result)
                self.mock_client.command.assert_not_called()

    def test_upload_is_always_confidential(self):
        self.mock_client.command.return_value = _ok([{"sha256": SHA, "file_name": "a.exe"}])
        content = base64.b64encode(b"MZ\x90\x00").decode()

        result = self.module.upload_sandbox_sample(
            file_name="a.exe", content_base64=content, comment="from host X"
        )

        self.mock_client.command.assert_called_once_with(
            "UploadSampleV2",
            data={"file_name": "a.exe", "is_confidential": "true", "comment": "from host X"},
            files=[("sample", ("a.exe", b"MZ\x90\x00"))],
        )
        self.assertEqual(result["sha256"], SHA)
        self.assertTrue(result["confidential"])

    def test_upload_validation(self):
        good = base64.b64encode(b"x").decode()
        cases = {
            "path in name": {"file_name": "../etc/passwd", "content_base64": good},
            "empty content": {"file_name": "a", "content_base64": ""},
            "not base64": {"file_name": "a", "content_base64": "%%%"},
            "decodes empty": {"file_name": "a", "content_base64": "===="},
        }
        for label, kwargs in cases.items():
            with self.subTest(case=label):
                self.mock_client.command.reset_mock()
                self.assertIn("error", self.module.upload_sandbox_sample(comment=None, **kwargs))
                self.mock_client.command.assert_not_called()

    def test_upload_size_cap(self):
        original = sandbox.MAX_UPLOAD_BYTES
        sandbox.MAX_UPLOAD_BYTES = 10
        try:
            content = base64.b64encode(b"x" * 10).decode()
            result = self.module.upload_sandbox_sample(
                file_name="a", content_base64=content, comment=None
            )
        finally:
            sandbox.MAX_UPLOAD_BYTES = original
        self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_deletes(self):
        self.mock_client.command.return_value = {"status_code": 200, "body": {}}

        self.assertTrue(self.module.delete_sandbox_report(report_id=REPORT)["deleted"])
        self.mock_client.command.assert_called_with("DeleteReport", parameters={"ids": REPORT})
        self.assertTrue(self.module.delete_sandbox_sample(sha256=SHA.upper())["deleted"])
        self.mock_client.command.assert_called_with("DeleteSampleV2", parameters={"ids": SHA})

        self.mock_client.command.reset_mock()
        self.assertIn("error", self.module.delete_sandbox_report(report_id="x"))
        self.assertIn("error", self.module.delete_sandbox_sample(sha256="x"))
        self.mock_client.command.assert_not_called()

    def test_delete_forbidden_names_the_write_scope(self):
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied"}]},
        }
        result = self.module.delete_sandbox_sample(sha256=SHA)
        self.assertEqual(result["required_scopes"], ["Sandbox (Falcon Intelligence):write"])


if __name__ == "__main__":
    unittest.main()
