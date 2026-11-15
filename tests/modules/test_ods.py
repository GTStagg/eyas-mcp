"""
Tests for the ODS (on-demand scans) module.
"""

import unittest

from mcp.types import ToolAnnotations

from falcon_mcp.modules.ods import OdsModule
from tests.modules.utils.test_modules import TestModules

AID = "a" * 32
GROUP = "b" * 32
SCAN = "c" * 32


def _ok(resources, total=None, status=200):
    body = {"resources": resources, "errors": []}
    if total is not None:
        body["meta"] = {"pagination": {"offset": 0, "limit": 20, "total": total}}
    return {"status_code": status, "body": body}


START_DEFAULTS = {
    "hosts": None,
    "host_groups": None,
    "file_paths": None,
    "mac_file_paths": None,
    "exclusions": None,
    "mac_exclusions": None,
    "quarantine": False,
    "ml_level": 2,
    "cpu_priority": 1,
    "endpoint_notification": True,
    "description": None,
}


class TestOdsModule(TestModules):
    """Test cases for the ODS module."""

    def setUp(self):
        self.setup_module(OdsModule)

    def test_register_tools(self):
        self.assert_tools_registered(
            [
                "falcon_search_ods_scans",
                "falcon_search_ods_scan_hosts",
                "falcon_search_ods_malicious_files",
                "falcon_search_ods_scheduled_scans",
                "falcon_start_ods_scan",
                "falcon_cancel_ods_scans",
                "falcon_delete_ods_scheduled_scans",
            ]
        )

    def test_write_annotations(self):
        self.module.register_tools(self.mock_server)
        for name, destructive in (
            ("falcon_start_ods_scan", True),
            ("falcon_cancel_ods_scans", False),
            ("falcon_delete_ods_scheduled_scans", True),
        ):
            with self.subTest(tool=name):
                self.assert_tool_annotations(
                    name,
                    ToolAnnotations(
                        readOnlyHint=False,
                        destructiveHint=destructive,
                        idempotentHint=name != "falcon_start_ods_scan",
                        openWorldHint=True,
                    ),
                )

    # --- searches ------------------------------------------------------------

    def test_search_scans_drops_policy_arrays_and_keeps_order(self):
        self.mock_client.command.side_effect = [
            _ok(["s1", "s2"], total=2),
            _ok(
                [
                    {"id": "s2", "status": "running", "policy_setting": [1] * 39},
                    {"id": "s1", "status": "completed", "mac_policy_setting": [1] * 19},
                ]
            ),
        ]

        result = self.module.search_ods_scans(
            filter="status:'completed'", limit=20, offset=None, sort="created_on|desc"
        )

        query, details = self.mock_client.command.call_args_list
        self.assertEqual(query[0][0], "query_scans")
        self.assertEqual(query[1]["parameters"]["sort"], "created_on|desc")
        self.assertEqual(details[0][0], "get_scans_by_scan_ids_v2")
        self.assertEqual([r["id"] for r in result["results"]], ["s1", "s2"])
        self.assertNotIn("policy_setting", result["results"][1])
        self.assertNotIn("mac_policy_setting", result["results"][0])

    def test_each_search_uses_its_own_operations(self):
        cases = (
            (self.module.search_ods_scan_hosts, "query_scan_host_metadata", "get_scan_host_metadata_by_ids"),
            (self.module.search_ods_malicious_files, "query_malicious_files", "get_malicious_files_by_ids"),
            (self.module.search_ods_scheduled_scans, "query_scheduled_scans", "get_scheduled_scans_by_scan_ids"),
        )
        for tool, query_op, get_op in cases:
            with self.subTest(query=query_op):
                self.mock_client.command.reset_mock()
                self.mock_client.command.side_effect = [_ok(["x"], total=1), _ok([{"id": "x"}])]
                result = tool(filter=None, limit=10, offset=None, sort=None)
                ops = [c[0][0] for c in self.mock_client.command.call_args_list]
                self.assertEqual(ops, [query_op, get_op])
                self.assertEqual(result["results"], [{"id": "x"}])

    def test_empty_search_makes_one_call(self):
        self.mock_client.command.return_value = _ok([], total=0)
        result = self.module.search_ods_malicious_files(filter=None, limit=10, offset=None, sort=None)
        self.assertEqual(result["results"], [])
        self.assertEqual(self.mock_client.command.call_count, 1)

    # --- start_ods_scan ------------------------------------------------------

    def test_start_scan_body(self):
        self.mock_client.command.return_value = _ok([{"id": SCAN, "status": "pending"}])

        result = self.module.start_ods_scan(
            **{
                **START_DEFAULTS,
                "hosts": [AID.upper(), AID],
                "file_paths": ["C:\\Users\\**"],
                "exclusions": ["C:\\Users\\*\\AppData\\**"],
                "description": " sweep ",
            }
        )

        self.mock_client.command.assert_called_once_with(
            "create_scan",
            body={
                "quarantine": False,
                "cpu_priority": 1,
                "endpoint_notification": True,
                "sensor_ml_level_detection": 2,
                "sensor_ml_level_prevention": 2,
                "cloud_ml_level_detection": 2,
                "cloud_ml_level_prevention": 2,
                "hosts": [AID],
                "file_paths": ["C:\\Users\\**"],
                "scan_exclusions": ["C:\\Users\\*\\AppData\\**"],
                "description": "sweep",
            },
        )
        self.assertEqual(result[0]["id"], SCAN)

    def test_start_scan_mac_paths_and_groups(self):
        self.mock_client.command.return_value = _ok([{"id": SCAN}])

        self.module.start_ods_scan(
            **{
                **START_DEFAULTS,
                "host_groups": [GROUP],
                "mac_file_paths": ["/Users/**"],
                "mac_exclusions": ["/Users/*/Library/**"],
                "quarantine": True,
                "ml_level": 3,
            }
        )

        body = self.mock_client.command.call_args[1]["body"]
        self.assertEqual(body["host_groups"], [GROUP])
        self.assertEqual(body["mac_scan_inclusions"], ["/Users/**"])
        self.assertEqual(body["mac_scan_exclusions"], ["/Users/*/Library/**"])
        self.assertEqual(body["mac_cloud_ml_level_prevention"], 3)
        self.assertTrue(body["quarantine"])
        self.assertNotIn("file_paths", body)
        self.assertNotIn("hosts", body)

    def test_start_scan_validation(self):
        cases = {
            "no targets": {"file_paths": ["C:\\**"]},
            "no paths": {"hosts": [AID]},
            "bad host": {"hosts": ["WS-01"], "file_paths": ["C:\\**"]},
            "bad group": {"host_groups": ["group name"], "file_paths": ["C:\\**"]},
            "control char": {"hosts": [AID], "file_paths": ["C:\\a\nb"]},
            "too many paths": {"hosts": [AID], "file_paths": [f"C:\\{i}" for i in range(51)]},
            "too many hosts": {"hosts": [f"{i:032x}" for i in range(501)], "file_paths": ["C:\\**"]},
        }
        for label, kwargs in cases.items():
            with self.subTest(case=label):
                self.mock_client.command.reset_mock()
                result = self.module.start_ods_scan(**{**START_DEFAULTS, **kwargs})
                self.assertIn("error", result)
                self.mock_client.command.assert_not_called()

    def test_start_scan_forbidden_names_the_write_scope(self):
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied"}]},
        }
        result = self.module.start_ods_scan(**{**START_DEFAULTS, "hosts": [AID], "file_paths": ["C:\\**"]})
        self.assertEqual(result["required_scopes"], ["On-demand scans (ODS):write"])

    # --- cancel / delete -----------------------------------------------------

    def test_cancel_and_delete(self):
        self.mock_client.command.return_value = _ok([SCAN])

        self.module.cancel_ods_scans(ids=[SCAN.upper()])
        self.mock_client.command.assert_called_with("cancel_scans", body={"ids": [SCAN]})

        self.module.delete_ods_scheduled_scans(ids=[SCAN])
        self.mock_client.command.assert_called_with(
            "delete_scheduled_scans", parameters={"ids": [SCAN]}
        )

    def test_cancel_and_delete_need_ids(self):
        for tool in (self.module.cancel_ods_scans, self.module.delete_ods_scheduled_scans):
            for ids in ([], ["not-an-id"]):
                with self.subTest(tool=tool.__name__, ids=ids):
                    self.assertIn("error", tool(ids=ids))
        self.mock_client.command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
