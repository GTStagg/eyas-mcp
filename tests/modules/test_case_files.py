"""
Tests for collecting files from hosts into cases, and deleting RTR session files.
"""

import unittest

from mcp.types import ToolAnnotations

from falcon_mcp.modules.cases import CasesModule
from falcon_mcp.modules.rtr import RTRModule
from tests.modules.utils.test_modules import TestModules

AID = "a" * 32
SHA = "b" * 64
SESSION = "11111111-2222-3333-4444-555555555555"
CASE = "019f449a-0000-7000-8000-000000000000"
PATH = "C:\\Users\\Public\\update.exe"


def _ok(resources, status=200):
    return {"status_code": status, "body": {"resources": resources, "errors": []}}


class TestCaseFiles(TestModules):
    """The case file tools in the cases module."""

    def setUp(self):
        self.setup_module(CasesModule)

    def test_annotations(self):
        self.module.register_tools(self.mock_server)
        self.assert_tool_annotations(
            "falcon_get_rtr_file_metadata",
            ToolAnnotations(
                readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
            ),
        )
        for name in ("falcon_retrieve_rtr_file_to_case", "falcon_add_rtr_session_file_to_case"):
            with self.subTest(tool=name):
                self.assert_tool_annotations(
                    name,
                    ToolAnnotations(
                        readOnlyHint=False,
                        destructiveHint=False,
                        idempotentHint=False,
                        openWorldHint=True,
                    ),
                )

    def test_search_case_files_scopes_to_the_case(self):
        files = [{"id": "f1", "name": "a.exe", "hash_value": SHA}]
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": files, "meta": {"pagination": {"total": 1}}},
        }

        result = self.module.search_case_files(
            case_id=CASE, filter="name:*'*.exe',name:*'*.dll'", limit=1, offset=0
        )

        self.mock_client.command.assert_called_once_with(
            "combined_file_details_get_v1",
            parameters={
                "limit": 1,
                "offset": 0,
                "filter": f"case_id:'{CASE}'+(name:*'*.exe',name:*'*.dll')",
            },
        )
        self.assertEqual(result["results"], files)
        # The API's total echoes the page size, so it isn't passed on
        self.assertIsNone(result["pagination"]["total"])
        self.assertEqual(result["pagination"]["next_offset"], 1)

    def test_search_case_files_without_scope_and_bad_case_id(self):
        self.mock_client.command.return_value = _ok([])
        result = self.module.search_case_files(case_id=None, filter=None, limit=50, offset=0)
        self.assertEqual(
            self.mock_client.command.call_args[1]["parameters"], {"limit": 50, "offset": 0}
        )
        self.assertIsNone(result["pagination"]["next_offset"])

        self.mock_client.command.reset_mock()
        result = self.module.search_case_files(case_id="x' OR '1", filter=None, limit=50, offset=0)
        self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_metadata_request(self):
        self.mock_client.command.return_value = _ok([{"file_path": PATH, "size": 10}])

        result = self.module.get_rtr_file_metadata(device_id=AID.upper(), file_path=f" {PATH} ")

        self.mock_client.command.assert_called_once_with(
            "entities_get_rtr_file_metadata_post_v1", body={"aid": AID, "file_path": PATH}
        )
        self.assertEqual(result[0]["size"], 10)

    def test_retrieve_to_case(self):
        self.mock_client.command.return_value = _ok([{"id": "f1"}])

        self.module.retrieve_rtr_file_to_case(
            case_id=CASE, device_id=AID, file_path=PATH, description="dropper"
        )

        self.mock_client.command.assert_called_once_with(
            "entities_retrieve_rtr_file_post_v1",
            body={"case_id": CASE, "aid": AID, "file_path": PATH, "description": "dropper"},
        )

    def test_add_session_file_to_case(self):
        self.mock_client.command.return_value = _ok([{"id": "f1"}])

        self.module.add_rtr_session_file_to_case(
            case_id=CASE, device_id=AID, session_id=SESSION.upper(), sha256=SHA.upper(),
            description=None,
        )

        self.mock_client.command.assert_called_once_with(
            "entities_retrieve_rtr_recent_file_post_v1",
            body={"case_id": CASE, "aid": AID, "session_id": SESSION, "sha256": SHA},
        )

    def test_inputs_are_checked_before_any_call(self):
        calls = [
            lambda: self.module.get_rtr_file_metadata(device_id="host-01", file_path=PATH),
            lambda: self.module.get_rtr_file_metadata(device_id=AID, file_path="C:\\a\nb"),
            lambda: self.module.get_rtr_file_metadata(device_id=AID, file_path="  "),
            lambda: self.module.retrieve_rtr_file_to_case(
                case_id="", device_id=AID, file_path=PATH, description=None
            ),
            lambda: self.module.retrieve_rtr_file_to_case(
                case_id=CASE, device_id=AID, file_path="x" * 1025, description=None
            ),
            lambda: self.module.add_rtr_session_file_to_case(
                case_id=CASE, device_id=AID, session_id="nope", sha256=SHA, description=None
            ),
            lambda: self.module.add_rtr_session_file_to_case(
                case_id=CASE, device_id=AID, session_id=SESSION, sha256="md5", description=None
            ),
        ]
        for index, call in enumerate(calls):
            with self.subTest(case=index):
                self.assertIn("error", call())
        self.mock_client.command.assert_not_called()

    def test_retrieve_forbidden_names_the_scope(self):
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied"}]},
        }
        result = self.module.retrieve_rtr_file_to_case(
            case_id=CASE, device_id=AID, file_path=PATH, description=None
        )
        self.assertEqual(result["required_scopes"], ["Cases:write"])


class TestDeleteSessionFile(TestModules):
    """falcon_delete_rtr_session_file in the RTR module."""

    def setUp(self):
        self.setup_module(RTRModule)

    def test_annotation(self):
        self.module.register_tools(self.mock_server)
        self.assert_tool_annotations(
            "falcon_delete_rtr_session_file",
            ToolAnnotations(
                readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True
            ),
        )

    def test_delete(self):
        self.mock_client.command.return_value = {"status_code": 204, "body": {}}

        result = self.module.delete_session_file(session_id=SESSION, file_id="file-1")

        self.mock_client.command.assert_called_once_with(
            "RTR_DeleteFileV2", parameters={"session_id": SESSION, "ids": "file-1"}
        )
        self.assertTrue(result["deleted"])

    def test_bad_ids_and_failure(self):
        self.assertIn("error", self.module.delete_session_file(session_id="a b", file_id="f"))
        self.assertIn("error", self.module.delete_session_file(session_id=SESSION, file_id=""))
        self.mock_client.command.assert_not_called()

        self.mock_client.command.return_value = {
            "status_code": 404,
            "body": {"errors": [{"message": "not found"}]},
        }
        self.assertIn("error", self.module.delete_session_file(session_id=SESSION, file_id="f"))


if __name__ == "__main__":
    unittest.main()
