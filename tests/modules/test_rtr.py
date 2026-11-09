"""
Tests for the RTR module.
"""

import json
from typing import Any
from unittest.mock import patch

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from falcon_mcp.modules import rtr
from falcon_mcp.modules.base import READ_ONLY_ANNOTATIONS
from falcon_mcp.modules.rtr import RTRModule
from falcon_mcp.resources.rtr import READ_ONLY_RTR_INVESTIGATION_GUIDE
from tests.modules.utils.test_modules import TestModules


class TestRTRModule(TestModules):
    """Test cases for the RTR module."""

    def setUp(self):
        """Set up test fixtures."""
        self.setup_module(RTRModule)

    def test_register_tools(self):
        """Test registering tools with the server."""
        expected_tools = [
            "falcon_search_rtr_sessions",
            "falcon_search_rtr_audit_sessions",
            "falcon_aggregate_rtr_sessions",
            "falcon_get_rtr_session_details",
            "falcon_init_rtr_session",
            "falcon_pulse_rtr_session",
            "falcon_execute_rtr_read_only_command",
            "falcon_run_rtr_read_only_command_and_wait",
            "falcon_run_rtr_read_only_command_on_hosts",
            "falcon_list_falcon_scripts",
            "falcon_run_falcon_script",
            "falcon_check_rtr_command_status",
            "falcon_list_rtr_session_files",
            "falcon_delete_rtr_session",
            "falcon_wait_for_rtr_sessions",
            "falcon_search_rtr_scripts",
            "falcon_create_rtr_script",
            "falcon_delete_rtr_scripts",
            "falcon_run_rtr_script_on_hosts",
            "falcon_check_rtr_admin_command_status",
        ]
        self.assert_tools_registered(expected_tools)

    def test_tool_annotations(self):
        """Test tool annotations are correctly set."""
        self.module.register_tools(self.mock_server)

        self.assert_tool_annotations("falcon_search_rtr_sessions", READ_ONLY_ANNOTATIONS)
        self.assert_tool_annotations("falcon_search_rtr_audit_sessions", READ_ONLY_ANNOTATIONS)
        self.assert_tool_annotations("falcon_aggregate_rtr_sessions", READ_ONLY_ANNOTATIONS)
        self.assert_tool_annotations("falcon_get_rtr_session_details", READ_ONLY_ANNOTATIONS)
        self.assert_tool_annotations(
            "falcon_init_rtr_session",
            ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )
        self.assert_tool_annotations(
            "falcon_pulse_rtr_session",
            ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )
        self.assert_tool_annotations(
            "falcon_execute_rtr_read_only_command",
            ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )
        self.assert_tool_annotations(
            "falcon_run_rtr_read_only_command_and_wait",
            ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )
        self.assert_tool_annotations("falcon_list_falcon_scripts", READ_ONLY_ANNOTATIONS)
        for name in ("falcon_run_falcon_script", "falcon_run_rtr_read_only_command_on_hosts"):
            self.assert_tool_annotations(
                name,
                ToolAnnotations(
                    readOnlyHint=False,
                    destructiveHint=False,
                    idempotentHint=False,
                    openWorldHint=True,
                ),
            )
        self.assert_tool_annotations("falcon_check_rtr_command_status", READ_ONLY_ANNOTATIONS)
        self.assert_tool_annotations("falcon_list_rtr_session_files", READ_ONLY_ANNOTATIONS)
        self.assert_tool_annotations(
            "falcon_delete_rtr_session",
            ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

    def test_register_resources(self):
        """Test registering resources with the server."""
        expected_resources = [
            "falcon_search_rtr_sessions_fql_guide",
            "falcon_search_rtr_audit_sessions_fql_guide",
            "falcon_aggregate_rtr_sessions_guide",
            "falcon_rtr_read_only_investigation_guide",
        ]
        self.assert_resources_registered(expected_resources)

    def test_search_sessions_returns_full_details(self):
        """Test searching RTR sessions fetches details after IDs are returned."""
        search_response = {
            "status_code": 200,
            "body": {
                "resources": ["session-1", "session-2"],
                "meta": {"pagination": {"offset": 0, "limit": 25, "total": 2}},
            },
        }
        details_response = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "session-1", "aid": "aid-1"},
                    {"id": "session-2", "aid": "aid-2"},
                ]
            },
        }
        self.mock_client.command.side_effect = [search_response, details_response]

        result = self.module.search_sessions(
            filter="hostname:'BRR-WB-LIB-22'",
            limit=25,
            offset=0,
            sort="created_at.desc",
        )

        self.assertEqual(self.mock_client.command.call_count, 2)
        first_call = self.mock_client.command.call_args_list[0]
        second_call = self.mock_client.command.call_args_list[1]

        self.assertEqual(first_call[0][0], "RTR_ListAllSessions")
        self.assertEqual(first_call[1]["parameters"]["filter"], "hostname:'BRR-WB-LIB-22'")
        self.assertEqual(first_call[1]["parameters"]["limit"], 25)
        self.assertEqual(first_call[1]["parameters"]["offset"], 0)
        self.assertEqual(first_call[1]["parameters"]["sort"], "created_at.desc")

        self.assertEqual(second_call[0][0], "RTR_ListSessions")
        self.assertEqual(second_call[1]["body"]["ids"], ["session-1", "session-2"])

        self.assertIn("results", result)
        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(result["results"][0]["id"], "session-1")
        self.assertEqual(result["pagination"]["total"], 2)

    def test_search_sessions_reorders_to_match_sorted_ids(self):
        """When RTR_ListSessions returns sessions out of order, the result is
        reordered to match the sorted ID order from RTR_ListAllSessions."""
        search_response = {
            "status_code": 200,
            "body": {"resources": ["session-b", "session-a"]},
        }
        details_response = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "session-a", "aid": "aid-1"},
                    {"id": "session-b", "aid": "aid-2"},
                ]
            },
        }
        self.mock_client.command.side_effect = [search_response, details_response]

        result = self.module.search_sessions(
            filter=None,
            limit=25,
            offset=0,
            sort="created_at.desc",
        )

        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(result["results"][0]["id"], "session-b")
        self.assertEqual(result["results"][1]["id"], "session-a")

    def test_search_audit_sessions(self):
        """Test searching RTR audit sessions."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "audit-session-1",
                        "hostname": "BRR-WB-LIB-22",
                        "user_id": "user@example.com",
                    }
                ],
                "meta": {"pagination": {"offset": 0, "limit": 25, "total": 1}},
            },
        }

        result = self.module.search_audit_sessions(
            filter="created_at:>'now-7d'",
            limit=25,
            offset=0,
            sort="created_at|desc",
            with_command_info=True,
        )

        self.mock_client.command.assert_called_once_with(
            "RTRAuditSessions",
            parameters={
                "filter": "created_at:>'now-7d'",
                "limit": 25,
                "offset": 0,
                "sort": "created_at|desc",
                "with_command_info": True,
            },
        )
        self.assertIn("results", result)
        self.assertEqual(result["results"][0]["id"], "audit-session-1")
        self.assertEqual(result["pagination"]["total"], 1)

    def test_search_audit_sessions_error_returns_fql_guide(self):
        """Test audit search with API error returns the RTR audit FQL guide."""
        self.mock_client.command.return_value = {
            "status_code": 400,
            "body": {"errors": [{"message": "Invalid filter"}]},
        }

        result = self.module.search_audit_sessions(
            filter="invalid:::filter",
            limit=10,
            offset=None,
            sort=None,
            with_command_info=False,
        )

        self.assertIsInstance(result, dict)
        self.assertIn("results", result)
        self.assertIn("fql_guide", result)
        self.assertIn("RTR Audit Sessions", result["fql_guide"])
        self.assertIn("Filter error occurred", result["hint"])

    def test_search_audit_sessions_empty_returns_fql_guide(self):
        """Test audit search with no results returns clean empty response."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }

        result = self.module.search_audit_sessions(
            filter="created_at:>'2099-01-01T00:00:00Z'",
            limit=10,
            offset=None,
            sort=None,
            with_command_info=False,
        )

        self.assertIsInstance(result, dict)
        self.assertEqual(result["results"], [])
        self.assertIsNone(result["pagination"]["total"])
        self.assertEqual(result["filter_used"], "created_at:>'2099-01-01T00:00:00Z'")
        self.assertNotIn("fql_guide", result)

    def test_aggregate_sessions_terms(self):
        """Test RTR session terms aggregation."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "name": "commands",
                        "buckets": [{"key": "ps", "count": 5}],
                    }
                ]
            },
        }

        result = self.module.aggregate_sessions(
            field="base_command",
            aggregate_type="terms",
            name="commands",
            filter="created_at:>'now-7d'",
            size=5,
            interval=None,
            date_ranges=None,
        )

        self.mock_client.command.assert_called_once_with(
            "RTR_AggregateSessions",
            body=[
                {
                    "field": "base_command",
                    "filter": "created_at:>'now-7d'",
                    "name": "commands",
                    "size": 5,
                    "type": "terms",
                }
            ],
        )
        self.assertEqual(result[0]["name"], "commands")

    def test_aggregate_sessions_date_range(self):
        """Test RTR session date range aggregation."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "name": "activity_by_day",
                        "buckets": [{"key": "now-7d_now", "count": 3}],
                    }
                ]
            },
        }

        result = self.module.aggregate_sessions(
            field="created_at",
            aggregate_type="date_range",
            name="activity_by_day",
            filter=None,
            size=None,
            interval="day",
            date_ranges=[{"from": "now-7d", "to": "now"}],
        )

        self.mock_client.command.assert_called_once_with(
            "RTR_AggregateSessions",
            body=[
                {
                    "date_ranges": [{"from": "now-7d", "to": "now"}],
                    "field": "created_at",
                    "interval": "day",
                    "name": "activity_by_day",
                    "type": "date_range",
                }
            ],
        )
        self.assertEqual(result[0]["name"], "activity_by_day")

    def test_get_session_details_empty_ids(self):
        """Test get_session_details returns early for empty input."""
        result = self.module.get_session_details(ids=[])

        self.assertEqual(result, [])
        self.mock_client.command.assert_not_called()

    def test_init_session(self):
        """Test RTR session initialization."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"session_id": "session-1"}]},
        }

        result = self.module.init_session(
            device_id="aid-123",
            origin="eyas-mcp",
            queue_offline=True,
            timeout=30,
            timeout_duration="30s",
        )

        self.mock_client.command.assert_called_once_with(
            "RTR_InitSession",
            parameters={
                "timeout": 30,
                "timeout_duration": "30s",
            },
            body={
                "device_id": "aid-123",
                "origin": "eyas-mcp",
                "queue_offline": True,
            },
        )
        self.assertEqual(result[0]["session_id"], "session-1")

    def test_execute_read_only_command(self):
        """Test RTR read-only command execution."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"cloud_request_id": "req-123"}]},
        }

        result = self.module.execute_read_only_command(
            session_id="session-1",
            base_command="cat",
            command_string=r"cat C:\Windows\win.ini",
            persist=False,
        )

        self.mock_client.command.assert_called_once_with(
            "RTR_ExecuteCommand",
            body={
                "session_id": "session-1",
                "base_command": "cat",
                "command_string": r"cat C:\Windows\win.ini",
                "persist": False,
            },
        )
        self.assertEqual(result[0]["cloud_request_id"], "req-123")

    def test_run_read_only_command_and_wait(self):
        """Test RTR read-only command execution with status polling."""
        execute_response = {
            "status_code": 200,
            "body": {"resources": [{"cloud_request_id": "req-123", "session_id": "session-1"}]},
        }
        status_response = {
            "status_code": 200,
            "body": {"resources": [{"complete": True, "stdout": "ok"}]},
        }
        self.mock_client.command.side_effect = [execute_response, status_response]

        result = self.module.run_read_only_command_and_wait(
            session_id="session-1",
            base_command="cat",
            command_string=r"cat C:\Windows\win.ini",
            persist=False,
            timeout_seconds=1,
            poll_interval_seconds=0,
        )

        self.assertEqual(self.mock_client.command.call_count, 2)
        self.mock_client.command.assert_any_call(
            "RTR_ExecuteCommand",
            body={
                "session_id": "session-1",
                "base_command": "cat",
                "command_string": r"cat C:\Windows\win.ini",
                "persist": False,
            },
        )
        self.mock_client.command.assert_any_call(
            "RTR_CheckCommandStatus",
            parameters={"cloud_request_id": "req-123", "sequence_id": 0},
        )
        self.assertEqual(result["cloud_request_id"], "req-123")
        self.assertTrue(result["complete"])
        self.assertFalse(result["timed_out"])
        self.assertEqual(result["stdout"], "ok")

    def test_run_read_only_command_and_wait_advances_sequence_chunks(self):
        """Test command-and-wait reads sequence_id from response for next poll."""
        execute_response = {
            "status_code": 200,
            "body": {"resources": [{"cloud_request_id": "req-123", "session_id": "session-1"}]},
        }
        first_chunk_response = {
            "status_code": 200,
            "body": {"resources": [{"complete": False, "stdout": "part1", "sequence_id": 3}]},
        }
        second_chunk_response = {
            "status_code": 200,
            "body": {"resources": [{"complete": True, "stdout": "part2"}]},
        }
        self.mock_client.command.side_effect = [
            execute_response,
            first_chunk_response,
            second_chunk_response,
        ]

        result = self.module.run_read_only_command_and_wait(
            session_id="session-1",
            base_command="cat",
            command_string=r"cat C:\Windows\win.ini",
            persist=False,
            timeout_seconds=1,
            poll_interval_seconds=0,
        )

        self.mock_client.command.assert_any_call(
            "RTR_CheckCommandStatus",
            parameters={"cloud_request_id": "req-123", "sequence_id": 0},
        )
        self.mock_client.command.assert_any_call(
            "RTR_CheckCommandStatus",
            parameters={"cloud_request_id": "req-123", "sequence_id": 3},
        )
        self.assertEqual(result["stdout"], "part1part2")
        self.assertTrue(result["complete"])

    def test_run_read_only_command_and_wait_execute_error(self):
        """Test command-and-wait returns execute phase on execute failure."""
        self.mock_client.command.return_value = {
            "status_code": 400,
            "body": {"errors": [{"message": "Session ID is invalid"}]},
        }

        result = self.module.run_read_only_command_and_wait(
            session_id="not-a-real-session",
            base_command="ps",
            command_string="ps",
            persist=False,
            timeout_seconds=1,
            poll_interval_seconds=0,
        )

        self.assertIsInstance(result, dict)
        self.assertIn("error", result)
        self.assertEqual(result["phase"], "execute")

    def test_run_read_only_command_and_wait_timeout(self):
        """Test command-and-wait returns partial status on timeout."""
        execute_response = {
            "status_code": 200,
            "body": {"resources": [{"cloud_request_id": "req-123", "session_id": "session-1"}]},
        }
        status_response = {
            "status_code": 200,
            "body": {"resources": [{"complete": False, "stdout": ""}]},
        }
        self.mock_client.command.side_effect = [execute_response, status_response]

        result = self.module.run_read_only_command_and_wait(
            session_id="session-1",
            base_command="ps",
            command_string="ps",
            persist=False,
            timeout_seconds=0,
            poll_interval_seconds=0,
        )

        self.assertEqual(result["cloud_request_id"], "req-123")
        self.assertFalse(result["complete"])
        self.assertTrue(result["timed_out"])
        self.assertIn("warning", result)

    def test_check_command_status(self):
        """Test retrieving RTR command status."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"complete": True, "stdout": "ok"}]},
        }

        result = self.module.check_command_status(
            cloud_request_id="req-123",
            sequence_id=1,
        )

        self.mock_client.command.assert_called_once_with(
            "RTR_CheckCommandStatus",
            parameters={"cloud_request_id": "req-123", "sequence_id": 1},
        )
        self.assertTrue(result[0]["complete"])

    def test_list_session_files(self):
        """Test listing RTR session files."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"sha256": "abc"}]},
        }

        result = self.module.list_session_files(session_id="session-1")

        self.mock_client.command.assert_called_once_with(
            "RTR_ListFilesV2",
            parameters={"session_id": "session-1"},
        )
        self.assertEqual(result[0]["sha256"], "abc")

    def test_delete_session(self):
        """Test deleting an RTR session."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"session_id": "session-1", "deleted": True}]},
        }

        result = self.module.delete_session(session_id="session-1")

        self.mock_client.command.assert_called_once_with(
            "RTR_DeleteSession",
            parameters={"session_id": "session-1"},
        )
        self.assertTrue(result[0]["deleted"])

    def test_search_sessions_error_returns_fql_guide(self):
        """Test searching RTR sessions with API error returns FQL guide."""
        mock_response = {
            "status_code": 400,
            "body": {"errors": [{"message": "Invalid filter"}]},
        }
        self.mock_client.command.return_value = mock_response

        result = self.module.search_sessions(
            filter="invalid:::filter",
            limit=10,
            offset=None,
            sort=None,
        )

        self.assertIsInstance(result, dict)
        self.assertIn("results", result)
        self.assertIn("fql_guide", result)
        self.assertIn("hint", result)
        self.assertIn("Filter error occurred", result["hint"])

    def test_search_sessions_empty_returns_fql_guide(self):
        """Test searching RTR sessions with no results returns clean empty response."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }

        result = self.module.search_sessions(
            filter="hostname:'nonexistent'",
            limit=10,
            offset=None,
            sort=None,
        )

        self.assertIsInstance(result, dict)
        self.assertEqual(result["results"], [])
        self.assertIsNone(result["pagination"]["total"])
        self.assertEqual(result["filter_used"], "hostname:'nonexistent'")
        self.assertNotIn("fql_guide", result)

    def test_search_sessions_with_special_characters_in_filter(self):
        """Test that special characters in filter are passed through safely."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }

        filter_with_special = "hostname:'test';DROP TABLE--"
        self.module.search_sessions(
            filter=filter_with_special,
            limit=10,
            offset=None,
            sort=None,
        )

        call_args = self.mock_client.command.call_args
        self.assertEqual(call_args[1]["parameters"]["filter"], filter_with_special)

    def test_search_sessions_with_long_filter_value(self):
        """Test that extremely long filter values are passed through to the API."""
        long_value = "a" * 10000
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }

        self.module.search_sessions(
            filter=f"hostname:'{long_value}'",
            limit=10,
            offset=None,
            sort=None,
        )

        call_args = self.mock_client.command.call_args
        self.assertIn(long_value, call_args[1]["parameters"]["filter"])

    def test_execute_command_with_malformed_session_id(self):
        """Test execute_read_only_command with malformed session ID returns API error."""
        self.mock_client.command.return_value = {
            "status_code": 400,
            "body": {"errors": [{"message": "Session ID is invalid"}]},
        }

        result = self.module.execute_read_only_command(
            session_id="not-a-real-session-!!!",
            base_command="ps",
            command_string=None,
            persist=False,
        )

        self.assertIsInstance(result, dict)
        self.assertIn("error", result)

    def test_check_command_status_with_malformed_request_id(self):
        """Test check_command_status with malformed cloud_request_id returns API error."""
        self.mock_client.command.return_value = {
            "status_code": 400,
            "body": {"errors": [{"message": "cloud_request_id must be a uuid string"}]},
        }

        result = self.module.check_command_status(
            cloud_request_id="not-a-uuid-!!!",
            sequence_id=0,
        )

        self.assertIsInstance(result, dict)
        self.assertIn("error", result)

    def test_delete_session_with_malformed_session_id(self):
        """Test delete_session with malformed session ID returns API error."""
        self.mock_client.command.return_value = {
            "status_code": 400,
            "body": {"errors": [{"message": "Session ID is invalid"}]},
        }

        result = self.module.delete_session(session_id="not-a-real-session-!!!")

        self.assertIsInstance(result, dict)
        self.assertIn("error", result)

    def test_init_session_permission_error(self):
        """Test init_session with 403 permission error returns error response."""
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Access denied, authorization failed"}]},
        }

        result = self.module.init_session(
            device_id="aid-123",
            origin="eyas-mcp",
            queue_offline=False,
            timeout=None,
            timeout_duration=None,
        )

        self.assertIsInstance(result, dict)
        self.assertIn("error", result)


AID_ONLINE = "a" * 32
AID_OFFLINE = "b" * 32

CATALOG_IDS_RESPONSE = {"status_code": 200, "body": {"resources": ["id-1", "id-2"]}}
CATALOG_DETAILS_RESPONSE = {
    "status_code": 200,
    "body": {
        "resources": [
            {
                "id": "id-2",
                "name": "RegistryKey",
                "platform": ["windows"],
                "description": "Registry key values",
                "json_input_schema": {"properties": {"Key": {"type": "string"}}},
                "content": "large script body",
            },
            {
                "id": "id-1",
                "name": "Process",
                "platform": ["windows", "mac"],
                "description": "Running processes",
            },
        ]
    },
}
INIT_RESPONSE = {
    "status_code": 201,
    "body": {
        "batch_id": "batch-1",
        "resources": {
            AID_ONLINE: {"session_id": "session-1", "complete": True, "errors": []},
            AID_OFFLINE: {
                "session_id": "",
                "errors": [{"code": 404, "message": "Could not find sensor"}],
            },
        },
    },
}


def _command_response(stdout: str, complete: bool = True) -> dict:
    return {
        "status_code": 201,
        "body": {
            "combined": {
                "resources": {
                    AID_ONLINE: {
                        "session_id": "session-1",
                        "task_id": "task-1",
                        "complete": complete,
                        "stdout": stdout,
                        "stderr": "",
                        "errors": None,
                    }
                }
            }
        },
    }


class TestFalconScripts(TestModules):
    """Falcon script catalog and execution."""

    def setUp(self):
        self.setup_module(RTRModule)

    def _operations_called(self) -> list[str]:
        return [c[0][0] for c in self.mock_client.command.call_args_list]

    def _seed_catalog(self):
        self.module._falcon_script_cache = {
            "Process": {"name": "Process"},
            "RegistryKey": {"name": "RegistryKey"},
        }

    def test_list_falcon_scripts(self):
        self.mock_client.command.side_effect = [CATALOG_IDS_RESPONSE, CATALOG_DETAILS_RESPONSE]

        result = self.module.list_falcon_scripts(platform=None, refresh=False)

        self.mock_client.command.assert_any_call(
            "RTR_ListFalconScripts", parameters={"limit": 100, "offset": 0}
        )
        self.mock_client.command.assert_any_call(
            "RTR_GetFalconScripts", parameters={"ids": ["id-1", "id-2"]}
        )
        self.assertEqual([s["name"] for s in result], ["Process", "RegistryKey"])
        registry_key = result[1]
        self.assertEqual(registry_key["platform"], ["windows"])
        self.assertEqual(registry_key["description"], "Registry key values")
        self.assertIn("json_input_schema", registry_key)
        self.assertNotIn("content", registry_key)

    def test_list_falcon_scripts_is_cached_and_filters_platform(self):
        self.mock_client.command.side_effect = [CATALOG_IDS_RESPONSE, CATALOG_DETAILS_RESPONSE]
        self.module.list_falcon_scripts(platform=None, refresh=False)
        self.mock_client.command.reset_mock()

        result = self.module.list_falcon_scripts(platform="mac", refresh=False)

        self.mock_client.command.assert_not_called()
        self.assertEqual([s["name"] for s in result], ["Process"])

    def test_list_falcon_scripts_error_is_not_cached(self):
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied"}]},
        }

        result = self.module.list_falcon_scripts(platform=None, refresh=False)

        self.assertIn("error", result)
        self.assertIsNone(self.module._falcon_script_cache)

    def test_run_falcon_script(self):
        script_output = {"script": "Process", "result": [{"Name": "lsass.exe"}]}
        self.mock_client.command.side_effect = [
            CATALOG_IDS_RESPONSE,
            CATALOG_DETAILS_RESPONSE,
            INIT_RESPONSE,
            _command_response(json.dumps(script_output)),
        ]

        result = self.module.run_falcon_script(
            script_name="Process",
            device_ids=[AID_ONLINE.upper(), AID_ONLINE, AID_OFFLINE],
            json_input=None,
            timeout_seconds=60,
        )

        self.mock_client.command.assert_any_call(
            "BatchInitSessions",
            parameters={"timeout": 60, "host_timeout_duration": "55s"},
            body={"host_ids": [AID_ONLINE, AID_OFFLINE], "queue_offline": False},
        )
        self.mock_client.command.assert_any_call(
            "BatchAdminCmd",
            parameters={"timeout": 60, "host_timeout_duration": "55s"},
            body={
                "base_command": "falconscript",
                "batch_id": "batch-1",
                "command_string": "falconscript -Name=```Process```",
                "optional_hosts": [AID_ONLINE],
            },
        )
        self.assertEqual(result["script_name"], "Process")
        self.assertEqual(result["hosts_requested"], 2)
        self.assertEqual(result["hosts_with_session"], 1)
        self.assertEqual(result["hosts_completed"], 1)
        self.assertEqual(result["results"][0]["output"], script_output)
        self.assertEqual(result["failed_hosts"][0]["device_id"], AID_OFFLINE)
        self.assertEqual(result["failed_hosts"][0]["phase"], "init")

    def test_run_falcon_script_with_json_input(self):
        self._seed_catalog()
        self.mock_client.command.side_effect = [INIT_RESPONSE, _command_response("not json")]

        result = self.module.run_falcon_script(
            script_name="RegistryKey",
            device_ids=[AID_ONLINE],
            json_input={"Key": "HKLM\\Software\\Run", "Max": 5},
            timeout_seconds=30,
        )

        command = self.mock_client.command.call_args_list[1]
        expected_json = '{"Key":"HKLM\\\\Software\\\\Run","Max":5}'
        self.assertEqual(
            command[1]["body"]["command_string"],
            f"falconscript -Name=```RegistryKey``` -JsonInput=```'{expected_json}'```",
        )
        self.assertEqual(result["results"][0]["stdout"], "not json")

    def test_run_falcon_script_reports_incomplete_hosts(self):
        self._seed_catalog()
        self.mock_client.command.side_effect = [INIT_RESPONSE, _command_response("", False)]

        result = self.module.run_falcon_script(
            script_name="Process", device_ids=[AID_ONLINE], json_input=None, timeout_seconds=30
        )

        self.assertFalse(result["results"][0]["complete"])
        self.assertIn("warning", result["results"][0])
        self.assertEqual(result["hosts_completed"], 0)

    def test_rejects_bad_script_names_without_api_calls(self):
        for name in [
            "",
            "Process`",
            "Process```; rm -rf /",
            "Process\n",
            "Pro cess",
            "1Process",
            "Process'",
            "Process\x00",
            "P" * 65,
        ]:
            with self.subTest(name=name):
                result = self.module.run_falcon_script(
                    script_name=name, device_ids=[AID_ONLINE], json_input=None, timeout_seconds=30
                )
                self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_rejects_unknown_script_before_opening_sessions(self):
        self._seed_catalog()

        result = self.module.run_falcon_script(
            script_name="Processes", device_ids=[AID_ONLINE], json_input=None, timeout_seconds=30
        )

        self.assertIn("Unknown Falcon script", result["error"])
        self.mock_client.command.assert_not_called()

    def test_unknown_script_fetches_catalog_but_opens_no_session(self):
        self.mock_client.command.side_effect = [CATALOG_IDS_RESPONSE, CATALOG_DETAILS_RESPONSE]

        result = self.module.run_falcon_script(
            script_name="process", device_ids=[AID_ONLINE], json_input=None, timeout_seconds=30
        )

        self.assertIn("error", result)
        self.assertEqual(
            self._operations_called(), ["RTR_ListFalconScripts", "RTR_GetFalconScripts"]
        )

    def test_rejects_injection_in_json_input_without_api_calls(self):
        self._seed_catalog()
        for json_input in [
            {"Key": "a```b"},
            {"Key": "a`b"},
            {"Key": "it's"},
            {"Key": "line\nbreak"},
            {"Key": "carriage\rreturn"},
            {"Key": "nul\x00"},
            {"Key": "tab\there"},
            {"Bad`Key": "value"},
            {"Key": ["nested", {"deep": "x`y"}]},
            {"Key": float("nan")},
            {"Key": object()},
            {"Key": "x" * 5000},
        ]:
            with self.subTest(json_input=repr(json_input)[:40]):
                result = self.module.run_falcon_script(
                    script_name="RegistryKey",
                    device_ids=[AID_ONLINE],
                    json_input=json_input,
                    timeout_seconds=30,
                )
                self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_rejects_bad_device_ids_without_api_calls(self):
        self._seed_catalog()
        too_many = [f"{i:032x}" for i in range(101)]
        for device_ids in [
            [],
            ["not-an-aid"],
            ["a" * 31],
            ["g" * 32],
            [AID_ONLINE + "\n"],
            [AID_ONLINE, "a" * 33],
            [None],
            too_many,
        ]:
            with self.subTest(device_ids=repr(device_ids)[:40]):
                for result in (
                    self.module.run_falcon_script(
                        script_name="Process",
                        device_ids=device_ids,
                        json_input=None,
                        timeout_seconds=30,
                    ),
                    self.module.run_read_only_command_on_hosts(
                        device_ids=device_ids,
                        base_command="ps",
                        command_string=None,
                        timeout_seconds=30,
                    ),
                ):
                    self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_accepts_one_hundred_hosts(self):
        hosts, refusal = rtr._validate_device_ids([f"{i:032x}" for i in range(100)])
        self.assertIsNone(refusal)
        self.assertEqual(len(hosts), 100)

    def test_init_failure_stops_before_command(self):
        self._seed_catalog()
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied"}]},
        }

        result = self.module.run_falcon_script(
            script_name="Process", device_ids=[AID_ONLINE], json_input=None, timeout_seconds=30
        )

        self.assertIn("error", result)
        self.assertEqual(result["phase"], "init")
        self.assertEqual(self._operations_called(), ["BatchInitSessions"])

    def test_all_hosts_offline_runs_nothing(self):
        self._seed_catalog()
        self.mock_client.command.return_value = {
            "status_code": 201,
            "body": {"batch_id": "batch-1", "resources": {}},
        }

        result = self.module.run_falcon_script(
            script_name="Process", device_ids=[AID_OFFLINE], json_input=None, timeout_seconds=30
        )

        self.assertEqual(self._operations_called(), ["BatchInitSessions"])
        self.assertEqual(result["failed_hosts"][0]["device_id"], AID_OFFLINE)
        self.assertIn("warning", result)

    def test_command_failure_is_reported(self):
        self._seed_catalog()
        self.mock_client.command.side_effect = [
            INIT_RESPONSE,
            {"status_code": 500, "body": {"errors": [{"message": "boom"}]}},
        ]

        result = self.module.run_falcon_script(
            script_name="Process", device_ids=[AID_ONLINE], json_input=None, timeout_seconds=30
        )

        self.assertIn("error", result)
        self.assertEqual(result["phase"], "command")
        self.assertEqual(result["batch_id"], "batch-1")


class TestReadOnlyCommandOnHosts(TestModules):
    """Batch read-only RTR commands share the single-host allowlist."""

    def setUp(self):
        self.setup_module(RTRModule)

    def test_run_read_only_command_on_hosts(self):
        self.mock_client.command.side_effect = [INIT_RESPONSE, _command_response('{"a": 1}')]

        result = self.module.run_read_only_command_on_hosts(
            device_ids=[AID_ONLINE, AID_OFFLINE],
            base_command="filehash",
            command_string=r"filehash C:\Windows\System32\cmd.exe",
            timeout_seconds=30,
        )

        self.mock_client.command.assert_any_call(
            "BatchCmd",
            parameters={"timeout": 30, "host_timeout_duration": "25s"},
            body={
                "base_command": "filehash",
                "batch_id": "batch-1",
                "command_string": r"filehash C:\Windows\System32\cmd.exe",
                "optional_hosts": [AID_ONLINE],
            },
        )
        operations = [c[0][0] for c in self.mock_client.command.call_args_list]
        self.assertNotIn("BatchAdminCmd", operations)
        # Plain command output stays text, even when it looks like JSON.
        self.assertEqual(result["results"][0]["stdout"], '{"a": 1}')
        self.assertEqual(result["failed_hosts"][0]["device_id"], AID_OFFLINE)

    def test_command_string_defaults_to_base_command(self):
        self.mock_client.command.side_effect = [INIT_RESPONSE, _command_response("")]

        self.module.run_read_only_command_on_hosts(
            device_ids=[AID_ONLINE], base_command="ps", command_string=None, timeout_seconds=30
        )

        body = self.mock_client.command.call_args_list[1][1]["body"]
        self.assertEqual(body["command_string"], "ps")

    def test_disallowed_commands_are_refused_by_every_read_only_tool(self):
        cases = [
            ("rm", "rm C:\\file"),
            ("runscript", "runscript -Raw=```whoami```"),
            ("put", "put file.exe"),
            ("falconscript", "falconscript -Name=```Process```"),
            ("reg", "reg set HKLM\\Software\\X"),
            ("reg", "reg delete HKLM\\Software\\X"),
            ("reg", "reg"),
            ("ps", "ls C:\\"),
            ("ps", "ps\nrm C:\\file"),
            ("PS", "PS"),
        ]
        for base_command, command_string in cases:
            with self.subTest(command=command_string):
                for result in (
                    self.module.run_read_only_command_on_hosts(
                        device_ids=[AID_ONLINE],
                        base_command=base_command,
                        command_string=command_string,
                        timeout_seconds=30,
                    ),
                    self.module.execute_read_only_command(
                        session_id="session-1",
                        base_command=base_command,
                        command_string=command_string,
                        persist=False,
                    ),
                    self.module.run_read_only_command_and_wait(
                        session_id="session-1",
                        base_command=base_command,
                        command_string=command_string,
                        persist=False,
                        timeout_seconds=1,
                        poll_interval_seconds=0,
                    ),
                ):
                    self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_reg_query_is_allowed(self):
        self.assertIsNone(
            rtr._validate_read_only_command("reg", "reg query HKLM\\Software\\Microsoft")
        )

    def test_every_read_only_tool_uses_the_same_validator(self):
        with patch.object(rtr, "_validate_read_only_command", return_value="refused") as validator:
            results = [
                self.module.run_read_only_command_on_hosts(
                    device_ids=[AID_ONLINE],
                    base_command="ps",
                    command_string="ps",
                    timeout_seconds=30,
                ),
                self.module.execute_read_only_command(
                    session_id="session-1", base_command="ps", command_string="ps", persist=False
                ),
                self.module.run_read_only_command_and_wait(
                    session_id="session-1",
                    base_command="ps",
                    command_string="ps",
                    persist=False,
                    timeout_seconds=1,
                    poll_interval_seconds=0,
                ),
            ]

        self.assertEqual(validator.call_count, 3)
        for args in validator.call_args_list:
            self.assertEqual(args[0], ("ps", "ps"))
        for result in results:
            self.assertEqual(result["error"], "refused")
        self.mock_client.command.assert_not_called()

    def test_guide_lists_the_allowlist(self):
        for command in rtr.READ_ONLY_RTR_COMMANDS:
            self.assertIn(command, READ_ONLY_RTR_INVESTIGATION_GUIDE)


class TestRTRReadOnlyMode(TestModules):
    """Batch tools that open sessions must not survive --read-only."""

    def setUp(self):
        self.setup_module(RTRModule)

    def test_read_only_hint_matches_session_behaviour(self):
        server = FastMCP("rtr")
        self.module.register_tools(server)
        tools = server._tool_manager._tools

        self.assertIs(tools["falcon_list_falcon_scripts"].annotations.readOnlyHint, True)
        self.assertIs(tools["falcon_run_falcon_script"].annotations.readOnlyHint, False)
        self.assertIs(
            tools["falcon_run_rtr_read_only_command_on_hosts"].annotations.readOnlyHint, False
        )


SCRIPT_IDS_RESPONSE = {"status_code": 200, "body": {"resources": ["script-1"]}}
SCRIPT_DETAILS_RESPONSE = {
    "status_code": 200,
    "body": {
        "resources": [
            {
                "id": "script-1",
                "name": "collect-triage",
                "platform": ["windows"],
                "permission_type": "private",
                "content": "Get-Process",
            }
        ]
    },
}
EMPTY_IDS_RESPONSE = {"status_code": 200, "body": {"resources": []}}


class TestRTRCustomScripts(TestModules):
    """Custom script library tools and runscript."""

    def setUp(self):
        self.setup_module(RTRModule)

    def test_registers_custom_script_tools_with_safe_hints(self):
        server = FastMCP("rtr")
        self.module.register_tools(server)
        tools = server._tool_manager._tools

        for name in ("falcon_search_rtr_scripts", "falcon_check_rtr_admin_command_status"):
            self.assertEqual(tools[name].annotations, READ_ONLY_ANNOTATIONS)
        self.assertEqual(
            tools["falcon_create_rtr_script"].annotations,
            ToolAnnotations(
                readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
            ),
        )
        self.assertEqual(
            tools["falcon_delete_rtr_scripts"].annotations,
            ToolAnnotations(
                readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True
            ),
        )
        self.assertEqual(
            tools["falcon_run_rtr_script_on_hosts"].annotations,
            ToolAnnotations(
                readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
            ),
        )

    def test_search_hides_content_by_default(self):
        self.mock_client.command.side_effect = [SCRIPT_IDS_RESPONSE, SCRIPT_DETAILS_RESPONSE]

        result = self.module.search_custom_scripts(
            filter=None, limit=50, offset=None, sort=None, include_content=False
        )

        self.mock_client.command.assert_any_call(
            "RTR_GetScriptsV2", parameters={"ids": ["script-1"]}
        )
        self.assertEqual(result["results"][0]["name"], "collect-triage")
        self.assertNotIn("content", result["results"][0])

    def test_search_can_include_content(self):
        self.mock_client.command.side_effect = [SCRIPT_IDS_RESPONSE, SCRIPT_DETAILS_RESPONSE]

        result = self.module.search_custom_scripts(
            filter="platform:'windows'", limit=50, offset=None, sort=None, include_content=True
        )

        self.assertEqual(result["results"][0]["content"], "Get-Process")

    def test_create_uploads_multipart_and_returns_id(self):
        self.mock_client.command.side_effect = [
            EMPTY_IDS_RESPONSE,
            {"status_code": 200, "body": {"resources": []}},
            SCRIPT_IDS_RESPONSE,
            SCRIPT_DETAILS_RESPONSE,
        ]

        result = self.module.create_custom_script(
            name="collect-triage",
            content="Get-Process",
            platform="windows",
            permission_type="private",
            description=None,
            comments_for_audit_log="triage",
        )

        self.mock_client.command.assert_any_call(
            "RTR_ListScripts", parameters={"filter": "name:'collect-triage'", "limit": 100}
        )
        self.mock_client.command.assert_any_call(
            "RTR_CreateScripts",
            data={
                "name": "collect-triage",
                "platform": "windows",
                "permission_type": "private",
                "comments_for_audit_log": "triage",
            },
            files=[("file", ("collect-triage.ps1", b"Get-Process", "application/script"))],
        )
        self.assertEqual(
            result,
            {
                "created": True,
                "id": "script-1",
                "name": "collect-triage",
                "platform": "windows",
                "permission_type": "private",
            },
        )

    def test_create_refuses_existing_name(self):
        self.mock_client.command.side_effect = [SCRIPT_IDS_RESPONSE, SCRIPT_DETAILS_RESPONSE]

        result = self.module.create_custom_script(
            name="collect-triage",
            content="Get-Process",
            platform="windows",
            permission_type="private",
            description=None,
            comments_for_audit_log=None,
        )

        self.assertIn("already exists", result["error"])
        called = [c[0][0] for c in self.mock_client.command.call_args_list]
        self.assertNotIn("RTR_CreateScripts", called)

    def test_create_rejects_bad_input_without_api_calls(self):
        for name, content in [
            ('bad"name', "x"),
            ("bad name", "x"),
            ("-leading", "x"),
            ("ok", "   "),
            ("ok", "x" * (rtr.MAX_CUSTOM_SCRIPT_BYTES + 1)),
        ]:
            with self.subTest(name=name):
                result = self.module.create_custom_script(
                    name=name,
                    content=content,
                    platform="windows",
                    permission_type="private",
                    description=None,
                    comments_for_audit_log=None,
                )
                self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_delete_reports_each_script(self):
        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {}},
            {"status_code": 404, "body": {"errors": [{"code": 404, "message": "not found"}]}},
        ]

        result = self.module.delete_custom_scripts(ids=["script-1", "script-2", "script-1"])

        self.mock_client.command.assert_any_call(
            "RTR_DeleteScripts", parameters={"ids": "script-1"}
        )
        self.assertEqual(result["deleted"], ["script-1"])
        self.assertEqual(result["failed"][0]["id"], "script-2")
        self.assertIn("error", result["failed"][0]["error"])

    def test_delete_rejects_bad_ids(self):
        result = self.module.delete_custom_scripts(ids=["id&ids=other"])
        self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_run_script_uses_cloudfile(self):
        self.mock_client.command.side_effect = [
            SCRIPT_IDS_RESPONSE,
            SCRIPT_DETAILS_RESPONSE,
            INIT_RESPONSE,
            _command_response("done"),
        ]

        result = self.module.run_custom_script_on_hosts(
            script_name="collect-triage",
            device_ids=[AID_ONLINE, AID_OFFLINE],
            timeout_seconds=60,
        )

        self.mock_client.command.assert_any_call(
            "BatchAdminCmd",
            parameters={"timeout": 60, "host_timeout_duration": "55s"},
            body={
                "base_command": "runscript",
                "batch_id": "batch-1",
                "command_string": 'runscript -CloudFile="collect-triage"',
                "optional_hosts": [AID_ONLINE],
            },
        )
        self.assertEqual(result["script_id"], "script-1")
        self.assertEqual(result["results"][0]["stdout"], "done")
        self.assertEqual(result["failed_hosts"][0]["device_id"], AID_OFFLINE)

    def test_run_script_warns_not_to_rerun_unfinished_hosts(self):
        self.mock_client.command.side_effect = [
            SCRIPT_IDS_RESPONSE,
            SCRIPT_DETAILS_RESPONSE,
            INIT_RESPONSE,
            _command_response("", False),
        ]

        result = self.module.run_custom_script_on_hosts(
            script_name="collect-triage", device_ids=[AID_ONLINE], timeout_seconds=30
        )

        host = result["results"][0]
        self.assertEqual(host["task_id"], "task-1")
        self.assertIn("falcon_check_rtr_admin_command_status", host["warning"])
        self.assertIn("don't run the script again", host["warning"])

    def test_run_script_refuses_unknown_script(self):
        self.mock_client.command.side_effect = [EMPTY_IDS_RESPONSE]

        result = self.module.run_custom_script_on_hosts(
            script_name="missing", device_ids=[AID_ONLINE], timeout_seconds=30
        )

        self.assertIn("No custom script", result["error"])
        called = [c[0][0] for c in self.mock_client.command.call_args_list]
        self.assertNotIn("BatchInitSessions", called)

    def test_run_script_ignores_name_prefix_matches(self):
        self.mock_client.command.side_effect = [SCRIPT_IDS_RESPONSE, SCRIPT_DETAILS_RESPONSE]

        result = self.module.run_custom_script_on_hosts(
            script_name="collect", device_ids=[AID_ONLINE], timeout_seconds=30
        )

        self.assertIn("No custom script", result["error"])

    def test_run_script_rejects_injection_without_api_calls(self):
        for name in ['x" ; reboot', "x'", "x`", "x\n", "", "a b"]:
            with self.subTest(name=name):
                result = self.module.run_custom_script_on_hosts(
                    script_name=name, device_ids=[AID_ONLINE], timeout_seconds=30
                )
                self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_check_admin_command_status(self):
        self.mock_client.command.side_effect = [
            {
                "status_code": 200,
                "body": {"resources": [{"complete": True, "stdout": "ok", "stderr": ""}]},
            },
            {"status_code": 200, "body": {"resources": [{"complete": False}]}},
        ]

        result = self.module.check_admin_command_status(cloud_request_ids=["task-1", "task-2"])

        self.mock_client.command.assert_any_call(
            "RTR_CheckAdminCommandStatus",
            parameters={"cloud_request_id": "task-1", "sequence_id": 0},
        )
        self.assertEqual(result["requested"], 2)
        self.assertEqual(result["complete"], 1)
        self.assertEqual(result["results"][0]["stdout"], "ok")
        self.assertFalse(result["results"][1]["complete"])


class TestRTRWaitForSessions(TestModules):
    """falcon_wait_for_rtr_sessions retries until hosts connect or time runs out."""

    def setUp(self):
        self.setup_module(RTRModule)

    def _init(self, connected: list[str], failed: list[str]) -> dict:
        resources: dict[str, dict[str, Any]] = {
            aid: {"session_id": f"s-{aid[0]}", "errors": []} for aid in connected
        }
        resources.update(
            {aid: {"session_id": "", "errors": [{"code": 404, "message": "x"}]} for aid in failed}
        )
        return {"status_code": 201, "body": {"batch_id": "b", "resources": resources}}

    def test_has_write_hints(self):
        server = FastMCP("rtr")
        self.module.register_tools(server)
        self.assertEqual(
            server._tool_manager._tools["falcon_wait_for_rtr_sessions"].annotations,
            ToolAnnotations(
                readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
            ),
        )

    @patch("falcon_mcp.modules.rtr.time.sleep")
    def test_retries_only_hosts_not_ready(self, mock_sleep):
        self.mock_client.command.side_effect = [
            self._init([AID_ONLINE], [AID_OFFLINE]),
            self._init([AID_OFFLINE], []),
        ]

        result = self.module.wait_for_sessions(
            device_ids=[AID_ONLINE, AID_OFFLINE], timeout_seconds=60, interval_seconds=5
        )

        second = self.mock_client.command.call_args_list[1]
        self.assertEqual(second[1]["body"]["host_ids"], [AID_OFFLINE])
        self.assertTrue(result["ready"])
        self.assertFalse(result["timed_out"])
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(len(result["ready_hosts"]), 2)
        mock_sleep.assert_called_once()

    @patch("falcon_mcp.modules.rtr.time.sleep")
    @patch("falcon_mcp.modules.rtr.time.monotonic")
    def test_times_out_with_last_error(self, mock_monotonic, mock_sleep):
        mock_monotonic.side_effect = [0, 10, 40, 40]
        self.mock_client.command.side_effect = [
            self._init([], [AID_OFFLINE]),
            self._init([], [AID_OFFLINE]),
        ]

        result = self.module.wait_for_sessions(
            device_ids=[AID_OFFLINE], timeout_seconds=30, interval_seconds=15
        )

        self.assertFalse(result["ready"])
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(result["not_ready_hosts"][0]["device_id"], AID_OFFLINE)
        self.assertEqual(result["not_ready_hosts"][0]["last_error"][0]["code"], 404)

    def test_rejects_bad_ids_without_api_calls(self):
        result = self.module.wait_for_sessions(
            device_ids=["not-an-aid"], timeout_seconds=30, interval_seconds=5
        )
        self.assertIn("error", result)
        self.mock_client.command.assert_not_called()
