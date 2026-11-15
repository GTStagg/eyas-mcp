"""
Tests for the Audit module.
"""

import asyncio
import unittest
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

from falcon_mcp.modules import audit
from falcon_mcp.modules.audit import AuditModule, _parse_time
from tests.modules.utils.test_modules import TestModules

JOB = "job-123"

SEARCH_DEFAULTS = {
    "start_time": "now-24h",
    "end_time": "now",
    "actor_type": None,
    "category": None,
    "action": None,
    "actor_id": None,
    "actor_ip": None,
    "target_id": None,
    "target_display_name": None,
    "geo_country": None,
    "user_agent": None,
    "event_id": None,
    "sort": "action_timestamp.desc",
    "limit": 25,
    "include_descriptions": False,
    "wait_seconds": 45,
}


def _created(job=JOB):
    return {"status_code": 200, "body": {"resources": [job]}}


def _status(status, total=None):
    record = {"id": JOB, "status": status}
    if total is not None:
        record["total_results"] = total
    return {"status_code": 200, "body": {"resources": [record]}}


def _page(records, offset=0, limit=25, total=None):
    return {
        "status_code": 200,
        "body": {
            "resources": records,
            "meta": {
                "pagination": {
                    "offset": offset,
                    "limit": limit,
                    "total": len(records) if total is None else total,
                }
            },
        },
    }


@patch("falcon_mcp.modules.audit.asyncio.sleep", new_callable=AsyncMock)
class TestAuditModule(TestModules):
    """Test cases for the Audit module."""

    def setUp(self):
        self.setup_module(AuditModule)

        async def _command_async(*args, **kwargs):
            return self.mock_client.command(*args, **kwargs)

        self.mock_client.command_async = AsyncMock(side_effect=_command_async)

    def _search(self, **kwargs):
        return asyncio.run(self.module.search_audit_log(**{**SEARCH_DEFAULTS, **kwargs}))

    def _results(self, **kwargs):
        args = {"offset": 0, "limit": 25, "include_descriptions": False, "wait_seconds": 45}
        return asyncio.run(self.module.get_audit_log_results(**{**args, **kwargs}))

    def test_register_tools(self, _sleep):
        self.assert_tools_registered(
            ["falcon_search_audit_log", "falcon_get_audit_log_results"]
        )

    def test_tools_are_read_only(self, _sleep):
        self.module.register_tools(self.mock_server)
        for call in self.mock_server.add_tool.call_args_list:
            with self.subTest(tool=call.kwargs["name"]):
                self.assertIs(call.kwargs["annotations"].readOnlyHint, True)

    def test_search_builds_the_job_body_and_returns_the_first_page(self, _sleep):
        records = [{"event_id": "e1", "category": "cases"}]
        self.mock_client.command.side_effect = [
            _created(),
            _status("RUNNING"),
            _status("COMPLETED", total=1),
            _page(records),
        ]

        result = self._search(
            start_time="2026-11-01T00:00:00Z",
            end_time="2026-11-02T00:00:00+01:00",
            actor_type=[1, 2],
            category=["Crowdstrike Authentication"],
            geo_country=[],
        )

        create = self.mock_client.command.call_args_list[0]
        self.assertEqual(create[0][0], "CreateQueryJob")
        self.assertEqual(
            create[1]["body"],
            {
                "start_time": "2026-11-01T00:00:00Z",
                "end_time": "2026-11-01T23:00:00Z",
                "sort": "action_timestamp.desc",
                "category": ["Crowdstrike Authentication"],
                # The API rejects integers here
                "actor_type": ["1", "2"],
            },
        )
        fetch = self.mock_client.command.call_args_list[3]
        self.assertEqual(fetch[0][0], "GetQueryResults")
        self.assertEqual(fetch[1]["parameters"], {"id": JOB, "offset": 0, "limit": 25})
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["results"], records)
        self.assertEqual(result["total_results"], 1)
        self.assertIsNone(result["pagination"]["next_offset"])
        self.assertEqual(result["window"]["start_time"], "2026-11-01T00:00:00Z")

    def test_running_job_returns_its_id_when_the_wait_runs_out(self, _sleep):
        self.mock_client.command.side_effect = [_created()] + [_status("RUNNING")] * 10

        result = self._search(wait_seconds=4)

        self.assertEqual(result["job_id"], JOB)
        self.assertEqual(result["status"], "RUNNING")
        self.assertIn("falcon_get_audit_log_results", result["message"])
        # Polls at 0, 2 and 4 seconds, then gives up
        self.assertEqual(self.mock_client.command.call_count, 4)

    def test_wait_zero_polls_once(self, _sleep):
        self.mock_client.command.side_effect = [_created(), _status("RUNNING")]

        result = self._search(wait_seconds=0)

        self.assertEqual(result["status"], "RUNNING")
        _sleep.assert_not_called()

    def test_failed_job_is_an_error(self, _sleep):
        self.mock_client.command.side_effect = [_created(), _status("FAILED")]

        result = self._search()

        self.assertIn("error", result)
        self.assertIn("FAILED", result["error"])

    def test_invalid_inputs_fail_without_calling_the_api(self, _sleep):
        cases = {
            "bad time": {"start_time": "yesterday"},
            "start after end": {"start_time": "now", "end_time": "now-1h"},
            "too long": {"start_time": "now-366d"},
            "pipe sort": {"sort": "action_timestamp|desc"},
            "negative actor type": {"actor_type": [-1]},
        }
        for label, kwargs in cases.items():
            with self.subTest(case=label):
                self.mock_client.command.reset_mock()
                result = self._search(**kwargs)
                self.assertIn("error", result)
                self.mock_client.command.assert_not_called()

    def test_forbidden_reports_the_audit_scope(self, _sleep):
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied, scope not permitted"}]},
        }

        result = self._search()

        self.assertIn("error", result)
        self.assertEqual(result["required_scopes"], ["Audit:read"])

    def test_get_results_pages_on(self, _sleep):
        self.mock_client.command.side_effect = [
            _status("COMPLETED", total=120),
            _page([{"event_id": "e"}] * 50, offset=50, limit=50, total=120),
        ]

        result = self._results(job_id=f" {JOB} ", offset=50, limit=50, include_descriptions=True)

        fetch = self.mock_client.command.call_args_list[1]
        self.assertEqual(
            fetch[1]["parameters"],
            {"id": JOB, "offset": 50, "limit": 50, "include_descriptions": True},
        )
        self.assertEqual(result["pagination"]["next_offset"], 100)
        self.assertEqual(result["total_results"], 120)

    def test_get_results_unknown_job(self, _sleep):
        self.mock_client.command.return_value = {
            "status_code": 400,
            "body": {"errors": [{"message": "The request was malformed or the job ID is invalid"}]},
        }

        result = self._results(job_id="nope")

        self.assertIn("job ID is invalid", result["error"])
        self.assertEqual(result["details"]["status_code"], 400)

    def test_rejected_job_reports_the_api_message_without_fql_advice(self, _sleep):
        """This API takes no FQL, so the shared 400 advice about FQL would mislead."""
        self.mock_client.command.return_value = {
            "status_code": 400,
            "body": {"errors": [{"message": "Invalid sort: sort field 'x' is not valid"}]},
        }

        result = self._search(sort="x.desc")

        self.assertIn("Invalid sort", result["error"])
        self.assertNotIn("FQL", result["error"])

    def test_get_results_requires_a_job_id(self, _sleep):
        self.assertIn("error", self._results(job_id="  "))
        self.mock_client.command.assert_not_called()


class TestParseTime(unittest.TestCase):
    NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)

    def test_relative_and_absolute_times(self):
        cases = {
            "now": self.NOW,
            "now-30m": datetime(2026, 11, 14, 11, 30, tzinfo=UTC),
            "now-24h": datetime(2026, 11, 13, 12, 0, tzinfo=UTC),
            "now-7d": datetime(2026, 11, 7, 12, 0, tzinfo=UTC),
            "2026-11-01T08:00:00Z": datetime(2026, 11, 1, 8, 0, tzinfo=UTC),
            "2026-11-01T08:00:00": datetime(2026, 11, 1, 8, 0, tzinfo=UTC),
            "2026-11-01T09:00:00+01:00": datetime(2026, 11, 1, 8, 0, tzinfo=UTC),
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(_parse_time(text, self.NOW), expected)

    def test_rejects_other_forms(self):
        for text in ("yesterday", "now-1w", "now+1d", "", "1d"):
            with self.subTest(text=text):
                self.assertIsNone(_parse_time(text, self.NOW))

    def test_module_constants_match_the_api(self):
        self.assertEqual(audit.MAX_PAGE_SIZE, 1000)
        self.assertEqual(audit.MAX_RANGE_DAYS, 365)


if __name__ == "__main__":
    unittest.main()
