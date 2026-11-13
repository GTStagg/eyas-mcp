"""
Tests for the Falcon Complete module.
"""

import base64
import unittest

from mcp.types import ToolAnnotations

from falcon_mcp.modules.base import READ_ONLY_ANNOTATIONS
from falcon_mcp.modules.falcon_complete import FalconCompleteModule
from tests.modules.utils.test_modules import TestModules

READ_TOOLS = [
    "falcon_search_message_center_cases",
    "falcon_get_message_center_cases",
    "falcon_get_message_center_case_activities",
    "falcon_aggregate_message_center_cases",
    "falcon_aggregate_complete_dashboard",
]
WRITE_TOOLS = [
    "falcon_create_message_center_case",
    "falcon_add_message_center_case_comment",
    "falcon_add_message_center_case_attachment",
]
MESSAGE_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)
USER = "01234567-89ab-cdef-0123-456789abcdef"
CASE_ID = "Abc123Def4567"
INCIDENT = "inc:" + "a" * 32 + ":" + "b" * 32
DETECTION = "ldt:" + "c" * 32 + ":12345"


def _ok(resources, total=None):
    body = {"resources": resources}
    if total is not None:
        body["meta"] = {"pagination": {"total": total, "offset": 0, "limit": 20}}
    return {"status_code": 200, "body": body}


def _case(case_id, **extra):
    return {"id": case_id, "key": f"CS-{case_id}", "status": "2", "case_type": "Blocklist", **extra}


class TestFalconCompleteModule(TestModules):
    """Test cases for the Falcon Complete module."""

    def setUp(self):
        self.setup_module(FalconCompleteModule)

    def _calls(self):
        return [(c.args[0], c.kwargs) for c in self.mock_client.command.call_args_list]

    def test_register_tools(self):
        self.assert_tools_registered(READ_TOOLS + WRITE_TOOLS)
        self.assertEqual(len(self.module.tools), 8)

    def test_tool_annotations(self):
        self.module.register_tools(self.mock_server)
        for name in READ_TOOLS:
            with self.subTest(tool=name):
                self.assert_tool_annotations(name, READ_ONLY_ANNOTATIONS)
        for name in WRITE_TOOLS:
            with self.subTest(tool=name):
                self.assert_tool_annotations(name, MESSAGE_ANNOTATIONS)

    def test_register_resources(self):
        self.assert_resources_registered(["falcon_search_message_center_cases_fql_guide"])

    # --- Message Center cases -------------------------------------------------------

    def test_search_cases_queries_then_hydrates_in_query_order(self):
        self.mock_client.command.side_effect = [
            _ok(["b", "a"], total=2),
            _ok([_case("a"), _case("b")]),
        ]

        result = self.module.search_message_center_cases(
            filter="case.status:'2'", limit=5, offset=None, sort="case.created_time.desc"
        )

        self.assertEqual([c["id"] for c in result["results"]], ["b", "a"])
        self.assertEqual(result["pagination"]["total"], 2)
        self.assertEqual(result["filter_used"], "case.status:'2'")
        (query_op, query_kwargs), (get_op, get_kwargs) = self._calls()
        self.assertEqual(query_op, "QueryCasesIdsByFilter")
        self.assertEqual(
            query_kwargs["parameters"],
            {"filter": "case.status:'2'", "limit": 5, "sort": "case.created_time.desc"},
        )
        self.assertEqual(get_op, "GetCaseEntitiesByIDs")
        self.assertEqual(get_kwargs["body"], {"ids": ["b", "a"]})

    def test_search_cases_defaults_and_empty_result(self):
        self.mock_client.command.return_value = _ok([], total=0)

        result = self.module.search_message_center_cases()

        self.assertEqual(result["results"], [])
        self.mock_client.command.assert_called_once()
        self.assertEqual(
            self._calls()[0][1]["parameters"],
            {"limit": 20, "sort": "case.last_modified_time.desc"},
        )

    def test_search_cases_filter_error_returns_the_fql_guide(self):
        self.mock_client.command.return_value = {
            "status_code": 400,
            "body": {"errors": [{"code": 400, "message": "fql: nope is an unknown property"}]},
        }

        result = self.module.search_message_center_cases(
            filter="nope:'x'", limit=5, offset=None, sort="case.created_time.desc"
        )

        self.assertIn("fql_guide", result)
        self.assertEqual(result["filter_used"], "nope:'x'")
        self.mock_client.command.assert_called_once()

    def test_get_cases_reports_not_found(self):
        self.mock_client.command.return_value = _ok([_case("b"), _case("a")])

        result = self.module.get_message_center_cases(ids=["a", "b", "a", "missing"])

        self.assertEqual([c["id"] for c in result["found"]], ["a", "b"])
        self.assertEqual(result["not_found"], ["missing"])
        self.assertEqual(self._calls()[0][1]["body"], {"ids": ["a", "b", "missing"]})

    def test_get_cases_rejects_bad_ids_without_calling_the_api(self):
        for ids in ([], None, ["ok", "bad id'"], [f"id{n}" for n in range(101)]):
            with self.subTest(ids=str(ids)[:40]):
                result = self.module.get_message_center_cases(ids=ids)
                self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    # --- Case activities --------------------------------------------------------------

    def test_activities_oldest_first_by_default(self):
        self.mock_client.command.side_effect = [
            _ok(["x2", "x1"], total=2),
            _ok([{"id": "x1", "type": "comment"}, {"id": "x2", "type": "status_change"}]),
        ]

        result = self.module.get_message_center_case_activities(case_id="Abc123Def4567")

        self.assertEqual([a["id"] for a in result["results"]], ["x2", "x1"])
        (query_op, query_kwargs), (get_op, get_kwargs) = self._calls()
        self.assertEqual(query_op, "QueryActivityByCaseID")
        self.assertEqual(
            query_kwargs["parameters"],
            {"case_id": "Abc123Def4567", "limit": 100, "sort": "activity.created_time.asc"},
        )
        self.assertEqual(get_op, "GetCaseActivityByIds")
        self.assertEqual(get_kwargs["body"], {"ids": ["x2", "x1"]})

    def test_activities_type_filter_and_newest_first(self):
        self.mock_client.command.return_value = _ok([], total=0)

        result = self.module.get_message_center_case_activities(
            case_id="Abc123Def4567", activity_type="comment", limit=10, offset=10, newest_first=True
        )

        self.assertEqual(result["results"], [])
        self.assertEqual(
            self._calls()[0][1]["parameters"],
            {
                "case_id": "Abc123Def4567",
                "filter": "activity.type:'comment'",
                "limit": 10,
                "offset": 10,
                "sort": "activity.created_time.desc",
            },
        )

    def test_activities_reject_bad_input(self):
        for kwargs in (
            {"case_id": "x' + case.id:*"},
            {"case_id": ""},
            {"case_id": "Abc123Def4567", "activity_type": "note"},
        ):
            with self.subTest(kwargs=kwargs):
                result = self.module.get_message_center_case_activities(**kwargs)
                self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    # --- Case aggregates --------------------------------------------------------------

    def test_aggregate_cases_by_value(self):
        self.mock_client.command.return_value = _ok(
            [{"name": "case.status", "buckets": [{"label": "3", "count": 30}, {"label": "2", "count": 5}]}]
        )

        result = self.module.aggregate_message_center_cases(
            field="case.status", filter="case.type:'10201'", size=5
        )

        self.assertEqual(
            result,
            {
                "field": "case.status",
                "filter_used": "case.type:'10201'",
                "buckets": [{"label": "3", "count": 30}, {"label": "2", "count": 5}],
            },
        )
        operation, kwargs = self._calls()[0]
        self.assertEqual(operation, "AggregateCases")
        self.assertEqual(
            kwargs["body"],
            [
                {
                    "type": "terms",
                    "field": "case.status",
                    "filter": "case.type:'10201'",
                    "name": "case.status",
                    "size": 5,
                }
            ],
        )

    def test_aggregate_cases_by_time_uses_a_date_histogram(self):
        self.mock_client.command.return_value = _ok([{"buckets": []}])

        self.module.aggregate_message_center_cases(field="case.created_time", interval="week")

        self.assertEqual(
            self._calls()[0][1]["body"],
            [
                {
                    "type": "date_histogram",
                    "field": "case.created_time",
                    "name": "case.created_time",
                    "interval": "week",
                }
            ],
        )

    def test_aggregate_cases_rejects_unknown_fields(self):
        result = self.module.aggregate_message_center_cases(field="case.hosts")
        self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    # --- Dashboard --------------------------------------------------------------------

    def test_dashboard_total_only(self):
        self.mock_client.command.return_value = _ok(["t1"], total=9)

        result = self.module.aggregate_complete_dashboard(dataset="escalations")

        self.assertEqual(
            result, {"dataset": "escalations", "filter_used": None, "total": 9}
        )
        self.assertEqual(self._calls(), [("QueryEscalationsFilter", {"parameters": {"limit": 1}})])

    def test_dashboard_buckets_by_field(self):
        self.mock_client.command.side_effect = [
            _ok(["a1"], total=1234),
            _ok([{"name": "severity", "buckets": [{"label": "High", "count": 7}]}]),
        ]

        result = self.module.aggregate_complete_dashboard(
            dataset="alerts", field="severity", filter="status:'new'", size=10
        )

        self.assertEqual(result["total"], 1234)
        self.assertEqual(result["buckets"], [{"label": "High", "count": 7}])
        (query_op, query_kwargs), (agg_op, agg_kwargs) = self._calls()
        # The v1 query covers the same endpoint alerts as the aggregate.
        self.assertEqual(query_op, "QueryAlertIdsByFilter")
        self.assertEqual(query_kwargs["parameters"], {"filter": "status:'new'", "limit": 1})
        self.assertEqual(agg_op, "AggregateAlerts")
        self.assertEqual(
            agg_kwargs["body"],
            [
                {
                    "type": "terms",
                    "field": "severity",
                    "filter": "status:'new'",
                    "name": "severity",
                    "size": 10,
                }
            ],
        )

    def test_dashboard_interval_uses_a_date_histogram(self):
        self.mock_client.command.side_effect = [
            _ok(["b1"], total=1),
            _ok([{"buckets": [{"label": 1767225600000, "count": 1}]}]),
        ]

        result = self.module.aggregate_complete_dashboard(
            dataset="blocklist", field="created_time", interval="month"
        )

        self.assertEqual(result["buckets"], [{"label": 1767225600000, "count": 1}])
        self.assertEqual(self._calls()[1][0], "AggregateBlockList")
        self.assertEqual(self._calls()[1][1]["body"][0]["type"], "date_histogram")
        self.assertEqual(self._calls()[1][1]["body"][0]["interval"], "month")

    def test_dashboard_dataset_operations(self):
        expected = {
            "alerts": ("QueryAlertIdsByFilter", "AggregateAlerts"),
            "escalations": ("QueryEscalationsFilter", "AggregateEscalations"),
            "remediations": ("QueryRemediationsFilter", "AggregateRemediations"),
            "blocklist": ("QueryBlockListFilter", "AggregateBlockList"),
            "allowlist": ("QueryAllowListFilter", "AggregateAllowList"),
        }
        for dataset, (query_op, agg_op) in expected.items():
            with self.subTest(dataset=dataset):
                self.mock_client.command.reset_mock()
                self.mock_client.command.side_effect = [_ok([], total=0), _ok([{"buckets": []}])]
                self.module.aggregate_complete_dashboard(dataset=dataset, field="severity")
                self.assertEqual([c[0] for c in self._calls()], [query_op, agg_op])

    def test_dashboard_rejects_bad_input_before_aggregating(self):
        result = self.module.aggregate_complete_dashboard(dataset="incidents")
        self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

        for kwargs in (
            {"field": 'severity", "x'},
            {"field": "a b"},
            {"field": "1abc"},
            {"field": "x" * 65},
            {"field": "created_time", "interval": "hour"},
        ):
            with self.subTest(kwargs=kwargs):
                result = self.module.aggregate_complete_dashboard(dataset="alerts", **kwargs)
                self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    # --- Writes: every call is mocked; none reaches a tenant ------------------------

    def test_create_case_sends_the_documented_body(self):
        self.mock_client.command.return_value = _ok([{"id": "NewCase12345"}])

        result = self.module.create_message_center_case(
            case_type="fc:incident-support",
            title="  Lateral movement on WS-01  ",
            content="Please investigate.",
            user_uuid=USER,
            incident_ids=[INCIDENT, INCIDENT],
        )

        self.assertEqual(result, [{"id": "NewCase12345"}])
        self.assertEqual(
            self._calls(),
            [
                (
                    "CreateCaseV2",
                    {
                        "body": {
                            "type": "fc:incident-support",
                            "title": "Lateral movement on WS-01",
                            "body": "Please investigate.",
                            "user_uuid": USER,
                            "incidents": [{"id": INCIDENT}],
                        }
                    },
                )
            ],
        )

    def test_create_case_links_detections_to_detection_support(self):
        self.mock_client.command.return_value = _ok([{"id": "NewCase12345"}])

        self.module.create_message_center_case(
            case_type="fc:detection-support",
            title="Is this a false positive?",
            content="See the linked detection.",
            user_uuid=USER,
            detection_ids=[DETECTION],
        )

        self.assertEqual(self._calls()[0][1]["body"]["detections"], [{"id": DETECTION}])

    def test_create_case_rejects_bad_input_without_calling_the_api(self):
        base = {
            "case_type": "fc:contact",
            "title": "Question",
            "content": "Hello",
            "user_uuid": USER,
            "detection_ids": None,
            "incident_ids": None,
        }
        for change in (
            {"case_type": "fc:other"},
            {"title": "   "},
            {"title": "x" * 256},
            {"content": ""},
            {"user_uuid": "not-a-uuid"},
            {"detection_ids": [DETECTION]},
            {"incident_ids": [INCIDENT]},
            {"case_type": "fc:incident-support", "incident_ids": ["inc:bad"]},
            {"case_type": "fc:detection-support", "detection_ids": ["bad id'"]},
            {"case_type": "fc:detection-support", "detection_ids": [f"d{n}" for n in range(101)]},
        ):
            with self.subTest(change=str(change)[:60]):
                result = self.module.create_message_center_case(**{**base, **change})
                self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_comment_sends_a_comment_activity(self):
        self.mock_client.command.return_value = _ok([{"id": "act1"}])

        result = self.module.add_message_center_case_comment(
            case_id=CASE_ID, content="Confirmed, please block it.", user_uuid=USER
        )

        self.assertEqual(result, [{"id": "act1"}])
        self.assertEqual(
            self._calls(),
            [
                (
                    "CaseAddActivity",
                    {
                        "body": {
                            "case_id": CASE_ID,
                            "type": "comment",
                            "body": "Confirmed, please block it.",
                            "user_uuid": USER,
                        }
                    },
                )
            ],
        )

    def test_comment_rejects_bad_input_without_calling_the_api(self):
        for kwargs in (
            {"case_id": "x;y", "content": "hi", "user_uuid": USER},
            {"case_id": CASE_ID, "content": " ", "user_uuid": USER},
            {"case_id": CASE_ID, "content": "hi", "user_uuid": "nope"},
        ):
            with self.subTest(kwargs=kwargs):
                self.assertIn("error", self.module.add_message_center_case_comment(**kwargs))
        self.mock_client.command.assert_not_called()

    def test_attachment_uploads_decoded_bytes_as_multipart(self):
        self.mock_client.command.return_value = _ok([{"id": "att1"}])
        content = b"line one\nline two\n"

        result = self.module.add_message_center_case_attachment(
            case_id=CASE_ID,
            file_name="triage-notes.txt",
            content_base64=base64.b64encode(content).decode(),
            user_uuid=USER,
        )

        self.assertEqual(result, [{"id": "att1"}])
        operation, kwargs = self._calls()[0]
        self.assertEqual(operation, "CaseAddAttachment")
        self.assertEqual(kwargs["data"], {"case_id": CASE_ID, "user_uuid": USER})
        self.assertEqual(kwargs["files"], [("file", ("triage-notes.txt", content))])

    def test_attachment_rejects_bad_input_without_calling_the_api(self):
        good = base64.b64encode(b"data").decode()
        base = {"case_id": CASE_ID, "file_name": "a.txt", "content_base64": good, "user_uuid": USER}
        oversized = base64.b64encode(bytes(15 * 1024 * 1024)).decode()
        for change in (
            {"file_name": "../etc/passwd.txt"},
            {"file_name": ".hidden.txt"},
            {"file_name": "script.ps1"},
            {"file_name": "noextension"},
            {"file_name": "a" * 252 + ".txt"},
            {"content_base64": "not base64!"},
            {"content_base64": ""},
            {"content_base64": oversized},
            {"user_uuid": "x"},
            {"case_id": ""},
        ):
            with self.subTest(change=str(change)[:60]):
                result = self.module.add_message_center_case_attachment(**{**base, **change})
                self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_write_api_errors_are_returned(self):
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"code": 403, "message": "access denied, scope not permitted"}]},
        }

        result = self.module.add_message_center_case_comment(
            case_id=CASE_ID, content="hi", user_uuid=USER
        )

        self.assertIn("error", result)

    def test_dashboard_api_error_is_returned(self):
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"code": 403, "message": "access denied, scope not permitted"}]},
        }

        result = self.module.aggregate_complete_dashboard(dataset="escalations", field="severity")

        self.assertIn("error", result)
        self.mock_client.command.assert_called_once()


if __name__ == "__main__":
    unittest.main()
