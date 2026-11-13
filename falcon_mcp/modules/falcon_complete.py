"""
Falcon Complete module for Falcon MCP Server

This module provides tools for Falcon Complete: reading Message Center cases, their
activity threads and the counts behind the Falcon Complete dashboard, and opening cases,
commenting on them and attaching files.
"""

import base64
import binascii
import re
from typing import Any, Literal, get_args

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from mcp.types import ToolAnnotations
from pydantic import AnyUrl, Field

from falcon_mcp.common.errors import _format_error_response, handle_api_response
from falcon_mcp.common.logging import get_logger
from falcon_mcp.common.utils import unwrap_field_default
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.falcon_complete import MESSAGE_CENTER_CASES_FQL_DOCUMENTATION

logger = get_logger(__name__)

# Message Center case IDs are short alphanumeric strings (13 characters in a live check).
CASE_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}")
MAX_CASE_IDS = 100
MAX_PAGE = 100

CASE_AGGREGATE_FIELDS = (
    "case.status",
    "case.type",
    "case.assigner.display_name",
    "case.created_time",
    "case.last_modified_time",
)
_CASE_TIME_FIELDS = frozenset({"case.created_time", "case.last_modified_time"})

DashboardDataset = Literal["alerts", "escalations", "remediations", "blocklist", "allowlist"]
# Written into the aggregate body, so only a plain dotted field name is accepted.
_FIELD_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,63}")
Interval = Literal["day", "week", "month", "year"]

# Message Center writes reach CrowdStrike analysts, so every argument is checked before
# the call. The rules follow CrowdStrike's own SDKs (PSFalcon and FalconPy).
CaseType = Literal[
    "fc:detection-support", "fc:contact", "fc:falcon-product-support", "fc:incident-support"
]
USER_UUID_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
INCIDENT_ID_PATTERN = re.compile(r"inc:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}")
# Legacy `ldt:` detection IDs and composite alert IDs; the API decides which it accepts.
DETECTION_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9:_-]{0,255}")
MAX_LINKED_IDS = 100
MAX_TITLE_LENGTH = 255
MAX_CONTENT_LENGTH = 100_000
ATTACHMENT_NAME_PATTERN = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,254}")
ATTACHMENT_EXTENSIONS = frozenset(
    {"png", "bmp", "jpg", "jpeg", "gif", "pdf", "doc", "docx", "xls", "xlsx", "pptx", "txt", "csv"}
)
MAX_ATTACHMENT_BYTES = 15 * 1024 * 1024
# A write that sends a message to CrowdStrike: it changes nothing that already exists,
# but cannot be taken back and repeats if retried.
MESSAGE_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=True,
)


class FalconCompleteModule(BaseModule):
    """Module for reading Falcon Complete Message Center cases and dashboard counts."""

    # Dashboard datasets: the query operation that reports the total and the aggregate
    # operation that buckets it. Incidents are left out: Falcon decommissioned them.
    # Alerts use the v1 query, which like the aggregate covers endpoint alerts only (v2
    # adds identity and NG-SIEM alerts, so its total would not match the buckets).
    _OPERATIONS: dict[str, dict[str, str]] = {
        "alerts": {"query": "QueryAlertIdsByFilter", "aggregate": "AggregateAlerts"},
        "escalations": {"query": "QueryEscalationsFilter", "aggregate": "AggregateEscalations"},
        "remediations": {
            "query": "QueryRemediationsFilter",
            "aggregate": "AggregateRemediations",
        },
        "blocklist": {"query": "QueryBlockListFilter", "aggregate": "AggregateBlockList"},
        "allowlist": {"query": "QueryAllowListFilter", "aggregate": "AggregateAllowList"},
    }

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(
            server=server,
            method=self.search_message_center_cases,
            name="search_message_center_cases",
        )
        self._add_tool(
            server=server,
            method=self.get_message_center_cases,
            name="get_message_center_cases",
        )
        self._add_tool(
            server=server,
            method=self.get_message_center_case_activities,
            name="get_message_center_case_activities",
        )
        self._add_tool(
            server=server,
            method=self.aggregate_message_center_cases,
            name="aggregate_message_center_cases",
        )
        self._add_tool(
            server=server,
            method=self.aggregate_complete_dashboard,
            name="aggregate_complete_dashboard",
        )
        self._add_tool(
            server=server,
            method=self.create_message_center_case,
            name="create_message_center_case",
            annotations=MESSAGE_ANNOTATIONS,
        )
        self._add_tool(
            server=server,
            method=self.add_message_center_case_comment,
            name="add_message_center_case_comment",
            annotations=MESSAGE_ANNOTATIONS,
        )
        self._add_tool(
            server=server,
            method=self.add_message_center_case_attachment,
            name="add_message_center_case_attachment",
            annotations=MESSAGE_ANNOTATIONS,
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_resource(
            server,
            TextResource(
                uri=AnyUrl("falcon://falcon-complete/message-center/cases/fql-guide"),
                name="falcon_search_message_center_cases_fql_guide",
                description=(
                    "Contains the guide for the `filter` param of the "
                    "`falcon_search_message_center_cases` tool."
                ),
                text=MESSAGE_CENTER_CASES_FQL_DOCUMENTATION,
            ),
        )

    def search_message_center_cases(
        self,
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter expression. See "
                "`falcon://falcon-complete/message-center/cases/fql-guide` for syntax."
            ),
            examples=["case.status:'2'", "case.created_time:>'2026-01-01'"],
        ),
        limit: int = Field(
            default=20,
            ge=1,
            le=MAX_PAGE,
            description="The maximum cases to return. [1-100] Page with offset for more.",
        ),
        offset: int | None = Field(
            default=None,
            description="The offset to start retrieving cases from.",
        ),
        sort: str = Field(
            default="case.last_modified_time.desc",
            description=(
                "Sort by case.created_time, case.last_modified_time or case.status, "
                "followed by .asc or .desc."
            ),
            examples=["case.last_modified_time.desc", "case.created_time.asc"],
        ),
    ) -> dict[str, Any]:
        """Search Falcon Complete and Support cases in Message Center.

        Use this to see what the Falcon Complete team or CrowdStrike Support has raised
        with you (escalations, blocklist requests, incidents, support issues) and the
        cases you opened with them. Consult
        falcon://falcon-complete/message-center/cases/fql-guide before constructing
        filter expressions. Returns full case records: key (the CS- number), title,
        body, status and type codes, case_type name, the alert IDs, host names and
        AIDs linked to it, and timestamps. Read a case's messages with
        falcon_get_message_center_case_activities.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        filter = unwrap_field_default(filter)
        limit = unwrap_field_default(limit)
        offset = unwrap_field_default(offset)
        sort = unwrap_field_default(sort)
        case_ids, pagination = self._base_search_with_meta(
            operation="QueryCasesIdsByFilter",
            search_params={"filter": filter, "limit": limit, "offset": offset, "sort": sort},
            error_message="Failed to search Message Center cases",
        )
        if self._is_error(case_ids):
            return self._format_fql_error_response(
                [case_ids], filter, MESSAGE_CENTER_CASES_FQL_DOCUMENTATION
            )
        if not case_ids:
            return self._build_pagination_envelope([], pagination, filter)

        cases = self._base_get_by_ids("GetCaseEntitiesByIDs", case_ids)
        if self._is_error(cases):
            return cases
        cases = self._reorder_by_ids(case_ids, cases, id_field="id")
        return self._build_pagination_envelope(cases, pagination, filter)

    def get_message_center_cases(
        self,
        ids: list[str] = Field(
            description=(
                "Message Center case IDs to look up, at most 100. These are the `id` "
                "values from falcon_search_message_center_cases, not the CS- case keys."
            ),
        ),
    ) -> dict[str, Any]:
        """Get Message Center cases by ID and report which IDs don't exist.

        Use this to re-read cases you already have IDs for, for example to check
        whether their status changed. Returns `found` (full case records in the order
        of `ids`) and `not_found` (IDs with no case).
        """
        ids = unwrap_field_default(ids)
        checked = self._validate_case_ids(ids)
        if isinstance(checked, dict):
            return checked
        cases = self._base_get_by_ids("GetCaseEntitiesByIDs", checked)
        if self._is_error(cases):
            return cases
        found = self._reorder_by_ids(checked, cases, id_field="id")
        found_ids = {str(case.get("id")) for case in found if isinstance(case, dict)}
        return {"found": found, "not_found": [i for i in checked if i not in found_ids]}

    def get_message_center_case_activities(
        self,
        case_id: str = Field(
            description="The Message Center case ID, from falcon_search_message_center_cases.",
        ),
        activity_type: Literal["comment", "status_change"] | None = Field(
            default=None,
            description=(
                "Only return messages (`comment`) or status changes (`status_change`). "
                "Default is both."
            ),
        ),
        limit: int = Field(
            default=100,
            ge=1,
            le=MAX_PAGE,
            description="The maximum activities to return. [1-100] Page with offset for more.",
        ),
        offset: int | None = Field(
            default=None,
            description="The offset to start retrieving activities from.",
        ),
        newest_first: bool = Field(
            default=False,
            description="Return the newest activity first. Default is oldest first.",
        ),
    ) -> dict[str, Any]:
        """Read the message thread of one Message Center case.

        Use this to see what the Falcon Complete team or Support wrote on a case and
        how its status changed. Returns activities with type (`comment` or
        `status_change`), body, created_by and created_time, oldest first.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        case_id = unwrap_field_default(case_id)
        activity_type = unwrap_field_default(activity_type)
        newest_first = unwrap_field_default(newest_first)
        limit = unwrap_field_default(limit)
        offset = unwrap_field_default(offset)
        if not isinstance(case_id, str) or not CASE_ID_PATTERN.fullmatch(case_id.strip()):
            return _format_error_response(
                "Invalid case_id: use the `id` of a case from "
                "falcon_search_message_center_cases.",
                operation="QueryActivityByCaseID",
            )
        if activity_type not in (None, "comment", "status_change"):
            return _format_error_response(
                "Invalid activity_type: must be 'comment' or 'status_change'.",
                operation="QueryActivityByCaseID",
            )
        activity_filter = f"activity.type:'{activity_type}'" if activity_type else None

        activity_ids, pagination = self._base_search_with_meta(
            operation="QueryActivityByCaseID",
            search_params={
                "case_id": case_id.strip(),
                "filter": activity_filter,
                "limit": limit,
                "offset": offset,
                "sort": f"activity.created_time.{'desc' if newest_first else 'asc'}",
            },
            error_message="Failed to list Message Center case activities",
        )
        if self._is_error(activity_ids):
            return activity_ids
        if not activity_ids:
            return self._build_pagination_envelope([], pagination)

        activities = self._base_get_by_ids("GetCaseActivityByIds", activity_ids)
        if self._is_error(activities):
            return activities
        activities = self._reorder_by_ids(activity_ids, activities, id_field="id")
        return self._build_pagination_envelope(activities, pagination)

    def aggregate_message_center_cases(
        self,
        field: Literal[
            "case.status",
            "case.type",
            "case.assigner.display_name",
            "case.created_time",
            "case.last_modified_time",
        ] = Field(
            default="case.status",
            description=(
                "Field to count cases by. The time fields are bucketed by `interval`; "
                "the others by value."
            ),
        ),
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter narrowing the cases counted. See "
                "`falcon://falcon-complete/message-center/cases/fql-guide`."
            ),
            examples=["case.type:'10201'"],
        ),
        interval: Interval = Field(
            default="month",
            description="Bucket width for the time fields. Ignored for the others.",
        ),
        size: int = Field(
            default=20,
            ge=1,
            le=500,
            description="Maximum buckets to return for value fields. [1-500]",
        ),
    ) -> dict[str, Any]:
        """Count Message Center cases by status, type, opener or time.

        Use this to answer "how many open cases" or "cases per month" without paging
        through them. Returns `buckets` of `{label, count}`. Status and type labels
        are numeric codes; search the cases to see each type's `case_type` name.
        """
        field = unwrap_field_default(field)
        filter = unwrap_field_default(filter)
        interval = unwrap_field_default(interval)
        size = unwrap_field_default(size)
        if field not in CASE_AGGREGATE_FIELDS:
            return _format_error_response(
                f"Invalid field: must be one of {', '.join(CASE_AGGREGATE_FIELDS)}.",
                operation="AggregateCases",
            )
        spec = self._spec(field, filter, interval if field in _CASE_TIME_FIELDS else None, size)
        if "error" in spec:
            return spec
        result = self._base_aggregate(
            "AggregateCases", specs=[spec], error_message="Failed to aggregate Message Center cases"
        )
        if self._is_error(result):
            return result
        return {"field": field, "filter_used": filter, "buckets": self._buckets(result)}

    def aggregate_complete_dashboard(
        self,
        dataset: DashboardDataset = Field(
            description=(
                "Falcon Complete dashboard data to count: `alerts` (endpoint alerts in "
                "Complete's view), `escalations` (escalation tickets), `remediations`, `blocklist` "
                "or `allowlist` (ticket requests)."
            ),
        ),
        field: str | None = Field(
            default=None,
            description=(
                "Field to bucket by. Fields seen to work: alerts: severity, status, "
                "type, product, platform_name, tactic, technique; escalations: "
                "severity, created_time; blocklist: created_time. Leave unset for the "
                "total only."
            ),
            examples=["severity", "product"],
        ),
        filter: str | None = Field(
            default=None,
            description="FQL filter narrowing what is counted, in the dataset's own fields.",
        ),
        interval: Interval | None = Field(
            default=None,
            description=(
                "Bucket a time field such as created_time by this width instead of by "
                "value."
            ),
        ),
        size: int = Field(
            default=20,
            ge=1,
            le=500,
            description="Maximum buckets to return. [1-500]",
        ),
    ) -> dict[str, Any]:
        """Count Falcon Complete dashboard data: escalations, remediations and more.

        Use this to answer how many escalations, remediations, blocklist or allowlist
        requests or alerts the Falcon Complete team has handled, optionally broken
        down by a field. Returns `total` (records matching `filter`) and, when
        `field` is set, `buckets` of `{label, count}`. The dashboard API lists only
        record IDs, so read case details with falcon_search_message_center_cases.
        """
        dataset = unwrap_field_default(dataset)
        field = unwrap_field_default(field)
        filter = unwrap_field_default(filter)
        interval = unwrap_field_default(interval)
        size = unwrap_field_default(size)
        if not isinstance(dataset, str) or dataset not in self._OPERATIONS:
            return _format_error_response(
                f"Invalid dataset: must be one of {', '.join(self._OPERATIONS)}."
            )
        query_operation = self._OPERATIONS[dataset]["query"]
        aggregate_operation = self._OPERATIONS[dataset]["aggregate"]
        spec = self._spec(field, filter, interval, size) if field is not None else None
        if spec is not None and "error" in spec:
            return spec

        ids, pagination = self._base_search_with_meta(
            operation=query_operation,
            search_params={"filter": filter, "limit": 1},
            error_message=f"Failed to count Falcon Complete {dataset}",
        )
        if self._is_error(ids):
            return ids
        response: dict[str, Any] = {
            "dataset": dataset,
            "filter_used": filter,
            "total": (pagination or {}).get("total"),
        }
        if spec is None:
            return response

        result = self._base_aggregate(
            aggregate_operation,
            specs=[spec],
            error_message=f"Failed to aggregate Falcon Complete {dataset}",
        )
        if self._is_error(result):
            return result
        response["field"] = field
        response["buckets"] = self._buckets(result)
        return response

    def create_message_center_case(
        self,
        case_type: CaseType = Field(
            description=(
                "What the case is about: `fc:detection-support` (questions about "
                "detections, give `detection_ids`), `fc:incident-support` (give "
                "`incident_ids`), `fc:falcon-product-support`, or `fc:contact` "
                "(anything else for the Falcon Complete team)."
            ),
        ),
        title: str = Field(description="Case title, at most 255 characters."),
        content: str = Field(description="The message to CrowdStrike: the case body."),
        user_uuid: str = Field(
            description=(
                "UUID of the Falcon console user the case is opened as. A case's "
                "`assigner.uuid`, or an activity's `created_by.uuid`, gives the UUID of "
                "a user who has written in Message Center before."
            ),
        ),
        detection_ids: list[str] | None = Field(
            default=None,
            description=(
                "Detection or alert IDs to link, for `fc:detection-support` only. At "
                "most 100."
            ),
        ),
        incident_ids: list[str] | None = Field(
            default=None,
            description=(
                "Incident IDs (inc:<32 hex>:<32 hex>) to link, for "
                "`fc:incident-support` only. At most 100."
            ),
        ),
    ) -> dict[str, Any] | list[Any]:
        """Open a Message Center case with Falcon Complete or CrowdStrike Support.

        Use this to ask the Falcon Complete team about a detection or incident, or to
        raise a product question. This sends a message to CrowdStrike analysts, who
        will see and act on it, and it cannot be withdrawn, so confirm the wording
        with the user first. Returns the API's response for the new case.
        """
        case_type = unwrap_field_default(case_type)
        title = unwrap_field_default(title)
        content = unwrap_field_default(content)
        user_uuid = unwrap_field_default(user_uuid)
        detection_ids = unwrap_field_default(detection_ids)
        incident_ids = unwrap_field_default(incident_ids)
        operation = "CreateCaseV2"

        if case_type not in get_args(CaseType):
            return _format_error_response(
                f"Invalid case_type: must be one of {', '.join(get_args(CaseType))}.",
                operation=operation,
            )
        error = self._check_text("title", title, MAX_TITLE_LENGTH, operation)
        error = error or self._check_text("content", content, MAX_CONTENT_LENGTH, operation)
        error = error or self._check_user_uuid(user_uuid, operation)
        if error:
            return error

        body: dict[str, Any] = {
            "type": case_type,
            "title": title.strip(),
            "body": content,
            "user_uuid": user_uuid,
        }
        for key, ids, pattern, wanted in (
            ("detections", detection_ids, DETECTION_ID_PATTERN, "fc:detection-support"),
            ("incidents", incident_ids, INCIDENT_ID_PATTERN, "fc:incident-support"),
        ):
            if ids is None or ids == []:
                continue
            if case_type != wanted:
                return _format_error_response(
                    f"`{key[:-1]}_ids` can only be given with case_type '{wanted}'.",
                    operation=operation,
                )
            checked = self._check_ids(key[:-1] + "_ids", ids, pattern, operation)
            if isinstance(checked, dict):
                return checked
            body[key] = [{"id": i} for i in checked]

        response = self.client.command(operation, body=body)
        return handle_api_response(
            response,
            operation=operation,
            error_message="Failed to create Message Center case",
            default_result=[],
        )

    def add_message_center_case_comment(
        self,
        case_id: str = Field(
            description="The Message Center case ID, from falcon_search_message_center_cases.",
        ),
        content: str = Field(description="The comment to post on the case."),
        user_uuid: str = Field(
            description=(
                "UUID of the Falcon console user the comment is posted as. A case's "
                "`assigner.uuid`, or an activity's `created_by.uuid`, gives the UUID of "
                "a user who has written in Message Center before."
            ),
        ),
    ) -> dict[str, Any] | list[Any]:
        """Post a comment on a Message Center case, as a reply to Falcon Complete or Support.

        Use this to answer a question the Falcon Complete team asked on a case or to
        add information to a case. CrowdStrike analysts see the comment and it cannot
        be withdrawn, so confirm the wording with the user first. Only comments can be
        added through the API. Returns the API's response for the new activity.
        """
        case_id = unwrap_field_default(case_id)
        content = unwrap_field_default(content)
        user_uuid = unwrap_field_default(user_uuid)
        operation = "CaseAddActivity"

        error = self._check_case_id(case_id, operation)
        error = error or self._check_text("content", content, MAX_CONTENT_LENGTH, operation)
        error = error or self._check_user_uuid(user_uuid, operation)
        if error:
            return error

        response = self.client.command(
            operation,
            body={
                "case_id": case_id.strip(),
                "type": "comment",
                "body": content,
                "user_uuid": user_uuid,
            },
        )
        return handle_api_response(
            response,
            operation=operation,
            error_message="Failed to add a comment to the Message Center case",
            default_result=[],
        )

    def add_message_center_case_attachment(
        self,
        case_id: str = Field(
            description="The Message Center case ID, from falcon_search_message_center_cases.",
        ),
        file_name: str = Field(
            description=(
                "File name for the attachment, such as 'triage-notes.txt'. Letters, "
                "digits, '.', '_' and '-' only, starting with a letter, digit, '_' or "
                "'-'. Extension must be one of png, bmp, jpg, jpeg, gif, pdf, doc, docx, "
                "xls, xlsx, pptx, txt or csv."
            ),
            examples=["triage-notes.txt"],
        ),
        content_base64: str = Field(
            description=(
                "The file's content, base64-encoded. Under 15 MB once decoded. Only "
                "content passed here is sent: the server never reads files from its own "
                "disk."
            ),
        ),
        user_uuid: str = Field(
            description=(
                "UUID of the Falcon console user the file is attached as. A case's "
                "`assigner.uuid`, or an activity's `created_by.uuid`, gives the UUID of "
                "a user who has written in Message Center before."
            ),
        ),
    ) -> dict[str, Any] | list[Any]:
        """Attach a file to a Message Center case for Falcon Complete or Support.

        Use this to give CrowdStrike analysts a screenshot, log extract or document
        on a case. They see the file and it cannot be removed, so confirm with the
        user what is being shared first. Returns the API's response for the upload.
        """
        case_id = unwrap_field_default(case_id)
        file_name = unwrap_field_default(file_name)
        content_base64 = unwrap_field_default(content_base64)
        user_uuid = unwrap_field_default(user_uuid)
        operation = "CaseAddAttachment"

        error = self._check_case_id(case_id, operation)
        error = error or self._check_user_uuid(user_uuid, operation)
        if error:
            return error
        if not isinstance(file_name, str) or not ATTACHMENT_NAME_PATTERN.fullmatch(file_name):
            return _format_error_response(
                "Invalid file_name: use letters, digits, '.', '_' and '-' only, starting "
                "with a letter, digit, '_' or '-', at most 255 characters.",
                operation=operation,
            )
        extension = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""
        if extension not in ATTACHMENT_EXTENSIONS:
            return _format_error_response(
                "Invalid file_name: the extension must be one of "
                f"{', '.join(sorted(ATTACHMENT_EXTENSIONS))}.",
                operation=operation,
            )
        if not isinstance(content_base64, str) or not content_base64.strip():
            return _format_error_response(
                "content_base64 must hold the file's content, base64-encoded.",
                operation=operation,
            )
        # Reject oversized input before decoding it: base64 is 4 characters per 3 bytes.
        if len(content_base64) > (MAX_ATTACHMENT_BYTES // 3 + 1) * 4 + 1024:
            return _format_error_response(
                "The attachment must be under 15 MB.", operation=operation
            )
        try:
            data = base64.b64decode("".join(content_base64.split()), validate=True)
        except (binascii.Error, ValueError):
            return _format_error_response(
                "content_base64 is not valid base64.", operation=operation
            )
        if not data:
            return _format_error_response("The attachment is empty.", operation=operation)
        if len(data) >= MAX_ATTACHMENT_BYTES:
            return _format_error_response(
                "The attachment must be under 15 MB.", operation=operation
            )

        response = self.client.command(
            operation,
            data={"case_id": case_id.strip(), "user_uuid": user_uuid},
            files=[("file", (file_name, data))],
        )
        return handle_api_response(
            response,
            operation=operation,
            error_message="Failed to attach the file to the Message Center case",
            default_result=[],
        )

    @staticmethod
    def _check_text(name: str, value: Any, max_length: int, operation: str) -> dict[str, Any] | None:
        if not isinstance(value, str) or not value.strip():
            return _format_error_response(f"`{name}` must not be empty.", operation=operation)
        if len(value) > max_length:
            return _format_error_response(
                f"`{name}` must be at most {max_length} characters; got {len(value)}.",
                operation=operation,
            )
        return None

    @staticmethod
    def _check_user_uuid(value: Any, operation: str) -> dict[str, Any] | None:
        if not isinstance(value, str) or not USER_UUID_PATTERN.fullmatch(value):
            return _format_error_response(
                "Invalid user_uuid: must be a Falcon user UUID such as "
                "'01234567-89ab-cdef-0123-456789abcdef'.",
                operation=operation,
            )
        return None

    @staticmethod
    def _check_case_id(value: Any, operation: str) -> dict[str, Any] | None:
        if not isinstance(value, str) or not CASE_ID_PATTERN.fullmatch(value.strip()):
            return _format_error_response(
                "Invalid case_id: use the `id` of a case from "
                "falcon_search_message_center_cases.",
                operation=operation,
            )
        return None

    @staticmethod
    def _check_ids(
        name: str, ids: Any, pattern: re.Pattern[str], operation: str
    ) -> list[str] | dict[str, Any]:
        if not isinstance(ids, list):
            return _format_error_response(f"`{name}` must be a list.", operation=operation)
        unique = list(dict.fromkeys(str(i).strip() for i in ids))
        bad = [i for i in unique if not pattern.fullmatch(i)]
        if bad:
            return _format_error_response(
                f"These `{name}` are not valid: {', '.join(bad[:10])}", operation=operation
            )
        if len(unique) > MAX_LINKED_IDS:
            return _format_error_response(
                f"At most {MAX_LINKED_IDS} `{name}` can be linked; got {len(unique)}.",
                operation=operation,
            )
        return unique

    def _spec(
        self, field: Any, filter: Any, interval: Any, size: Any
    ) -> dict[str, Any]:
        """Build one aggregation spec, or an error response for a bad field or interval."""
        if not isinstance(field, str) or not _FIELD_PATTERN.fullmatch(field):
            return _format_error_response(
                "Invalid field: use a field name such as 'severity' or 'case.status'."
            )
        if interval is not None and interval not in ("day", "week", "month", "year"):
            return _format_error_response(
                "Invalid interval: must be day, week, month or year."
            )
        if interval is not None:
            return self._build_aggregate_spec(
                "date_histogram", field, filter=filter, name=field, interval=interval
            )
        return self._build_aggregate_spec("terms", field, filter=filter, name=field, size=size)

    @staticmethod
    def _buckets(result: Any) -> list[dict[str, Any]]:
        """Return the buckets of the single aggregation in `result`."""
        if not isinstance(result, list) or not result or not isinstance(result[0], dict):
            return []
        return [
            {"label": bucket.get("label"), "count": bucket.get("count")}
            for bucket in result[0].get("buckets") or []
            if isinstance(bucket, dict)
        ]

    @staticmethod
    def _validate_case_ids(ids: Any) -> list[str] | dict[str, Any]:
        """Return the de-duplicated case IDs, or an error response."""
        if not isinstance(ids, list) or not ids:
            return _format_error_response(
                "`ids` must list at least one Message Center case ID.",
                operation="GetCaseEntitiesByIDs",
            )
        unique = list(dict.fromkeys(str(i).strip() for i in ids))
        bad = [i for i in unique if not CASE_ID_PATTERN.fullmatch(i)]
        if bad:
            return _format_error_response(
                f"These are not Message Center case IDs: {', '.join(bad[:10])}",
                operation="GetCaseEntitiesByIDs",
            )
        if len(unique) > MAX_CASE_IDS:
            return _format_error_response(
                f"At most {MAX_CASE_IDS} case IDs can be given at once; got {len(unique)}.",
                operation="GetCaseEntitiesByIDs",
            )
        return unique
