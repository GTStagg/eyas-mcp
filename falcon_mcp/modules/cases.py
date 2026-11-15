"""
Case Management module for Falcon MCP Server.

This module provides tools for managing CrowdStrike cases, including searching,
creating, updating, and managing evidence and tags.
"""

import re
from typing import Any, Literal

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from mcp.types import ToolAnnotations
from pydantic import AnyUrl, Field

from falcon_mcp.common.errors import _format_error_response, handle_api_response
from falcon_mcp.common.logging import get_logger
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.cases import (
    AGGREGATE_CASE_CONFIG_FQL_DOCUMENTATION,
    AGGREGATE_CASE_FILE_DETAILS_FQL_DOCUMENTATION,
    SEARCH_CASES_FQL_DOCUMENTATION,
)

logger = get_logger(__name__)


# Characters that would end or extend a quoted FQL value
FQL_SPECIAL_CHARS = frozenset("'\"[],\\")

# Retrieving files from hosts into cases
DEVICE_ID_PATTERN = re.compile(r"[0-9a-fA-F]{32}")
SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}")
SESSION_ID_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
MAX_FILE_PATH = 1024
MAX_FILE_DESCRIPTION = 1000
MAX_CASE_FILES = 500

# Tools that reach a host over RTR or add evidence to a case
_ADDS_EVIDENCE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)


def _check_case_file_inputs(
    operation: str,
    case_id: str | None = None,
    device_id: str | None = None,
    file_path: str | None = None,
    description: str | None = None,
) -> dict[str, Any] | None:
    """Validate the IDs and path of a host-to-case file request; None when they're fine."""
    if case_id is not None and (
        not case_id.strip() or CONTROL_CHARS.search(case_id) or len(case_id) > 128
    ):
        return _format_error_response(
            "Invalid case_id. Find case IDs with falcon_search_cases.", operation=operation
        )
    if device_id is not None and not DEVICE_ID_PATTERN.fullmatch(device_id.strip()):
        return _format_error_response(
            "device_id must be a host AID (32 hexadecimal characters).", operation=operation
        )
    if file_path is not None and (
        not file_path.strip() or CONTROL_CHARS.search(file_path) or len(file_path) > MAX_FILE_PATH
    ):
        return _format_error_response(
            f"file_path must be a full path on the host, at most {MAX_FILE_PATH} characters, "
            "without control characters.",
            operation=operation,
        )
    if description is not None and len(description) > MAX_FILE_DESCRIPTION:
        return _format_error_response(
            f"description must be at most {MAX_FILE_DESCRIPTION} characters.", operation=operation
        )
    return None


def _is_filter_error(error: dict[str, Any]) -> bool:
    """Report whether an aggregate error blames the FQL filter.

    Reads the API's own messages rather than the assembled error string, which
    carries generic filter-syntax advice on every 400.

    Args:
        error: An error dict from `_base_aggregate`

    Returns:
        True when a message points at the filter rather than at the
        aggregation field or type
    """
    details = error.get("details")
    body = details.get("body") if isinstance(details, dict) else None
    api_errors = body.get("errors") if isinstance(body, dict) else None
    if not isinstance(api_errors, list):
        return False
    return any(
        "filter" in str(item.get("message", "")).lower()
        for item in api_errors
        if isinstance(item, dict)
    )


class CasesModule(BaseModule):
    """Case Management module for Falcon MCP Server.

    This module provides tools for managing CrowdStrike cases including
    case lifecycle, evidence attachment, tagging, and template listing.

    Required API Scopes:
    - Cases:read
    - Cases:write
    - Case Templates:read
    """

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(server=server, method=self.search_cases, name="search_cases")
        self._add_tool(server=server, method=self.get_cases, name="get_cases")
        self._add_tool(
            server=server,
            method=self.create_case,
            name="create_case",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )
        self._add_tool(
            server=server,
            method=self.update_case,
            name="update_case",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )
        self._add_tool(
            server=server,
            method=self.add_case_alert_evidence,
            name="add_case_alert_evidence",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )
        self._add_tool(
            server=server,
            method=self.add_case_event_evidence,
            name="add_case_event_evidence",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )
        self._add_tool(
            server=server,
            method=self.manage_case_tags,
            name="manage_case_tags",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )
        self._add_tool(
            server=server,
            method=self.list_case_templates,
            name="list_case_templates",
        )
        self._add_tool(
            server=server,
            method=self.aggregate_case_slas,
            name="aggregate_case_slas",
        )
        self._add_tool(
            server=server,
            method=self.aggregate_case_templates,
            name="aggregate_case_templates",
        )
        self._add_tool(
            server=server,
            method=self.aggregate_case_access_tags,
            name="aggregate_case_access_tags",
        )
        self._add_tool(
            server=server,
            method=self.aggregate_case_notification_groups,
            name="aggregate_case_notification_groups",
        )
        self._add_tool(
            server=server,
            method=self.aggregate_case_file_details,
            name="aggregate_case_file_details",
        )
        self._add_tool(server=server, method=self.search_case_files, name="search_case_files")
        self._add_tool(
            server=server,
            method=self.get_rtr_file_metadata,
            name="get_rtr_file_metadata",
            annotations=ToolAnnotations(
                readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
            ),
        )
        self._add_tool(
            server=server,
            method=self.retrieve_rtr_file_to_case,
            name="retrieve_rtr_file_to_case",
            annotations=_ADDS_EVIDENCE,
        )
        self._add_tool(
            server=server,
            method=self.add_rtr_session_file_to_case,
            name="add_rtr_session_file_to_case",
            annotations=_ADDS_EVIDENCE,
        )

    def register_resources(self, server: FastMCP) -> None:
        resource = TextResource(
            uri=AnyUrl("falcon://cases/search/fql-guide"),
            name="falcon_search_cases_fql_guide",
            description="Contains the guide for the `filter` param of the `falcon_search_cases` tool.",
            text=SEARCH_CASES_FQL_DOCUMENTATION,
        )
        self._add_resource(server, resource)
        self._add_resource(
            server,
            TextResource(
                uri=AnyUrl("falcon://cases/aggregates/fql-guide"),
                name="falcon_aggregate_case_config_fql_guide",
                description=(
                    "Contains the guide for the `filter` param of the "
                    "`falcon_aggregate_case_slas`, `falcon_aggregate_case_templates`, "
                    "`falcon_aggregate_case_access_tags`, and "
                    "`falcon_aggregate_case_notification_groups` tools."
                ),
                text=AGGREGATE_CASE_CONFIG_FQL_DOCUMENTATION,
            ),
        )
        self._add_resource(
            server,
            TextResource(
                uri=AnyUrl("falcon://cases/file-aggregates/fql-guide"),
                name="falcon_aggregate_case_file_details_fql_guide",
                description=(
                    "Contains the guide for the `filter` param of the "
                    "`falcon_aggregate_case_file_details` tool."
                ),
                text=AGGREGATE_CASE_FILE_DETAILS_FQL_DOCUMENTATION,
            ),
        )

    def search_cases(
        self,
        filter: str | None = Field(
            default=None,
            description="FQL filter expression. See `falcon://cases/search/fql-guide` for syntax.",
            examples=["status:'new'+severity:>70", "assigned_to_name:'Alice'"],
        ),
        limit: int = Field(
            default=10,
            ge=1,
            le=500,
            description="Maximum number of cases to return (default: 10, max: 500).",
        ),
        offset: int | None = Field(
            default=None,
            description="Starting index for pagination.",
        ),
        q: str | None = Field(
            default=None,
            description="Free-text search across all case metadata.",
        ),
        sort: str | None = Field(
            default=None,
            description="Sort order. Fields: created_timestamp, updated_timestamp, severity, status, name, reference_id. Prefer the dot separator ('field.desc'), which is supported on every Falcon sort endpoint; the pipe form ('field|asc') also works here. Example: 'created_timestamp.desc'",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Find cases by criteria and return their complete details.

        Use this to discover cases by status, severity, assignee, time range, or
        evidence attributes. Consult falcon://cases/search/fql-guide before
        constructing filter expressions. Returns full case records including
        status, severity, evidence, assigned user, and analysis results.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        case_ids, pagination = self._base_search_with_meta(
            operation="queries_cases_get_v1",
            search_params={
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "q": q,
                "sort": sort,
            },
            error_message="Failed to search cases",
        )

        if self._is_error(case_ids):
            return self._format_fql_error_response(
                [case_ids], filter, SEARCH_CASES_FQL_DOCUMENTATION
            )

        if not case_ids:
            return self._build_pagination_envelope([], pagination, filter)

        details = self._base_get_by_ids(
            operation="entities_cases_post_v2",
            ids=case_ids,
        )

        if self._is_error(details):
            return [details]

        # entities_cases_post_v2 returns cases in arbitrary order; restore the sort
        # applied by the query step (validated against live API: field is id).
        details = self._reorder_by_ids(case_ids, details, id_field="id")
        return self._build_pagination_envelope(details, pagination, filter)

    def get_cases(
        self,
        ids: list[str] = Field(
            description="Case ID(s) to retrieve. These are opaque system IDs, not the human-readable reference_id.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Retrieve details for case IDs you already have.

        Use when you have specific case IDs from search results or external
        references. For discovering cases by criteria, use falcon_search_cases;
        for files attached to a case, use falcon_aggregate_case_file_details.
        Returns full case records. Their `analysis_results.files` field lists
        forensic artifacts from detections, not attachments, and is empty for
        cases that do have attachments.
        """
        return self._base_get_by_ids(
            operation="entities_cases_post_v2",
            ids=ids,
        )

    def create_case(
        self,
        name: str = Field(
            description="Case name (max 256 characters).",
        ),
        severity: int = Field(
            description="Severity level (1-100). 1=Informational, ~25=Low, ~50=Medium, ~75=High, 100=Critical.",
            ge=1,
            le=100,
        ),
        description: str | None = Field(
            default=None,
            description="Case description (max 2048 characters).",
        ),
        description_format: Literal["markdown", "plaintext"] | None = Field(
            default=None,
            description="Rendering format for the description. Omit to leave it unset.",
        ),
        status: str | None = Field(
            default=None,
            description="Initial status. Values: new, in_progress. Defaults to 'new' if omitted.",
        ),
        assigned_to_user_uuid: str | None = Field(
            default=None,
            description="UUID of the user to assign the case to.",
        ),
        tags: list[str] | None = Field(
            default=None,
            description="Tags to apply (128 combined character limit across all tags).",
        ),
        template_id: str | None = Field(
            default=None,
            description="Template ID to apply to the case.",
        ),
        alert_ids: list[str] | None = Field(
            default=None,
            description="Alert composite IDs to attach as evidence (from Alerts v2 API). Max 100 total evidence items.",
        ),
        event_ids: list[str] | None = Field(
            default=None,
            description="LogScale event IDs to attach as evidence (from falcon_search_ngsiem). Max 100 total evidence items.",
        ),
    ) -> list[dict[str, Any]]:
        """Create a new case in CrowdStrike.

        Provide a name and severity at minimum. Optionally attach alert or event
        evidence, assign a user, apply a template, and set tags. Returns the
        created case record.
        """
        body: dict[str, Any] = {
            "name": name,
            "severity": severity,
        }

        if description is not None:
            body["description"] = description
        if description_format is not None:
            body["description_format"] = description_format
        if status is not None:
            body["status"] = status
        if assigned_to_user_uuid is not None:
            body["assigned_to_user_uuid"] = assigned_to_user_uuid
        if tags is not None:
            body["tags"] = tags
        if template_id is not None:
            body["template"] = {"id": template_id}

        evidence: dict[str, Any] = {}
        if alert_ids:
            evidence["alerts"] = [{"id": aid} for aid in alert_ids]
        if event_ids:
            evidence["events"] = [{"id": eid} for eid in event_ids]
        if evidence:
            body["evidence"] = evidence

        result = self._base_query_api_call(
            operation="entities_cases_put_v2",
            body_params=body,
            error_message="Failed to create case",
            default_result=[],
        )

        if self._is_error(result):
            return [result]

        return result

    def update_case(
        self,
        id: str = Field(
            description="Case ID to update (the opaque system ID, not reference_id).",
        ),
        name: str | None = Field(
            default=None,
            description="New case name.",
        ),
        description: str | None = Field(
            default=None,
            description="New case description.",
        ),
        description_format: Literal["markdown", "plaintext"] | None = Field(
            default=None,
            description="Rendering format for the description. Left unchanged when omitted.",
        ),
        status: str | None = Field(
            default=None,
            description="New status. Values: new, in_progress, closed, reopened.",
        ),
        severity: int | None = Field(
            default=None,
            description="New severity (1-100).",
            ge=1,
            le=100,
        ),
        assigned_to_user_uuid: str | None = Field(
            default=None,
            description="UUID of user to assign. Use remove_user_assignment=True to unassign instead.",
        ),
        remove_user_assignment: bool | None = Field(
            default=None,
            description="Set to True to remove the current user assignment.",
        ),
        template_id: str | None = Field(
            default=None,
            description="Template ID to apply to the case.",
        ),
        expected_version: int | None = Field(
            default=None,
            description="Expected case version for optimistic concurrency. If provided and mismatched, the update returns 409 Conflict.",
        ),
    ) -> list[dict[str, Any]]:
        """Update an existing case's fields.

        Provide the case ID and any fields to change. Use expected_version for
        optimistic concurrency control to prevent conflicting updates. Returns the
        updated case record with incremented version.
        """
        fields: dict[str, Any] = {}
        if name is not None:
            fields["name"] = name
        if description is not None:
            fields["description"] = description
        if description_format is not None:
            fields["description_format"] = description_format
        if status is not None:
            fields["status"] = status
        if severity is not None:
            fields["severity"] = severity
        if assigned_to_user_uuid is not None:
            fields["assigned_to_user_uuid"] = assigned_to_user_uuid
        if remove_user_assignment is not None:
            fields["remove_user_assignment"] = remove_user_assignment
        if template_id is not None:
            fields["template"] = {"id": template_id}

        if not fields:
            return [
                _format_error_response(
                    "At least one field to update must be provided.",
                    operation="entities_cases_patch_v2",
                )
            ]

        body: dict[str, Any] = {
            "id": id,
            "fields": fields,
        }
        if expected_version is not None:
            body["expected_version"] = expected_version

        result = self._base_query_api_call(
            operation="entities_cases_patch_v2",
            body_params=body,
            error_message="Failed to update case",
            default_result=[],
        )

        if self._is_error(result):
            return [result]

        return result

    def add_case_alert_evidence(
        self,
        id: str = Field(
            description="Case ID to add alert evidence to.",
        ),
        alert_ids: list[str] = Field(
            description="Alert composite IDs to attach (from Alerts v2 API). Max 100 total evidence items per case.",
        ),
    ) -> list[dict[str, Any]]:
        """Attach alert evidence to an existing case.

        Provide alert composite_id values from the Alerts v2 API (e.g. from
        falcon_search_detections). Each case supports a maximum of 100 combined
        evidence items. Returns the updated case record.
        """
        body = {
            "id": id,
            "alerts": [{"id": aid} for aid in alert_ids],
        }

        result = self._base_query_api_call(
            operation="entities_alert_evidence_post_v1",
            body_params=body,
            error_message="Failed to add alert evidence",
            default_result=[],
        )

        if self._is_error(result):
            return [result]

        return result

    def add_case_event_evidence(
        self,
        id: str = Field(
            description="Case ID to add event evidence to.",
        ),
        event_ids: list[str] = Field(
            description="LogScale event IDs to attach (from falcon_search_ngsiem). Max 100 total evidence items per case.",
        ),
    ) -> list[dict[str, Any]]:
        """Attach LogScale event evidence to an existing case.

        Provide event IDs obtained from falcon_search_ngsiem or the Falcon
        console. Each case supports a maximum of 100 combined evidence items.
        Returns the updated case record.
        """
        body = {
            "id": id,
            "events": [{"id": eid} for eid in event_ids],
        }

        result = self._base_query_api_call(
            operation="entities_event_evidence_post_v1",
            body_params=body,
            error_message="Failed to add event evidence",
            default_result=[],
        )

        if self._is_error(result):
            return [result]

        return result

    def manage_case_tags(
        self,
        id: str = Field(
            description="Case ID to manage tags for.",
        ),
        action: str = Field(
            description="Action to perform. Values: 'add' or 'remove'.",
        ),
        tags: list[str] = Field(
            description="Tags to add or remove. 128 combined character limit across all tags on a case.",
        ),
    ) -> list[dict[str, Any]]:
        """Add or remove tags on a case.

        Set action to 'add' to attach new tags, or 'remove' to delete existing
        tags. Returns the updated case record.
        """
        if action == "add":
            body = {"id": id, "tags": tags}
            result = self._base_query_api_call(
                operation="entities_case_tags_post_v1",
                body_params=body,
                error_message="Failed to add case tags",
                default_result=[],
            )
        elif action == "remove":
            result = self._base_query_api_call(
                operation="entities_case_tags_delete_v1",
                query_params={"id": id, "tag": tags},
                error_message="Failed to remove case tags",
                default_result=[],
            )
        else:
            return [
                _format_error_response(
                    "Invalid action. Must be 'add' or 'remove'.",
                    operation="entities_case_tags_post_v1",
                )
            ]

        if self._is_error(result):
            return [result]

        return result

    def list_case_templates(
        self,
        limit: int = Field(
            default=50,
            ge=1,
            le=200,
            description="Maximum number of templates to return (default: 50, max: 200).",
        ),
        offset: int | None = Field(
            default=None,
            description="Starting index for pagination.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """List available case templates.

        Use to discover templates that can be applied when creating or updating
        cases. Returns template details including name, custom fields, and SLA
        configuration.
        """
        template_ids = self._base_search_api_call(
            operation="queries_templates_get_v1",
            search_params={"limit": limit, "offset": offset},
            error_message="Failed to query case templates",
        )

        if self._is_error(template_ids):
            return [template_ids]

        if not template_ids:
            return []

        details = self._base_get_by_ids(
            operation="entities_templates_get_v1",
            ids=template_ids,
            use_params=True,
        )

        if self._is_error(details):
            return [details]

        # Preserve the query-step order in case the details endpoint reorders results.
        return self._reorder_by_ids(template_ids, details, id_field="id")

    def _aggregate_case_config(
        self,
        operation: str,
        entity: str,
        agg_type: Literal["terms", "date_range"],
        field: str,
        filter: str | None,
        size: int | None,
        from_: int | None,
        date_ranges: list[dict[str, Any]] | None,
        name: str | None,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Run one aggregation against a /casemgmt/aggregates/* endpoint.

        These four endpoints share the reduced `api.MSAAggregateQueryRequest`
        dialect, so they differ only in operation name and which fields they
        accept.
        """
        result = self._base_aggregate(
            operation=operation,
            agg_type=agg_type,
            field=field,
            filter=filter,
            size=size,
            from_=from_,
            date_ranges=date_ranges,
            name=name,
            error_message=f"Failed to aggregate case {entity}",
        )

        # Only a filter problem is worth answering with the FQL guide; an
        # unsupported aggregation field or type is a different fix.
        if self._is_error(result):
            if _is_filter_error(result):
                return self._format_fql_error_response(
                    [result], filter, AGGREGATE_CASE_CONFIG_FQL_DOCUMENTATION
                )
            return [result]

        return result

    def aggregate_case_slas(
        self,
        field: str = Field(
            description="Field to aggregate on. Supported: name, id, cid, created_by_name, updated_by_name, created_timestamp, updated_timestamp.",
            examples=["name", "created_by_name"],
        ),
        agg_type: Literal["terms", "date_range"] = Field(
            default="terms",
            description="Aggregation type. 'terms' counts records per distinct value; 'date_range' counts records per date_ranges bucket.",
        ),
        filter: str | None = Field(
            default=None,
            description="FQL filter expression. See `falcon://cases/aggregates/fql-guide` for syntax.",
            examples=["created_timestamp:>'now-30d'", "name:*'*Corp*'"],
        ),
        size: int | None = Field(
            default=None,
            ge=1,
            description="Maximum number of buckets to return. Omit for all buckets.",
        ),
        from_: int | None = Field(
            default=None,
            ge=0,
            description="Bucket offset, for paging through a large bucket list.",
        ),
        date_ranges: list[dict[str, Any]] | None = Field(
            default=None,
            description="Date buckets for agg_type='date_range', each {'from': ISO8601, 'to': ISO8601}.",
        ),
        name: str | None = Field(
            default=None,
            description="Label echoed back on the result to identify this aggregation.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Count case SLA definitions grouped by a field.

        Use this to summarize the SLA policies configured in your tenant — for
        example how many exist, or who created them — rather than to list them
        individually. Consult falcon://cases/aggregates/fql-guide before
        constructing filter expressions. Returns buckets of `label` and `count`.
        Requires the Case Templates:read scope.
        """
        return self._aggregate_case_config(
            operation="aggregates_slas_post_v1",
            entity="SLAs",
            agg_type=agg_type,
            field=field,
            filter=filter,
            size=size,
            from_=from_,
            date_ranges=date_ranges,
            name=name,
        )

    def aggregate_case_templates(
        self,
        field: str = Field(
            description="Field to aggregate on. Supported: name, id, cid, created_by_name, updated_by_name, created_timestamp, updated_timestamp.",
            examples=["name", "created_by_name"],
        ),
        agg_type: Literal["terms", "date_range"] = Field(
            default="terms",
            description="Aggregation type. 'terms' counts records per distinct value; 'date_range' counts records per date_ranges bucket.",
        ),
        filter: str | None = Field(
            default=None,
            description="FQL filter expression. See `falcon://cases/aggregates/fql-guide` for syntax.",
            examples=["created_timestamp:>'now-30d'", "created_by_name:'analyst@example.com'"],
        ),
        size: int | None = Field(
            default=None,
            ge=1,
            description="Maximum number of buckets to return. Omit for all buckets.",
        ),
        from_: int | None = Field(
            default=None,
            ge=0,
            description="Bucket offset, for paging through a large bucket list.",
        ),
        date_ranges: list[dict[str, Any]] | None = Field(
            default=None,
            description="Date buckets for agg_type='date_range', each {'from': ISO8601, 'to': ISO8601}.",
        ),
        name: str | None = Field(
            default=None,
            description="Label echoed back on the result to identify this aggregation.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Count case templates grouped by a field.

        Use this to summarize the case templates configured in your tenant, such
        as how many exist or which users author them; falcon_list_case_templates
        returns the individual template records instead. Consult
        falcon://cases/aggregates/fql-guide before constructing filter
        expressions. Returns buckets of `label` and `count`. Requires the
        Case Templates:read scope.
        """
        return self._aggregate_case_config(
            operation="aggregates_templates_post_v1",
            entity="templates",
            agg_type=agg_type,
            field=field,
            filter=filter,
            size=size,
            from_=from_,
            date_ranges=date_ranges,
            name=name,
        )

    def aggregate_case_access_tags(
        self,
        field: str = Field(
            description="Field to aggregate on. Access tags support only: key, id, cid.",
            examples=["key"],
        ),
        agg_type: Literal["terms", "date_range"] = Field(
            default="terms",
            description="Aggregation type. 'terms' counts records per distinct value; 'date_range' counts records per date_ranges bucket.",
        ),
        filter: str | None = Field(
            default=None,
            description="FQL filter expression. See `falcon://cases/aggregates/fql-guide` for syntax.",
            examples=["key:'ANALYST1'", "key:*'*ANALYST*'"],
        ),
        size: int | None = Field(
            default=None,
            ge=1,
            description="Maximum number of buckets to return. Omit for all buckets.",
        ),
        from_: int | None = Field(
            default=None,
            ge=0,
            description="Bucket offset, for paging through a large bucket list.",
        ),
        date_ranges: list[dict[str, Any]] | None = Field(
            default=None,
            description="Date buckets for agg_type='date_range', each {'from': ISO8601, 'to': ISO8601}.",
        ),
        name: str | None = Field(
            default=None,
            description="Label echoed back on the result to identify this aggregation.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Count case access tags grouped by a field.

        Use this to see which access tags control case visibility in your tenant
        and how many of each exist. Access tags accept a narrower field set than
        the other case aggregates — only key, id, and cid. Consult
        falcon://cases/aggregates/fql-guide before constructing filter
        expressions. Returns buckets of `label` and `count`. Requires the
        Case Templates:read scope.
        """
        return self._aggregate_case_config(
            operation="aggregates_access_tags_post_v1",
            entity="access tags",
            agg_type=agg_type,
            field=field,
            filter=filter,
            size=size,
            from_=from_,
            date_ranges=date_ranges,
            name=name,
        )

    def aggregate_case_notification_groups(
        self,
        field: str = Field(
            description="Field to aggregate on. Supported: name, id, cid, created_by_name, updated_by_name, created_timestamp, updated_timestamp.",
            examples=["name", "created_by_name"],
        ),
        agg_type: Literal["terms", "date_range"] = Field(
            default="terms",
            description="Aggregation type. 'terms' counts records per distinct value; 'date_range' counts records per date_ranges bucket.",
        ),
        filter: str | None = Field(
            default=None,
            description="FQL filter expression. See `falcon://cases/aggregates/fql-guide` for syntax.",
            examples=["name:*'*Analyst*'", "created_timestamp:>'now-90d'"],
        ),
        size: int | None = Field(
            default=None,
            ge=1,
            description="Maximum number of buckets to return. Omit for all buckets.",
        ),
        from_: int | None = Field(
            default=None,
            ge=0,
            description="Bucket offset, for paging through a large bucket list.",
        ),
        date_ranges: list[dict[str, Any]] | None = Field(
            default=None,
            description="Date buckets for agg_type='date_range', each {'from': ISO8601, 'to': ISO8601}.",
        ),
        name: str | None = Field(
            default=None,
            description="Label echoed back on the result to identify this aggregation.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Count case notification groups grouped by a field.

        Use this to summarize the notification groups that receive case updates,
        such as how many are configured or who created them. Consult
        falcon://cases/aggregates/fql-guide before constructing filter
        expressions. Returns buckets of `label` and `count`. Requires the
        Case Templates:read scope.
        """
        return self._aggregate_case_config(
            operation="aggregates_notification_groups_post_v2",
            entity="notification groups",
            agg_type=agg_type,
            field=field,
            filter=filter,
            size=size,
            from_=from_,
            date_ranges=date_ranges,
            name=name,
        )

    def aggregate_case_file_details(
        self,
        field: str = Field(
            description="Field to aggregate on. Supported: name, case_id, id, cid, file_size (a human-readable string such as '114.8 KB').",
            examples=["name", "case_id"],
        ),
        agg_type: Literal["terms", "date_range"] = Field(
            default="terms",
            description="Aggregation type. 'terms' counts files per distinct value; 'date_range' counts files per date_ranges bucket.",
        ),
        case_ids: list[str] | None = Field(
            default=None,
            description="Case ID(s) to restrict the aggregation to. Omit to aggregate files across all cases.",
        ),
        filter: str | None = Field(
            default=None,
            description="FQL filter expression. See `falcon://cases/file-aggregates/fql-guide` for syntax.",
            examples=["name:*'*.png'"],
        ),
        size: int | None = Field(
            default=None,
            ge=1,
            description="Maximum number of buckets to return. Omit for all buckets.",
        ),
        from_: int | None = Field(
            default=None,
            ge=0,
            description="Bucket offset, for paging through a large bucket list.",
        ),
        date_ranges: list[dict[str, Any]] | None = Field(
            default=None,
            description="Date buckets for agg_type='date_range', each {'from': ISO8601, 'to': ISO8601}.",
        ),
        name: str | None = Field(
            default=None,
            description="Label echoed back on the result to identify this aggregation.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Report the files attached to cases, grouped and counted by a field.

        Use this whenever a question mentions files, attachments or screenshots
        on a case, including "what files are attached to case X" and "how many
        files does case X have" — pass the case IDs as case_ids. Case records
        from falcon_get_cases do not list attachments; their
        `analysis_results.files` field holds forensic artifacts from detections
        and is empty for cases that do have attachments. Consult
        falcon://cases/file-aggregates/fql-guide before constructing filter
        expressions. Returns buckets of `label` and `count`. Requires the
        Cases:read scope.
        """
        # The endpoint's `ids` query parameter does not narrow the result set
        # (live-validated), so case scoping is expressed as a case_id filter,
        # which does. `ids` is still sent because the API marks it required.
        scoped_filter = filter
        if case_ids:
            bad_ids = [i for i in case_ids if not i or set(i) & FQL_SPECIAL_CHARS]
            if bad_ids:
                return [
                    _format_error_response(
                        f"Invalid case_ids {bad_ids}: a case ID can't be empty or contain "
                        "quotes, brackets, commas or backslashes.",
                        operation="aggregates_file_details_post_v1",
                    )
                ]
            id_list = ",".join(f"'{case_id}'" for case_id in case_ids)
            scope = f"case_id:[{id_list}]"
            # The caller's filter is parenthesized so an OR inside it cannot
            # widen the result beyond the requested cases.
            scoped_filter = f"{scope}+({filter})" if filter else scope

        result = self._base_aggregate(
            operation="aggregates_file_details_post_v1",
            agg_type=agg_type,
            field=field,
            filter=scoped_filter,
            size=size,
            from_=from_,
            date_ranges=date_ranges,
            name=name,
            error_message="Failed to aggregate case file details",
            parameters={"ids": case_ids} if case_ids else None,
        )

        if self._is_error(result):
            if _is_filter_error(result):
                return self._format_fql_error_response(
                    [result],
                    scoped_filter,
                    AGGREGATE_CASE_FILE_DETAILS_FQL_DOCUMENTATION,
                )
            return [result]

        return result

    # ------------------------------------------------------------------ #
    # Case files and retrieving files from hosts
    # ------------------------------------------------------------------ #

    def search_case_files(
        self,
        case_id: str | None = Field(
            default=None,
            description="Only files attached to this case. Find case IDs with falcon_search_cases.",
        ),
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter on case files, e.g. name:*'*.exe'. See "
                "`falcon://cases/file-aggregates/fql-guide`."
            ),
        ),
        limit: int = Field(
            default=50, ge=1, le=MAX_CASE_FILES,
            description=f"The maximum files to return. [1-{MAX_CASE_FILES}]",
        ),
        offset: int = Field(default=0, ge=0, description="The offset to start from."),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """List the files attached to cases: name, size, type, SHA256, who added them and when.

        Use this to see a case's evidence files, including ones retrieved from hosts
        with falcon_retrieve_rtr_file_to_case. Each record has `id`, `name`, `case_id`,
        `file_size`, `file_type`, `hash_value`, `description`, `uploaded_on`,
        `uploaded_by` and `source`. The API does not report how many files match in
        total; `pagination.next_offset` is set when a full page came back.
        """
        operation = "combined_file_details_get_v1"
        scoped = filter
        if case_id is not None:
            if not case_id.strip() or set(case_id) & FQL_SPECIAL_CHARS:
                return _format_error_response(
                    "Invalid case_id: it can't be empty or contain quotes, brackets, commas "
                    "or backslashes.",
                    operation=operation,
                )
            scope = f"case_id:'{case_id.strip()}'"
            # Parenthesized so an OR in the caller's filter can't widen the scope
            scoped = f"{scope}+({filter})" if filter else scope

        parameters: dict[str, Any] = {"limit": limit, "offset": offset}
        if scoped:
            parameters["filter"] = scoped
        response = self.client.command(operation, parameters=parameters)
        files = handle_api_response(
            response, operation=operation, error_message="Failed to list case files"
        )
        if isinstance(files, dict):
            return self._format_fql_error_response(
                [files], scoped, AGGREGATE_CASE_FILE_DETAILS_FQL_DOCUMENTATION
            )
        return {
            "results": files,
            # The API's pagination.total echoes the page size, so it isn't reported
            "pagination": {
                "offset": offset,
                "limit": limit,
                "total": None,
                "next_offset": offset + len(files) if len(files) >= limit else None,
            },
        }

    def get_rtr_file_metadata(
        self,
        device_id: str = Field(description="The host's AID. Find it with falcon_search_hosts."),
        file_path: str = Field(
            description="Full path of the file on the host, e.g. C:\\Users\\Public\\a.exe.",
        ),
    ) -> dict[str, Any] | list[Any]:
        """Read a file's metadata on a host over RTR, without retrieving the file.

        Use this to confirm a file exists on a host and see its details before
        retrieving it into a case with falcon_retrieve_rtr_file_to_case. The host must
        be online. Nothing on the host changes, but the request goes through an RTR
        session on it. Returns the API's response.
        """
        operation = "entities_get_rtr_file_metadata_post_v1"
        problem = _check_case_file_inputs(operation, device_id=device_id, file_path=file_path)
        if problem:
            return problem
        response = self.client.command(
            operation,
            body={"aid": device_id.strip().lower(), "file_path": file_path.strip()},
        )
        result: dict[str, Any] | list[Any] = handle_api_response(
            response, operation=operation, error_message="Failed to read the file's metadata"
        )
        return result

    def retrieve_rtr_file_to_case(
        self,
        case_id: str = Field(description="The case to add the file to."),
        device_id: str = Field(description="The host's AID. Find it with falcon_search_hosts."),
        file_path: str = Field(
            description="Full path of the file on the host, e.g. C:\\Users\\Public\\a.exe.",
        ),
        description: str | None = Field(
            default=None, description="Why the file is being collected."
        ),
    ) -> dict[str, Any] | list[Any]:
        """Collect a file from a host over RTR and attach it to a case as evidence.

        The file goes straight from the host into the case; its content never passes
        through this server. Use this to preserve a suspicious executable, script or
        document during an investigation. The host must be online. Afterwards the file
        appears in falcon_search_case_files with its SHA256. Returns the API's response.
        """
        operation = "entities_retrieve_rtr_file_post_v1"
        problem = _check_case_file_inputs(
            operation, case_id=case_id, device_id=device_id, file_path=file_path,
            description=description,
        )
        if problem:
            return problem
        body: dict[str, Any] = {
            "case_id": case_id.strip(),
            "aid": device_id.strip().lower(),
            "file_path": file_path.strip(),
        }
        if description and description.strip():
            body["description"] = description.strip()
        response = self.client.command(operation, body=body)
        result: dict[str, Any] | list[Any] = handle_api_response(
            response, operation=operation, error_message="Failed to retrieve the file into the case"
        )
        return result

    def add_rtr_session_file_to_case(
        self,
        case_id: str = Field(description="The case to add the file to."),
        device_id: str = Field(description="The host's AID the file came from."),
        session_id: str = Field(
            description="The RTR session that collected the file, from falcon_list_rtr_session_files.",
        ),
        sha256: str = Field(
            description="SHA256 of the collected file, from falcon_list_rtr_session_files.",
        ),
        description: str | None = Field(
            default=None, description="Why the file is being added."
        ),
    ) -> dict[str, Any] | list[Any]:
        """Attach a file an RTR session already collected (with `get`) to a case.

        Use this when an analyst has fetched a file in an RTR session and it should be
        kept with the case. List a session's collected files and their SHA256 with
        falcon_list_rtr_session_files. Returns the API's response.
        """
        operation = "entities_retrieve_rtr_recent_file_post_v1"
        problem = _check_case_file_inputs(
            operation, case_id=case_id, device_id=device_id, description=description
        )
        if problem:
            return problem
        if not SESSION_ID_PATTERN.fullmatch(session_id.strip()):
            return _format_error_response(
                "session_id must be an RTR session ID (a UUID).", operation=operation
            )
        if not SHA256_PATTERN.fullmatch(sha256.strip()):
            return _format_error_response(
                "sha256 must be 64 hexadecimal characters.", operation=operation
            )
        body: dict[str, Any] = {
            "case_id": case_id.strip(),
            "aid": device_id.strip().lower(),
            "session_id": session_id.strip().lower(),
            "sha256": sha256.strip().lower(),
        }
        if description and description.strip():
            body["description"] = description.strip()
        response = self.client.command(operation, body=body)
        result: dict[str, Any] | list[Any] = handle_api_response(
            response, operation=operation, error_message="Failed to add the session file to the case"
        )
        return result
