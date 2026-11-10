"""
Detections module for Falcon MCP Server

This module provides tools for accessing and analyzing CrowdStrike Falcon detections.
"""

import re
from textwrap import dedent
from typing import Any, Literal

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from mcp.types import ToolAnnotations
from pydantic import AnyUrl, Field

from falcon_mcp.common.errors import _format_error_response
from falcon_mcp.common.logging import get_logger
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.detections import (
    SEARCH_DETECTIONS_FQL_DOCUMENTATION,
)

logger = get_logger(__name__)

# PatchEntitiesAlertsV3 rejects requests carrying more than this many composite
# IDs with HTTP 413 ("request too large").
MAX_UPDATE_COMPOSITE_IDS = 1000

# Host agent IDs are 32 hex characters; the ID is written into an FQL filter.
DEVICE_ID_PATTERN = re.compile(r"[0-9a-fA-F]{32}")
OPEN_STATUSES = ("new", "in_progress", "reopened")
RESOLUTION_TAGS = ("true_positive", "false_positive", "ignored")
# GetQueriesAlertsV2 pages; a host with more open detections than this is reported
# as truncated, and running the tool again closes the rest.
HOST_DETECTIONS_PAGE_SIZE = 1000
MAX_HOST_DETECTIONS = 10000
# Alerts that name the host somewhere other than device.device_id. NGSIEM
# correlation alerts carry no device block; they name hosts in agent_id,
# enriched_entities.aids and users[].aid instead (validated against the live API).
RELATED_HOST_FIELDS = ("agent_id", "enriched_entities.aids", "users.aid")
ALERT_ENTITY_BATCH = 100
MAX_SKIPPED_IDS_SHOWN = 100


class DetectionsModule(BaseModule):
    """Module for accessing and analyzing CrowdStrike Falcon detections."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(
            server=server,
            method=self.search_detections,
            name="search_detections",
        )

        self._add_tool(
            server=server,
            method=self.get_detection_details,
            name="get_detection_details",
        )

        self._add_tool(
            server=server,
            method=self.aggregate_detections,
            name="aggregate_detections",
        )

        self._add_tool(
            server=server,
            method=self.update_detections,
            name="update_detections",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.close_host_detections,
            name="close_host_detections",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP server.

        Args:
            server: MCP server instance
        """
        search_detections_fql_resource = TextResource(
            uri=AnyUrl("falcon://detections/search/fql-guide"),
            name="falcon_search_detections_fql_guide",
            description=(
                "Contains the guide for the `filter` param of the "
                "`falcon_search_detections` tool."
            ),
            text=SEARCH_DETECTIONS_FQL_DOCUMENTATION,
        )

        self._add_resource(
            server,
            search_detections_fql_resource,
        )

    def search_detections(
        self,
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter expression. See `falcon://detections/search/fql-guide`"
                " for syntax."
            ),
            examples=["status:'new'+severity_name:'High'", "device.hostname:'DC*'"],
        ),
        limit: int = Field(
            default=10,
            ge=1,
            le=9999,
            description=(
                "The maximum number of detections to return in this response (default: 10; "
                "max: 9999). Use with the offset parameter to manage pagination of results."
            ),
        ),
        offset: int | None = Field(
            default=None,
            description=(
                "The first detection to return, where 0 is the latest detection. Use with "
                "the offset parameter to manage pagination of results."
            ),
        ),
        q: str | None = Field(
            default=None,
            description="Search all detection metadata for the provided string",
        ),
        sort: str | None = Field(
            default=None,
            description=dedent("""
                Sort detections using these options:

                timestamp: Timestamp when the detection occurred
                created_timestamp: When the detection was created
                updated_timestamp: When the detection was last modified
                severity: Severity level of the detection (1-100, recommended when filtering
                by severity)
                confidence: Confidence level of the detection (1-100)
                agent_id: Agent ID associated with the detection

                Sort either asc (ascending) or desc (descending). Use the dot
                separator ('severity.desc'), which is supported on every Falcon
                sort endpoint. The pipe form ('severity|desc') is accepted here
                but rejected by some endpoints, so prefer the dot form.

                When searching for high severity detections, use 'severity.desc' to get the
                highest severity detections first.
                For chronological ordering, use 'timestamp.desc' for most recent detections first.

                Examples: 'severity.desc', 'timestamp.desc'
            """).strip(),
            examples=["severity.desc", "timestamp.desc"],
        ),
        include_hidden: bool = Field(
            default=True,
            description=(
                "Whether to include hidden detections (default: True). Set False to "
                "match the detection totals shown in the Falcon console."
            ),
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Find detections (also called alerts) by criteria and return their complete details.

        Use this to discover detections by severity, status, hostname, time range, or other
        attributes — this is the tool for general alert and detection queries. Covers alerts
        across all Falcon products: endpoint (EPP), identity (IDP), XDR, OverWatch, and
        NG-SIEM. Consult falcon://detections/search/fql-guide before constructing filter
        expressions. Returns full alert records including process context, device info,
        tactic/technique details, and threat classification.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        detection_ids, pagination = self._base_search_with_meta(
            operation="GetQueriesAlertsV2",
            search_params={
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "q": q,
                "sort": sort,
                "include_hidden": include_hidden,
            },
            error_message="Failed to search detections",
        )

        # Handle search error - return with FQL guide
        if self._is_error(detection_ids):
            return self._format_fql_error_response(
                [detection_ids], filter, SEARCH_DETECTIONS_FQL_DOCUMENTATION
            )

        # Handle empty results
        if not detection_ids:
            return self._build_pagination_envelope([], pagination, filter)

        # Get detection details - past FQL concerns, normal API flow
        details = self._base_get_by_ids(
            operation="PostEntitiesAlertsV2",
            ids=detection_ids,
            id_key="composite_ids",
            parameters={"include_hidden": include_hidden},
        )

        if self._is_error(details):
            return [details]

        # PostEntitiesAlertsV2 returns entities in arbitrary order; restore the sort
        # applied by the query step (validated against live API: field is composite_id).
        details = self._reorder_by_ids(detection_ids, details, id_field="composite_id")
        return self._build_pagination_envelope(details, pagination, filter)

    def get_detection_details(
        self,
        ids: list[str] = Field(
            description="Composite ID(s) to retrieve detection details for.",
        ),
        include_hidden: bool = Field(
            default=True,
            description=(
                "Whether to include hidden detections (default: True). When True, shows "
                "all detections including previously hidden ones for comprehensive visibility."
            ),
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Retrieve details for detection IDs you already have.

        Use when you have specific composite detection ID(s). For discovering detections
        by criteria (severity, status, hostname, etc.), use falcon_search_detections
        instead. Returns full detection records; IDs hidden from the Falcon UI are
        omitted when include_hidden is False.
        """
        logger.debug("Getting detection details for ID(s): %s", ids)

        return self._base_get_by_ids(
            operation="PostEntitiesAlertsV2",
            ids=ids,
            id_key="composite_ids",
            parameters={"include_hidden": include_hidden},
        )

    def aggregate_detections(
        self,
        field: str = Field(
            description=(
                "Alert field to aggregate on, such as `severity_name`, `status`, "
                "`tactic`, `technique`, `product`, `device.hostname`, or `timestamp`. "
                "See `falcon://detections/search/fql-guide` for the aggregatable fields."
            ),
            examples=["severity_name", "status", "tactic", "device.hostname"],
        ),
        type: Literal[
            "terms",
            "date_histogram",
            "date_range",
            "range",
            "cardinality",
            "max",
            "min",
            "avg",
            "sum",
            "percentiles",
        ] = Field(
            default="terms",
            description=(
                "Aggregation to run. Use `terms` to count alerts per distinct value, "
                "`date_histogram` for a time series, `date_range` or `range` for "
                "explicit buckets, and `cardinality` for a distinct-value count."
            ),
        ),
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter expression narrowing which alerts are counted. See "
                "`falcon://detections/search/fql-guide` for syntax."
            ),
            examples=["status:'new'", "severity_name:'Critical'+product:'epp'"],
        ),
        size: int | None = Field(
            default=10,
            ge=1,
            le=1000,
            description="Maximum number of buckets to return for `terms` aggregations.",
        ),
        sort: str | None = Field(
            default=None,
            description=(
                "Bucket ordering, using the pipe form only: `_count|desc` (most "
                "alerts first), `_count|asc`, `_key|asc`, or `_key|desc`. The dot "
                "form accepted by search sorts is rejected here."
            ),
            examples=["_count|desc", "_key|asc"],
        ),
        interval: Literal["hour", "day", "week", "month", "quarter", "year"] | None = Field(
            default=None,
            description=(
                "Bucket width for `date_histogram` aggregations. Required whenever "
                "`type` is `date_histogram`."
            ),
        ),
        date_ranges: list[dict[str, str]] | None = Field(
            default=None,
            description=(
                "Explicit time buckets for `date_range` aggregations, for example "
                "`[{'from': 'now-7d', 'to': 'now'}]`. Required whenever `type` is "
                "`date_range`."
            ),
            examples=[[{"from": "now-7d", "to": "now"}]],
        ),
        ranges: list[dict[str, Any]] | None = Field(
            default=None,
            description=(
                "Numeric buckets for `range` aggregations, for example "
                "`[{'From': 0, 'To': 50}]`. Required whenever `type` is `range`."
            ),
            examples=[[{"From": 0, "To": 50}, {"From": 50, "To": 100}]],
        ),
        percents: list[float] | None = Field(
            default=None,
            description="Percentiles to compute for `percentiles` aggregations.",
            examples=[[50.0, 95.0]],
        ),
        missing: str | None = Field(
            default=None,
            description=(
                "Label used for alerts that have no value for `field`, so they are "
                "counted instead of dropped."
            ),
            examples=["Unassigned"],
        ),
        include: str | None = Field(
            default=None,
            description=(
                "Keep only buckets whose key matches this regular expression, e.g. "
                "`High|Critical`."
            ),
            examples=["High|Critical"],
        ),
        name: str = Field(
            default="alert_aggregation",
            description="Label echoed back on the returned aggregation.",
        ),
        time_zone: str | None = Field(
            default=None,
            description="UTC offset applied to date buckets, e.g. `+00:00`.",
            examples=["+00:00"],
        ),
        sub_aggregates: list[dict[str, Any]] | None = Field(
            default=None,
            description=(
                "Nested aggregations applied within each bucket, each shaped like a "
                "top-level spec, e.g. `[{'type': 'terms', 'field': 'status'}]`."
            ),
            examples=[[{"type": "terms", "field": "status", "size": 3}]],
        ),
        include_hidden: bool = Field(
            default=True,
            description=(
                "Whether to count hidden alerts (default: True). Set False to match "
                "the alert totals shown in the Falcon console."
            ),
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Count and summarize detections (also called alerts) without retrieving each record.

        Use this for "how many" and "top N" questions — alerts per severity, status,
        tactic, or host, distinct host counts, and alert volume over time — instead of
        paging through falcon_search_detections. Consult
        falcon://detections/search/fql-guide before constructing filter expressions.
        Returns one aggregation per request holding `buckets`, which key on `label`
        with a `count`; single-value aggregations (`cardinality`, `max`, `min`, `avg`,
        `sum`) report their answer as `value` instead.
        """
        return self._base_aggregate(
            operation="PostAggregatesAlertsV2",
            agg_type=type,
            field=field,
            filter=filter,
            name=name,
            size=size,
            sort=sort,
            interval=interval,
            date_ranges=date_ranges,
            ranges=ranges,
            percents=percents,
            missing=missing,
            include=include,
            time_zone=time_zone,
            sub_aggregates=sub_aggregates,
            parameters={"include_hidden": include_hidden},
            error_message="Failed to aggregate detections",
        )

    def update_detections(
        self,
        ids: list[str] = Field(
            description="Composite ID(s) of the detection(s) to update.",
        ),
        status: str | None = Field(
            default=None,
            description=(
                "New status for the detection(s). Allowed values: new, in_progress, "
                "reopened, closed."
            ),
        ),
        assign_to_uuid: str | None = Field(
            default=None,
            description=(
                "UUID of the user to assign the detection(s) to. "
                "Example: '00000000-0000-0000-0000-000000000000'."
            ),
        ),
        assign_to_user_id: str | None = Field(
            default=None,
            description=(
                "Email address of the user to assign the detection(s) to. "
                "Example: 'analyst@example.com'."
            ),
        ),
        assign_to_name: str | None = Field(
            default=None,
            description=(
                "Full name of the user to assign the detection(s) to. "
                "Example: 'Jane Smith'."
            ),
        ),
        unassign: bool | None = Field(
            default=None,
            description=(
                "Pass True to remove the current assignee. False is a no-op; "
                "only True has any effect."
            ),
        ),
        append_comment: str | None = Field(
            default=None,
            description=(
                "Comment to append to the detection(s). Comments are visible in the Falcon "
                "console. Must be a non-empty, non-whitespace string."
            ),
        ),
        show_in_ui: bool | None = Field(
            default=None,
            description="Whether to show the detection(s) in the Falcon UI. Set to False to hide.",
        ),
        add_tags: list[str] | None = Field(
            default=None,
            description=(
                "Tags to add to the detection(s). Tags are free-form strings; any value is "
                "accepted. "
                "true_positive, false_positive, and ignored are the conventional resolution "
                "tags the "
                "Falcon console surfaces in its Resolution column — use them when recording "
                "a resolution, "
                "but they are guidance, not an enforced set."
            ),
        ),
        remove_tags: list[str] | None = Field(
            default=None,
            description=(
                "Tags to remove from the detection(s). Each value must match an existing "
                "tag exactly."
            ),
        ),
        remove_tags_by_prefix: str | None = Field(
            default=None,
            description=(
                "Remove all tags on the detection(s) that start with this prefix (e.g. 'fc/')."
            ),
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Update the status, assignment, visibility, comments, and tags of one or more detections.

        Use to change status (new, in_progress, reopened, closed), assign to a user by UUID,
        email address, or full name, unassign, append a comment, hide/show detections in the UI,
        or add/remove tags. Resolution is tag-based: applying the conventional tags true_positive,
        false_positive, or ignored is what populates the console's Resolution view. At least one
        update parameter must be provided. Requests covering more than 1000 detection IDs are
        chunked automatically so none are silently dropped. Returns `[]` (empty list) on success, or
        `{"result": [], "hint": "..."}` when closing without adding a resolution tag in this call;
        returns an error dict on failure. If a later chunk fails after earlier chunks already
        applied, the error dict carries a `partial_success` block listing the already-updated ids so
        the caller can retry only the remainder rather than re-applying non-idempotent actions.
        """
        # Validate mutually exclusive assignment parameters
        assignment_params = [assign_to_uuid, assign_to_user_id, assign_to_name]
        if sum(p is not None for p in assignment_params) > 1:
            return {
                "error": (
                    "Provide at most one of assign_to_uuid, assign_to_user_id, assign_to_name."
                )
            }

        if unassign is True and any(p is not None for p in assignment_params):
            return {"error": "Cannot combine unassign with an assignment parameter."}

        if append_comment is not None and append_comment.strip() == "":
            return {"error": "append_comment must not be empty."}

        for tag in add_tags or []:
            if tag.strip() == "":
                return {"error": "add_tags must not contain empty or whitespace-only strings."}

        for tag in remove_tags or []:
            if tag.strip() == "":
                return {"error": "remove_tags must not contain empty or whitespace-only strings."}

        if remove_tags_by_prefix is not None and remove_tags_by_prefix.strip() == "":
            return {"error": "remove_tags_by_prefix must not be empty or whitespace-only."}

        _valid_statuses = {"new", "in_progress", "reopened", "closed"}
        if status is not None and status not in _valid_statuses:
            return {"error": f"status must be one of: {', '.join(sorted(_valid_statuses))}."}

        if not ids:
            return {"error": "At least one detection ID must be provided."}

        action_parameters: list[dict[str, Any]] = []

        str_params = {
            "update_status": status,
            "assign_to_uuid": assign_to_uuid,
            "assign_to_user_id": assign_to_user_id,
            "assign_to_name": assign_to_name,
            "append_comment": append_comment,
        }
        for name, value in str_params.items():
            if value is not None:
                action_parameters.append({"name": name, "value": value})

        # show_in_ui and unassign must be sent as strings — the API rejects JSON booleans
        if show_in_ui is not None:
            action_parameters.append({"name": "show_in_ui", "value": str(show_in_ui).lower()})
        if unassign is True:
            action_parameters.append({"name": "unassign", "value": "true"})

        for tag in add_tags or []:
            action_parameters.append({"name": "add_tag", "value": tag})
        for tag in remove_tags or []:
            action_parameters.append({"name": "remove_tag", "value": tag})
        if remove_tags_by_prefix is not None:
            action_parameters.append(
                {"name": "remove_tags_by_prefix", "value": remove_tags_by_prefix}
            )

        if not action_parameters:
            return {"error": "At least one update parameter must be provided."}

        body_base = {"action_parameters": action_parameters}

        # PatchEntitiesAlertsV3 rejects more than MAX_UPDATE_COMPOSITE_IDS ids per
        # request with HTTP 413, so chunk larger requests and fail loudly if any
        # batch errors rather than reporting success on a truncated update.
        result: list[dict[str, Any]] | dict[str, Any] = []
        for i in range(0, len(ids), MAX_UPDATE_COMPOSITE_IDS):
            batch = ids[i : i + MAX_UPDATE_COMPOSITE_IDS]
            batch_result = self._base_query_api_call(
                operation="PatchEntitiesAlertsV3",
                body_params={**body_base, "composite_ids": batch},
                error_message="Failed to update detections",
                default_result=[],
            )

            if self._is_error(batch_result):
                # The API applies each batch independently and cannot roll back, so
                # ids before this batch are already updated. Report how many so the
                # caller can retry only the remainder instead of re-applying
                # non-idempotent actions (e.g. append_comment) to earlier ids.
                if i > 0:
                    batch_result["partial_success"] = {
                        "updated_ids": ids[:i],
                        "updated_count": i,
                        "failed_and_remaining_ids": ids[i:],
                    }
                return batch_result

            if isinstance(batch_result, list):
                result.extend(batch_result)

        # Soft hint: closing without adding a resolution tag in this call may leave the
        # detection out of the console's Resolution view. Non-fatal — only wraps the success
        # case. We only know this call's add_tags, not any resolution tag set previously.
        _resolution_tags = {"true_positive", "false_positive", "ignored"}
        if (
            not self._is_error(result)
            and status == "closed"
            and not _resolution_tags.intersection(add_tags or [])
        ):
            return {
                "result": result,
                "hint": (
                    "No resolution tag was added in this update call. The console convention is to "
                    "add true_positive, false_positive, or ignored when closing a detection so it "
                    "appears in the Resolution view (skip if a resolution tag was already set)."
                ),
            }

        return result

    def _open_alert_ids(
        self, fql: str, cap: int
    ) -> tuple[list[str] | dict[str, Any], bool]:
        """Page GetQueriesAlertsV2 for `fql`; return (ids or error, truncated)."""
        ids: list[str] = []
        seen: set[str] = set()
        while True:
            page = self._base_search_api_call(
                operation="GetQueriesAlertsV2",
                search_params={
                    "filter": fql,
                    "limit": HOST_DETECTIONS_PAGE_SIZE,
                    "offset": len(ids),
                    "include_hidden": True,
                },
                error_message="Failed to search the host's open detections",
                default_result=[],
            )
            if isinstance(page, dict):
                return page, False
            new_ids = [i for i in page if isinstance(i, str) and i not in seen]
            seen.update(new_ids)
            ids.extend(new_ids)
            if len(page) < HOST_DETECTIONS_PAGE_SIZE or not new_ids:
                return ids, False
            if len(ids) >= cap:
                return ids, True

    def close_host_detections(
        self,
        device_id: str = Field(
            description="Host agent ID (AID, 32 hex characters) whose open detections to close.",
        ),
        resolution: Literal["true_positive", "false_positive", "ignored"] = Field(
            description=(
                "Resolution tag recorded on every closed detection, as shown in the "
                "console's Resolution column."
            ),
        ),
        comment: str | None = Field(
            default=None,
            description="Comment appended to every closed detection, for the audit trail.",
        ),
        include_multi_host: bool = Field(
            default=False,
            description=(
                "Also close open alerts that name this host alongside other hosts, such "
                "as NGSIEM correlation detections spanning several machines. Default "
                "false: they are listed in skipped_multi_host instead."
            ),
        ),
    ) -> dict[str, Any]:
        """Close every open detection on one host, with one resolution and comment.

        Finds all detections on the host whose status is new, in_progress or reopened,
        then closes them and tags them with the resolution. That includes endpoint
        detections and alerts that name the host in other fields, such as Next-Gen SIEM
        correlation detections; an alert that also names another host is left open and
        listed unless include_multi_host is true. Use this once a host has been
        investigated and cleaned up, or confirmed as a false positive, to clear its queue
        in one step. Review the host's detections with falcon_search_detections first;
        this closes all of them, whatever their severity. Running it again only touches
        detections that are still open. Returns how many were found and closed, and the
        composite IDs closed.
        """
        if not isinstance(device_id, str) or not DEVICE_ID_PATTERN.fullmatch(device_id):
            return _format_error_response(
                f"Invalid host AID {device_id!r}. AIDs are 32 hexadecimal characters.",
                operation="GetQueriesAlertsV2",
            )
        if resolution not in RESOLUTION_TAGS:
            return _format_error_response(
                f"resolution must be one of: {', '.join(RESOLUTION_TAGS)}.",
                operation="PatchEntitiesAlertsV3",
            )
        if comment is not None and not comment.strip():
            return _format_error_response(
                "comment must not be empty.", operation="PatchEntitiesAlertsV3"
            )

        aid = device_id.lower()
        statuses = ",".join(f"'{status}'" for status in OPEN_STATUSES)
        host_fql = f"device.device_id:'{aid}'+status:[{statuses}]"
        related = ",".join(f"{field}:'{aid}'" for field in RELATED_HOST_FIELDS)
        related_fql = f"({related})+status:[{statuses}]"

        host_ids, truncated = self._open_alert_ids(host_fql, MAX_HOST_DETECTIONS)
        if isinstance(host_ids, dict):
            return {**host_ids, "phase": "search"}
        related_ids: list[str] = []
        if not truncated:
            found_related, truncated = self._open_alert_ids(
                related_fql, MAX_HOST_DETECTIONS - len(host_ids)
            )
            if isinstance(found_related, dict):
                return {**found_related, "phase": "search"}
            seen = set(host_ids)
            related_ids = [i for i in found_related if i not in seen]

        # Alerts matched only through the related fields may span several hosts
        # (a correlation rule over many machines). Close only those that name this
        # host alone, unless the caller asks for the rest too.
        single_host: list[str] = []
        multi_host: list[str] = []
        for start in range(0, len(related_ids), ALERT_ENTITY_BATCH):
            batch = related_ids[start : start + ALERT_ENTITY_BATCH]
            records = self._base_get_by_ids(
                operation="PostEntitiesAlertsV2",
                ids=batch,
                id_key="composite_ids",
                parameters={"include_hidden": True},
            )
            if isinstance(records, dict):
                return {**records, "phase": "search"}
            by_id = {r.get("composite_id"): r for r in records if isinstance(r, dict)}
            for composite_id in batch:
                record = by_id.get(composite_id)
                if record is not None and _names_only_host(record, aid):
                    single_host.append(composite_id)
                else:
                    multi_host.append(composite_id)

        closing_multi = include_multi_host is True
        ids = host_ids + single_host + (multi_host if closing_multi else [])

        summary: dict[str, Any] = {
            "device_id": aid,
            "resolution": resolution,
            "found": len(ids),
            "closed": 0,
            "composite_ids": [],
            "matched_by": {
                "device_id": len(host_ids),
                "related_fields_this_host_only": len(single_host),
                "related_fields_multi_host": len(multi_host),
            },
        }
        if multi_host and not closing_multi:
            summary["skipped_multi_host"] = {
                "count": len(multi_host),
                "composite_ids": multi_host[:MAX_SKIPPED_IDS_SHOWN],
                "reason": (
                    "These open alerts name this host and other hosts too, such as "
                    "correlation detections across several machines, so they were left "
                    "open. Review them with falcon_get_detection_details, then close them "
                    "by ID, or run again with include_multi_host=true."
                ),
            }
        if truncated:
            summary["warning"] = (
                f"The host has more than {MAX_HOST_DETECTIONS} open detections. Only the "
                "first batch was closed; run this again to close the rest."
            )
        if not ids:
            return summary

        action_parameters: list[dict[str, Any]] = [
            {"name": "update_status", "value": "closed"},
            {"name": "add_tag", "value": resolution},
        ]
        if comment is not None:
            action_parameters.append({"name": "append_comment", "value": comment})

        for start in range(0, len(ids), MAX_UPDATE_COMPOSITE_IDS):
            batch = ids[start : start + MAX_UPDATE_COMPOSITE_IDS]
            result = self._base_query_api_call(
                operation="PatchEntitiesAlertsV3",
                body_params={"action_parameters": action_parameters, "composite_ids": batch},
                error_message="Failed to close detections",
                default_result=[],
            )
            if isinstance(result, dict):
                return {
                    **summary,
                    **result,
                    "phase": "close",
                    "failed_and_remaining_ids": ids[start:],
                }
            summary["closed"] += len(batch)
            summary["composite_ids"].extend(batch)
        return summary


def _names_only_host(record: dict[str, Any], aid: str) -> bool:
    """Whether an alert names `aid` and no other host AID."""
    if record.get("has_truncated_entities"):
        return False
    found: set[str] = set()
    device = record.get("device")
    if isinstance(device, dict):
        found.add(str(device.get("device_id") or ""))
    found.add(str(record.get("agent_id") or ""))
    enriched = record.get("enriched_entities")
    if isinstance(enriched, dict):
        found.update(str(a) for a in enriched.get("aids") or [])
    for user in record.get("users") or []:
        if isinstance(user, dict):
            found.add(str(user.get("aid") or ""))
    hosts = {a.lower() for a in found if DEVICE_ID_PATTERN.fullmatch(a)}
    return hosts == {aid}
