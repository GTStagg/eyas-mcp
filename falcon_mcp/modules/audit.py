"""
Audit module for Falcon MCP Server

This module provides read-only tools for the Falcon audit log: who did what in the
tenant, from console logins and API client changes to policy, workflow and case edits.
"""

import asyncio
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from mcp.server import FastMCP
from pydantic import Field

from falcon_mcp.common.errors import (
    _format_error_response,
    error_details,
    handle_api_response,
)
from falcon_mcp.common.logging import get_logger
from falcon_mcp.modules.base import BaseModule

logger = get_logger(__name__)

# Limits the API enforces (checked live)
MAX_RANGE_DAYS = 365
MAX_PAGE_SIZE = 1000

# Query jobs over the raw API request log can run for minutes, so a call waits at most
# this long and otherwise hands back the job ID for falcon_get_audit_log_results.
DEFAULT_WAIT_SECONDS = 45
MAX_WAIT_SECONDS = 120
POLL_INTERVAL_SECONDS = 2

COMPLETED = "COMPLETED"
FAILED_STATUSES = frozenset({"FAILED", "ERROR", "CANCELLED", "CANCELED", "TIMEOUT", "TIMED_OUT"})

_RELATIVE_TIME = re.compile(r"now(?:-(\d+)([mhd]))?")
_UNIT = {"m": "minutes", "h": "hours", "d": "days"}
_SORT = re.compile(r"[a-z_]+\.(asc|desc)")

# Records of the raw API request log carry actor_type 3. Filtering to people (1) and
# services (2) leaves that noise out and makes a job finish in seconds.
ACTOR_TYPE_HELP = (
    "Who acted, as observed in the log: 1 = a person (console logins, API client and "
    "secret changes, policy and workflow edits), 2 = a service or integration "
    "(Streaming API sessions, workflow runs, action request approvals, detection and "
    "case updates), 3 = the raw API request log, which is most of the log. Pass [1, 2] "
    "to leave out API requests; such jobs finish in seconds instead of minutes."
)


def _parse_time(value: str, now: datetime) -> datetime | None:
    """Read 'now', 'now-<N>m|h|d' or an ISO 8601 timestamp (UTC when no offset)."""
    text = value.strip()
    relative = _RELATIVE_TIME.fullmatch(text)
    if relative:
        amount, unit = relative.groups()
        return now - timedelta(**{_UNIT[unit]: int(amount)}) if amount else now
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _rfc3339(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _job_error(message: str, operation: str = "CreateQueryJob") -> dict[str, Any]:
    return _format_error_response(message, operation=operation)


def _api_error(response: dict[str, Any], operation: str, message: str) -> dict[str, Any]:
    """Report a failed audit call.

    The shared handler's 400 text is about FQL, which this API doesn't use, so a 400
    carries the API's own messages instead. Other statuses keep the shared handling,
    including the scope hints on a 403.
    """
    if response.get("status_code") == 400:
        errors = (response.get("body") or {}).get("errors") or []
        said = "; ".join(e.get("message", "") for e in errors if isinstance(e, dict))
        return _format_error_response(
            f"{message}: {said or 'the API rejected the request'}",
            details=error_details(response),
            operation=operation,
        )
    error: dict[str, Any] = handle_api_response(
        response, operation=operation, error_message=message
    )
    return error


class AuditModule(BaseModule):
    """Module for searching the Falcon audit log."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(
            server=server,
            method=self.search_audit_log,
            name="search_audit_log",
        )

        self._add_tool(
            server=server,
            method=self.get_audit_log_results,
            name="get_audit_log_results",
        )

    async def search_audit_log(
        self,
        start_time: str = Field(
            default="now-24h",
            description=(
                "Start of the window: 'now-<N>m', 'now-<N>h', 'now-<N>d' or an ISO 8601 "
                "timestamp (UTC when it has no offset). The window may span at most "
                f"{MAX_RANGE_DAYS} days."
            ),
            examples=["now-24h", "now-7d", "2026-11-01T00:00:00Z"],
        ),
        end_time: str = Field(
            default="now",
            description="End of the window: 'now', 'now-<N>m|h|d' or an ISO 8601 timestamp.",
        ),
        actor_type: list[int] | None = Field(
            default=None,
            description=ACTOR_TYPE_HELP,
            examples=[[1, 2], [1]],
        ),
        category: list[str] | None = Field(
            default=None,
            description=(
                "Event categories, for example 'Crowdstrike Authentication', "
                "'Crowdstrike API Client', 'csvault', 'cases', 'detections', "
                "'workflow_v2', 'aidr_policy', 'action_requests', 'api_request'. "
                "Matching ignores case and accepts * wildcards."
            ),
            examples=[["Crowdstrike Authentication"], ["Crowdstrike API Client"]],
        ),
        action: list[str] | None = Field(
            default=None,
            description=(
                "Actions within a category, for example `assert` (a login), "
                "`CreateAPIClient`, `UpdateAPIClient`, `secret_read`, `case_update`, "
                "`approve_action_request`. Matching ignores case and accepts * wildcards."
            ),
        ),
        actor_id: list[str] | None = Field(
            default=None,
            description="IDs of the user or API client that acted, as `actor_id` shows them.",
        ),
        actor_ip: list[str] | None = Field(
            default=None,
            description="Source IP addresses of the actor.",
        ),
        target_id: list[str] | None = Field(
            default=None,
            description="IDs of the object acted on, as `target_id` shows them.",
        ),
        target_display_name: list[str] | None = Field(
            default=None,
            description="Names of the object acted on. Accepts * wildcards.",
        ),
        geo_country: list[str] | None = Field(
            default=None,
            description="Countries the actor's IP address maps to, as `geo_country` shows them.",
        ),
        user_agent: list[str] | None = Field(
            default=None,
            description="User agents of the actor's client. Accepts * wildcards.",
        ),
        event_id: list[str] | None = Field(
            default=None,
            description="Audit event IDs, to fetch specific events.",
        ),
        sort: str = Field(
            default="action_timestamp.desc",
            description="Sort as 'field.direction', for example 'action_timestamp.asc'.",
        ),
        limit: int = Field(
            default=25,
            ge=1,
            le=MAX_PAGE_SIZE,
            description=(
                f"Records to return from the first page [1-{MAX_PAGE_SIZE}]. Records can "
                "be large; page on with falcon_get_audit_log_results."
            ),
        ),
        include_descriptions: bool = Field(
            default=False,
            description="Add readable `category_description` and `action_description`.",
        ),
        wait_seconds: int = Field(
            default=DEFAULT_WAIT_SECONDS,
            ge=0,
            le=MAX_WAIT_SECONDS,
            description=(
                f"How long to wait for the query job [0-{MAX_WAIT_SECONDS}]. If it is still "
                "running then, the job ID comes back for falcon_get_audit_log_results."
            ),
        ),
    ) -> dict[str, Any]:
        """Search the Falcon audit log: who did what in the tenant, when and from where.

        Covers console logins, API client creation and changes, secret reads, policy,
        workflow, case and detection changes, action request approvals, and every API
        request. Use it to investigate a suspected compromised admin or API key, or to
        see who changed a setting. Runs as a query job: when it finishes within
        `wait_seconds`, returns `job_id`, `status`, `total_results`, the first page of
        `results` (each with `action_timestamp`, `category`, `action`, `actor_*`,
        `target_*`, `geo_*` and `extensions` holding the details) and `pagination`.
        Otherwise returns `job_id` with `status` RUNNING; fetch it later with
        falcon_get_audit_log_results.
        """
        now = datetime.now(UTC)
        start = _parse_time(start_time, now)
        end = _parse_time(end_time, now)
        if start is None or end is None:
            bad = start_time if start is None else end_time
            return _job_error(
                f"Invalid time {bad!r}. Use 'now', 'now-<N>m|h|d' or an ISO 8601 timestamp."
            )
        if start >= end:
            return _job_error("start_time must be before end_time.")
        if end - start > timedelta(days=MAX_RANGE_DAYS):
            return _job_error(f"The window may span at most {MAX_RANGE_DAYS} days.")
        if not _SORT.fullmatch(sort):
            return _job_error(
                f"Invalid sort {sort!r}. Use 'field.direction', e.g. 'action_timestamp.desc'."
            )
        if actor_type is not None and any(
            isinstance(t, bool) or not isinstance(t, int) or t < 0 for t in actor_type
        ):
            return _job_error("actor_type values must be non-negative integers.")

        body: dict[str, Any] = {
            "start_time": _rfc3339(start),
            "end_time": _rfc3339(end),
            "sort": sort,
        }
        filters = {
            "category": category,
            "action": action,
            "actor_id": actor_id,
            "actor_ip": actor_ip,
            "target_id": target_id,
            "target_display_name": target_display_name,
            "geo_country": geo_country,
            "user_agent": user_agent,
            "event_id": event_id,
        }
        for key, values in filters.items():
            if values:
                body[key] = [str(v) for v in values]
        if actor_type:
            # The API takes these as strings and rejects integers
            body["actor_type"] = [str(t) for t in actor_type]

        response = await self.client.command_async("CreateQueryJob", body=body)
        if response.get("status_code") != 200:
            return _api_error(
                response, "CreateQueryJob", "Failed to start the audit log query"
            )
        resources = (response.get("body") or {}).get("resources") or []
        if not resources or not isinstance(resources[0], str):
            return _job_error("Failed to start the audit log query: no job ID returned.")

        job_id = resources[0]
        logger.debug("Audit log query job started")
        result = await self._wait_and_fetch(job_id, 0, limit, include_descriptions, wait_seconds)
        if "error" not in result:
            result["window"] = {"start_time": body["start_time"], "end_time": body["end_time"]}
        return result

    async def get_audit_log_results(
        self,
        job_id: str = Field(
            description="The `job_id` falcon_search_audit_log returned.",
        ),
        offset: int = Field(
            default=0,
            ge=0,
            description="Record offset to start from, for paging through results.",
        ),
        limit: int = Field(
            default=25,
            ge=1,
            le=MAX_PAGE_SIZE,
            description=f"Records to return [1-{MAX_PAGE_SIZE}].",
        ),
        include_descriptions: bool = Field(
            default=False,
            description="Add readable `category_description` and `action_description`.",
        ),
        wait_seconds: int = Field(
            default=DEFAULT_WAIT_SECONDS,
            ge=0,
            le=MAX_WAIT_SECONDS,
            description=f"How long to wait if the job is still running [0-{MAX_WAIT_SECONDS}].",
        ),
    ) -> dict[str, Any]:
        """Get the results of an audit log query job, or the next page of them.

        Use it after falcon_search_audit_log returned a RUNNING job, or to page on
        through a finished one with `offset`. Returns the same shape as
        falcon_search_audit_log: `job_id`, `status`, `total_results`, `results` and
        `pagination`, or `status` RUNNING if the job has still not finished.
        """
        if not job_id or not job_id.strip():
            return _job_error("`job_id` is required.", operation="PollQueryJobStatus")
        return await self._wait_and_fetch(
            job_id.strip(), offset, limit, include_descriptions, wait_seconds
        )

    async def _wait_and_fetch(
        self,
        job_id: str,
        offset: int,
        limit: int,
        include_descriptions: bool,
        wait_seconds: int,
    ) -> dict[str, Any]:
        """Poll a query job until it completes or the wait runs out, then read a page."""
        elapsed = 0
        while True:
            response = await self.client.command_async(
                "PollQueryJobStatus", parameters={"id": job_id}
            )
            if response.get("status_code") != 200:
                return _api_error(
                    response, "PollQueryJobStatus", "Failed to check the audit log query"
                )
            records = (response.get("body") or {}).get("resources") or [{}]
            job = records[0] if isinstance(records[0], dict) else {}
            status = str(job.get("status") or "").upper()

            if status == COMPLETED:
                break
            if status in FAILED_STATUSES:
                return _format_error_response(
                    f"The audit log query job ended with status {status}.",
                    details={"job_id": job_id, "status": status},
                    operation="PollQueryJobStatus",
                )
            if elapsed >= wait_seconds:
                return {
                    "job_id": job_id,
                    "status": status or "RUNNING",
                    "message": (
                        f"The query is still running after {elapsed} seconds. Call "
                        "falcon_get_audit_log_results with this job_id to get the results. "
                        "Filtering on actor_type [1, 2] or a category makes jobs finish "
                        "much faster."
                    ),
                }
            await asyncio.sleep(POLL_INTERVAL_SECONDS)
            elapsed += POLL_INTERVAL_SECONDS

        params: dict[str, Any] = {"id": job_id, "offset": offset, "limit": limit}
        if include_descriptions:
            params["include_descriptions"] = True
        response = await self.client.command_async("GetQueryResults", parameters=params)
        if response.get("status_code") != 200:
            return _api_error(
                response, "GetQueryResults", "Failed to read the audit log query results"
            )

        body = response.get("body") or {}
        results = [r for r in body.get("resources") or [] if isinstance(r, dict)]
        pagination = (body.get("meta") or {}).get("pagination") or {}
        total = pagination.get("total", job.get("total_results"))
        next_offset = offset + len(results)
        return {
            "job_id": job_id,
            "status": COMPLETED,
            "total_results": total,
            "results": results,
            "pagination": {
                "offset": offset,
                "limit": limit,
                "total": total,
                "next_offset": next_offset if total is not None and next_offset < total else None,
            },
        }
