"""
Real Time Response module for Falcon MCP Server.

This module provides tools for initiating and inspecting RTR sessions, for
executing read-only RTR commands during host investigations, and for managing
and running scripts from the tenant's custom RTR script library.
"""

import json
import re
import time
from textwrap import dedent
from typing import Any, Literal

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from mcp.types import ToolAnnotations
from pydantic import AnyUrl, Field

from falcon_mcp.client import FalconClient
from falcon_mcp.common.errors import _format_error_response, handle_api_response
from falcon_mcp.common.logging import get_logger
from falcon_mcp.common.utils import prepare_api_parameters
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.rtr import (
    AGGREGATE_RTR_SESSIONS_GUIDE,
    AUDIT_RTR_SESSIONS_EMBEDDED_FQL_SYNTAX,
    EMBEDDED_FQL_SYNTAX,
    READ_ONLY_RTR_INVESTIGATION_GUIDE,
    SEARCH_RTR_AUDIT_SESSIONS_FQL_DOCUMENTATION,
    SEARCH_RTR_SESSIONS_FQL_DOCUMENTATION,
)

logger = get_logger(__name__)

# Base commands the read-only RTR tools accept. The read-only RTR endpoints
# (RTR_ExecuteCommand, BatchCmd) already refuse Active Responder and Admin
# commands; this list is a client-side check on top, shared by every read-only tool.
READ_ONLY_RTR_COMMANDS = frozenset(
    {
        "cat",
        "cd",
        "clear",
        "csrutil",
        "env",
        "eventlog",
        "filehash",
        "getsid",
        "help",
        "history",
        "ifconfig",
        "ipconfig",
        "ls",
        "mount",
        "netstat",
        "ps",
        "reg",
        "users",
    }
)

# `reg` is read-only only for its `query` subcommand.
READ_ONLY_RTR_SUBCOMMANDS = {"reg": frozenset({"query"})}

# Host agent IDs are 32 hex characters.
DEVICE_ID_PATTERN = re.compile(r"[0-9a-fA-F]{32}")
MAX_BATCH_HOSTS = 100

# Falcon script names are written into the command string between triple backticks,
# so only a plain identifier is accepted, and only one the live catalog lists.
FALCON_SCRIPT_NAME_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")
MAX_FALCON_SCRIPT_JSON_INPUT = 4096
# Characters that could end the ```'...'``` argument wrapper or split the command.
_FORBIDDEN_JSON_INPUT_CHARS = re.compile(r"[`'\x00-\x1f\x7f]")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

# RTR_ListFalconScripts returns nothing at all when limit is above 100.
FALCON_SCRIPT_PAGE_SIZE = 100
MAX_FALCON_SCRIPT_PAGES = 10

# Custom script names go into an FQL filter (name:'...') and into the runscript
# command (-CloudFile="..."), so only characters that can't end either are allowed.
CUSTOM_SCRIPT_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
MAX_CUSTOM_SCRIPT_BYTES = 1_000_000
MAX_CUSTOM_SCRIPT_DESCRIPTION = 1000
CUSTOM_SCRIPT_EXTENSIONS = {"windows": "ps1", "mac": "sh", "linux": "sh"}
# Opaque Falcon IDs (scripts, command requests): letters, digits, `-` and `_` only.
OPAQUE_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,128}")
MAX_STATUS_REQUESTS = 100


def _validate_custom_script_name(name: Any) -> str | None:
    """Return why a custom script name is refused, or None when it is allowed."""
    if not isinstance(name, str) or not CUSTOM_SCRIPT_NAME_PATTERN.fullmatch(name):
        return (
            f"Invalid script name {name!r}. Use 1-100 letters, digits, `.`, `_` or `-`, "
            "starting with a letter or digit."
        )
    return None


def _validate_opaque_ids(
    values: list[str] | None, label: str, limit: int
) -> tuple[list[str], str | None]:
    """Deduplicate opaque Falcon IDs or return why they are refused."""
    if not values:
        return [], f"Provide at least one {label}."
    clean: list[str] = []
    for value in values:
        if not isinstance(value, str) or not OPAQUE_ID_PATTERN.fullmatch(value):
            return [], f"Invalid {label} {value!r}."
        if value not in clean:
            clean.append(value)
    if len(clean) > limit:
        return [], f"Provide at most {limit} distinct values for {label}."
    return clean, None


def _validate_read_only_command(base_command: str, command_string: str | None) -> str | None:
    """Return why a read-only RTR command is refused, or None when it is allowed."""
    if not isinstance(base_command, str) or base_command not in READ_ONLY_RTR_COMMANDS:
        return (
            f"Unsupported read-only RTR command {base_command!r}. Use one of: "
            f"{', '.join(sorted(READ_ONLY_RTR_COMMANDS))}."
        )
    if command_string is None:
        return None
    if not isinstance(command_string, str) or _CONTROL_CHARS.search(command_string):
        return "command_string must be a single line without control characters."
    tokens = command_string.split()
    if not tokens or tokens[0].lower() != base_command:
        return f"command_string must start with the base command {base_command!r}."
    subcommands = READ_ONLY_RTR_SUBCOMMANDS.get(base_command)
    if subcommands is not None and (len(tokens) < 2 or tokens[1].lower() not in subcommands):
        return (
            f"`{base_command}` is read-only only as: "
            f"{', '.join(f'{base_command} {s}' for s in sorted(subcommands))}."
        )
    return None


def _validate_device_ids(device_ids: list[str] | None) -> tuple[list[str], str | None]:
    """Normalize host AIDs (lowercase, deduplicated) or return why they are refused."""
    if not device_ids:
        return [], "Provide at least one host AID in device_ids."
    clean: list[str] = []
    for value in device_ids:
        if not isinstance(value, str) or not DEVICE_ID_PATTERN.fullmatch(value):
            return [], f"Invalid host AID {value!r}. AIDs are 32 hexadecimal characters."
        normalized = value.lower()
        if normalized not in clean:
            clean.append(normalized)
    if len(clean) > MAX_BATCH_HOSTS:
        return [], f"Provide at most {MAX_BATCH_HOSTS} distinct host AIDs per call."
    return clean, None


def _strings_in(value: Any) -> list[str]:
    """Collect every string key and value inside a JSON-like structure."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        found: list[str] = []
        for key, item in value.items():
            found.extend(_strings_in(key))
            found.extend(_strings_in(item))
        return found
    if isinstance(value, (list, tuple)):
        return [s for item in value for s in _strings_in(item)]
    return []


def _serialize_falcon_script_input(json_input: dict[str, Any]) -> tuple[str, str | None]:
    """Serialize a Falcon script's JSON input or return why it is refused."""
    if not isinstance(json_input, dict):
        return "", "json_input must be a JSON object."
    for text in _strings_in(json_input):
        if _FORBIDDEN_JSON_INPUT_CHARS.search(text):
            return "", (
                "json_input keys and values must not contain backticks, single quotes, "
                "newlines or other control characters."
            )
    try:
        serialized = json.dumps(
            json_input, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError) as err:
        return "", f"json_input is not serializable as JSON: {err}"
    if _FORBIDDEN_JSON_INPUT_CHARS.search(serialized):
        return "", "json_input must not contain backticks, quotes or control characters."
    if len(serialized) > MAX_FALCON_SCRIPT_JSON_INPUT:
        return "", (
            f"json_input is {len(serialized)} characters once serialized; "
            f"the limit is {MAX_FALCON_SCRIPT_JSON_INPUT}."
        )
    return serialized, None


def _build_falcon_script_command(script_name: str, serialized_input: str | None) -> str:
    """Build the `falconscript` command string from already-validated parts."""
    command = f"falconscript -Name=```{script_name}```"
    if serialized_input is not None:
        command += f" -JsonInput=```'{serialized_input}'```"
    return command


def _parse_json_output(stdout: str) -> Any:
    """Decode stdout as JSON, or return None when it isn't JSON."""
    text = stdout.strip()
    if not text or text[0] not in "{[":
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


_SCRIPT_INPUT_KEY = re.compile(r"schema|input|param", re.IGNORECASE)


def _summarize_falcon_script(script: dict[str, Any]) -> dict[str, Any]:
    """Keep a Falcon script's identity, platforms, description and any input schema."""
    summary: dict[str, Any] = {
        "name": script.get("name"),
        "id": script.get("id"),
        "platform": script.get("platform") or script.get("platforms"),
        "description": script.get("description") or "",
    }
    for key, value in script.items():
        if key not in summary and _SCRIPT_INPUT_KEY.search(key):
            summary[key] = value
    return summary


def _supports_platform(platforms: Any, platform: str) -> bool:
    """Check a catalog platform field, a string or a list, for one platform."""
    if isinstance(platforms, str):
        platforms = [platforms]
    if not isinstance(platforms, list):
        return False
    return platform in {str(p).lower() for p in platforms}


def _format_batch_host_result(
    device_id: str, session_id: str, host: dict[str, Any], parse_json: bool
) -> dict[str, Any]:
    """Shape one host's batch command result."""
    complete = host.get("complete") is True
    stdout = str(host.get("stdout") or "")
    result: dict[str, Any] = {
        "device_id": device_id,
        "session_id": session_id,
        "complete": complete,
        "task_id": host.get("task_id"),
    }
    parsed = _parse_json_output(stdout) if parse_json else None
    if parsed is not None:
        result["output"] = parsed
    else:
        result["stdout"] = stdout
    result["stderr"] = str(host.get("stderr") or "")
    if host.get("errors"):
        result["errors"] = host["errors"]
    if not complete:
        result["warning"] = (
            "The host did not finish within the timeout. Retry with a longer timeout_seconds."
        )
    return result


class RTRModule(BaseModule):
    """Module for Real Time Response hunt and triage workflows."""

    def __init__(self, client: FalconClient):
        super().__init__(client)
        # Falcon script catalog keyed by name, cached after the first successful fetch.
        self._falcon_script_cache: dict[str, dict[str, Any]] | None = None

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(
            server=server,
            method=self.search_sessions,
            name="search_rtr_sessions",
        )

        self._add_tool(
            server=server,
            method=self.search_audit_sessions,
            name="search_rtr_audit_sessions",
        )

        self._add_tool(
            server=server,
            method=self.aggregate_sessions,
            name="aggregate_rtr_sessions",
        )

        self._add_tool(
            server=server,
            method=self.get_session_details,
            name="get_rtr_session_details",
        )

        self._add_tool(
            server=server,
            method=self.init_session,
            name="init_rtr_session",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.pulse_session,
            name="pulse_rtr_session",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.execute_read_only_command,
            name="execute_rtr_read_only_command",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.run_read_only_command_and_wait,
            name="run_rtr_read_only_command_and_wait",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.run_read_only_command_on_hosts,
            name="run_rtr_read_only_command_on_hosts",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.list_falcon_scripts,
            name="list_falcon_scripts",
        )

        self._add_tool(
            server=server,
            method=self.run_falcon_script,
            name="run_falcon_script",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.check_command_status,
            name="check_rtr_command_status",
        )

        self._add_tool(
            server=server,
            method=self.list_session_files,
            name="list_rtr_session_files",
        )

        self._add_tool(
            server=server,
            method=self.delete_session,
            name="delete_rtr_session",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.wait_for_sessions,
            name="wait_for_rtr_sessions",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.search_custom_scripts,
            name="search_rtr_scripts",
        )

        self._add_tool(
            server=server,
            method=self.create_custom_script,
            name="create_rtr_script",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.delete_custom_scripts,
            name="delete_rtr_scripts",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.run_custom_script_on_hosts,
            name="run_rtr_script_on_hosts",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.check_admin_command_status,
            name="check_rtr_admin_command_status",
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP server.

        Args:
            server: MCP server instance
        """
        search_rtr_sessions_fql_resource = TextResource(
            uri=AnyUrl("falcon://rtr/sessions/search/fql-guide"),
            name="falcon_search_rtr_sessions_fql_guide",
            description=(
                "Contains the guide for the `filter` param of the "
                "`falcon_search_rtr_sessions` tool."
            ),
            text=SEARCH_RTR_SESSIONS_FQL_DOCUMENTATION,
        )

        self._add_resource(
            server,
            search_rtr_sessions_fql_resource,
        )

        search_rtr_audit_sessions_fql_resource = TextResource(
            uri=AnyUrl("falcon://rtr/audit/sessions/search/fql-guide"),
            name="falcon_search_rtr_audit_sessions_fql_guide",
            description=(
                "Contains the guide for the `filter` param of the "
                "`falcon_search_rtr_audit_sessions` tool."
            ),
            text=SEARCH_RTR_AUDIT_SESSIONS_FQL_DOCUMENTATION,
        )

        self._add_resource(
            server,
            search_rtr_audit_sessions_fql_resource,
        )

        aggregate_rtr_sessions_resource = TextResource(
            uri=AnyUrl("falcon://rtr/sessions/aggregate-guide"),
            name="falcon_aggregate_rtr_sessions_guide",
            description=(
                "Explains how to summarize RTR session activity with the "
                "`falcon_aggregate_rtr_sessions` tool."
            ),
            text=AGGREGATE_RTR_SESSIONS_GUIDE,
        )

        self._add_resource(
            server,
            aggregate_rtr_sessions_resource,
        )

        read_only_rtr_investigation_resource = TextResource(
            uri=AnyUrl("falcon://rtr/workflows/investigation-guide"),
            name="falcon_rtr_read_only_investigation_guide",
            description="Provides a safe read-only RTR workflow for endpoint investigation tools.",
            text=READ_ONLY_RTR_INVESTIGATION_GUIDE,
        )

        self._add_resource(
            server,
            read_only_rtr_investigation_resource,
        )

    def search_sessions(
        self,
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter expression. See `falcon://rtr/sessions/search/fql-guide` "
                "for syntax."
            ),
            examples=["hostname:'BRR-WB-LIB-22'", "aid:'2c5c4e7738...'"],
        ),
        limit: int = Field(
            default=10,
            ge=1,
            le=5000,
            description="Maximum number of RTR session IDs to return. Max: 5000.",
        ),
        offset: int | None = Field(
            default=None,
            description="Starting index of overall result set from which to return IDs.",
        ),
        sort: str | None = Field(
            default=None,
            description=dedent("""
                Sort RTR sessions by a supported session property such as:
                `created_at.asc`, `updated_at.desc`, or `hostname.asc`.
            """).strip(),
            examples=["created_at.desc", "hostname.asc"],
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search RTR sessions and return full session details.

        Use this to find sessions by hostname, agent ID, user, or creation time. Consult
        falcon://rtr/sessions/search/fql-guide before constructing filter expressions.
        Returns session metadata including host info, commands executed, and status.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        session_ids, pagination = self._base_search_with_meta(
            operation="RTR_ListAllSessions",
            search_params={
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
            },
            error_message="Failed to search RTR sessions",
        )

        if self._is_error(session_ids):
            return self._format_fql_error_response(
                [session_ids], filter, SEARCH_RTR_SESSIONS_FQL_DOCUMENTATION
            )

        if not session_ids:
            return self._build_pagination_envelope([], pagination, filter)

        details = self._base_get_by_ids(
            operation="RTR_ListSessions",
            ids=session_ids,
            id_key="ids",
            use_params=False,
        )

        if self._is_error(details):
            return [details]

        # Restore the query-step sort order in case RTR_ListSessions reorders results.
        details = self._reorder_by_ids(session_ids, details, id_field="id")
        return self._build_pagination_envelope(details, pagination, filter)

    def search_audit_sessions(
        self,
        filter: str | None = Field(
            default=None,
            description=AUDIT_RTR_SESSIONS_EMBEDDED_FQL_SYNTAX,
            examples=["created_at:>'now-7d'", "hostname:'BRR-WB-LIB-22'+created_at:>'now-7d'"],
        ),
        limit: int = Field(
            default=10,
            ge=1,
            le=1000,
            description="Maximum number of RTR audit session records to return. Max: 1000.",
        ),
        offset: int | None = Field(
            default=None,
            ge=0,
            description="Starting index of the audit result set.",
        ),
        sort: str | None = Field(
            default=None,
            description=dedent("""
                Sort RTR audit sessions by a supported audit property using the
                dot separator, supported on every Falcon sort endpoint:
                `created_at.desc`, `updated_at.asc`, or `deleted_at.desc`.
            """).strip(),
            examples=["created_at.desc", "updated_at.asc"],
        ),
        with_command_info: bool = Field(
            default=False,
            description="Include command IDs and command log fields in the audit response.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search RTR audit sessions for accountability and timeline evidence.

        Use this when you need to understand who used RTR, when they used it,
        which host was targeted, or which command activity Falcon recorded.
        This is read-only audit visibility; it does not open sessions or run
        commands. Consult falcon://rtr/audit/sessions/search/fql-guide before
        constructing filter expressions.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        audit_sessions, pagination = self._base_search_with_meta(
            operation="RTRAuditSessions",
            search_params={
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
                "with_command_info": with_command_info,
            },
            error_message="Failed to search RTR audit sessions",
        )

        if self._is_error(audit_sessions):
            return self._format_fql_error_response(
                [audit_sessions], filter, SEARCH_RTR_AUDIT_SESSIONS_FQL_DOCUMENTATION
            )

        return self._build_pagination_envelope(audit_sessions or [], pagination, filter)

    def aggregate_sessions(
        self,
        field: str = Field(
            description=(
                "RTR session field to aggregate, such as `hostname`, `user_id`, "
                "`origin`, `base_command`, or `created_at`."
            ),
            examples=["base_command", "hostname", "user_id", "created_at"],
        ),
        aggregate_type: Literal["terms", "date_range"] = Field(
            default="terms",
            description=(
                "Aggregation type to run. Use `terms` for top values and "
                "`date_range` for time buckets."
            ),
        ),
        name: str = Field(
            default="rtr_session_aggregation",
            description="Friendly name for the aggregation returned by Falcon.",
        ),
        filter: str | None = Field(
            default=None,
            description=EMBEDDED_FQL_SYNTAX,
            examples=["created_at:>'now-7d'", "hostname:'DC*'"],
        ),
        size: int | None = Field(
            default=10,
            ge=1,
            le=1000,
            description="Maximum buckets to return for terms aggregations.",
        ),
        interval: str | None = Field(
            default=None,
            description="Optional interval for date range aggregations, such as `day` or `hour`.",
            examples=["day", "hour"],
        ),
        date_ranges: list[dict[str, str]] | None = Field(
            default=None,
            description=(
                "Date ranges for date_range aggregations, for example "
                "`[{'from': 'now-7d', 'to': 'now'}]`."
            ),
            examples=[[{"from": "now-7d", "to": "now"}]],
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Summarize RTR session activity with Falcon aggregation buckets.

        Use this before detailed searches when the user asks which hosts,
        users, origins, commands, or time windows account for RTR activity.
        This is read-only summary visibility; it does not open sessions, run
        commands, or return every session record.
        """
        operation = "RTR_AggregateSessions"
        body_params = {
            "date_ranges": date_ranges,
            "field": field,
            "filter": filter,
            "interval": interval,
            "name": name,
            "size": size,
            "type": aggregate_type,
        }
        prepared_body = prepare_api_parameters(body_params)

        logger.debug("Executing %s with body: %s", operation, prepared_body)
        response = self.client.command(operation, body=[prepared_body])

        return handle_api_response(
            response,
            operation=operation,
            error_message="Failed to aggregate RTR sessions",
            default_result=[],
        )

    def get_session_details(
        self,
        ids: list[str] = Field(
            description="RTR session IDs to retrieve details for.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Retrieve detailed metadata for one or more RTR sessions.

        Use when you already have session IDs from search results. For discovering
        sessions by criteria, use falcon_search_rtr_sessions instead. Returns full
        session records.
        """
        logger.debug("Getting RTR session details for IDs: %s", ids)

        if not ids:
            return []

        return self._base_get_by_ids(
            operation="RTR_ListSessions",
            ids=ids,
            id_key="ids",
            use_params=False,
        )

    def init_session(
        self,
        device_id: str = Field(
            description="The host agent ID (AID) to open or reuse an RTR session for.",
        ),
        origin: str = Field(
            default="eyas-mcp",
            description="Origin label for the RTR request.",
        ),
        queue_offline: bool = Field(
            default=False,
            description="Queue the request if the host is currently offline.",
        ),
        timeout: int | None = Field(
            default=None,
            ge=1,
            le=600,
            description="How long to wait for the request in seconds. Max: 600.",
        ),
        timeout_duration: str | None = Field(
            default=None,
            description="Alternate duration syntax such as `30s`, `2m`, or `1h`.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Initialize or reuse an RTR session for a single host.

        Opens a live connection to the specified device for executing RTR commands.
        Use queue_offline=True if the host may be offline. Returns session records
        containing the session_id needed for subsequent commands.
        """
        return self._base_query_api_call(
            operation="RTR_InitSession",
            query_params={
                "timeout": timeout,
                "timeout_duration": timeout_duration,
            },
            body_params={
                "device_id": device_id,
                "origin": origin,
                "queue_offline": queue_offline,
            },
            error_message="Failed to initialize RTR session",
        )

    def pulse_session(
        self,
        device_id: str = Field(
            description="The host agent ID (AID) whose RTR session timeout should be refreshed.",
        ),
        origin: str = Field(
            default="eyas-mcp",
            description="Origin label for the RTR request.",
        ),
        queue_offline: bool = Field(
            default=False,
            description="Queue the pulse if the host is currently offline.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Refresh an RTR session timeout for a single host.

        Keeps an existing session alive by resetting its inactivity timer. Use this
        to prevent session expiration during long investigations.
        """
        return self._base_query_api_call(
            operation="RTR_PulseSession",
            body_params={
                "device_id": device_id,
                "origin": origin,
                "queue_offline": queue_offline,
            },
            error_message="Failed to pulse RTR session",
        )

    def execute_read_only_command(
        self,
        session_id: str = Field(
            description=(
                "RTR session ID returned from falcon_init_rtr_session or "
                "falcon_search_rtr_sessions."
            ),
        ),
        base_command: str = Field(
            description=(
                "Read-only RTR base command to execute, such as `ls`, `ps`, `cat`, "
                "`filehash`, or `reg`."
            ),
            examples=["ls", "ps", "filehash"],
        ),
        command_string: str | None = Field(
            default=None,
            description=(
                "Optional full command line to execute. Example: "
                "`cat C:\\Windows\\win.ini`."
            ),
        ),
        persist: bool = Field(
            default=False,
            description="Persist the read-only command in the RTR session history.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Execute a read-only RTR command on a single host.

        Limited to read-only commands (ls, ps, cat, filehash, reg) for hunt and triage
        workflows. Does not expose admin or remediation commands. Returns command records
        containing a cloud_request_id for polling output via falcon_check_rtr_command_status.
        """
        refusal = _validate_read_only_command(base_command, command_string)
        if refusal:
            return _format_error_response(refusal, operation="RTR_ExecuteCommand")

        return self._base_query_api_call(
            operation="RTR_ExecuteCommand",
            body_params={
                "session_id": session_id,
                "base_command": base_command,
                "command_string": command_string,
                "persist": persist,
            },
            error_message="Failed to execute RTR read-only command",
        )

    def check_command_status(
        self,
        cloud_request_id: str = Field(
            description="Cloud request ID returned from falcon_execute_rtr_read_only_command.",
        ),
        sequence_id: int = Field(
            default=0,
            ge=0,
            description="Sequence chunk to retrieve for command output. Starts at 0.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Get the status and output for an RTR command execution.

        Poll this after falcon_execute_rtr_read_only_command to retrieve command
        output. Use sequence_id to paginate through large output chunks.
        """
        return self._base_query_api_call(
            operation="RTR_CheckCommandStatus",
            query_params={
                "cloud_request_id": cloud_request_id,
                "sequence_id": sequence_id,
            },
            error_message="Failed to check RTR command status",
        )

    def run_read_only_command_and_wait(
        self,
        session_id: str = Field(
            description=(
                "RTR session ID returned from falcon_init_rtr_session or "
                "falcon_search_rtr_sessions."
            ),
        ),
        base_command: str = Field(
            description=(
                "Read-only RTR base command to execute, such as `ls`, `ps`, `cat`, "
                "`filehash`, or `reg`."
            ),
            examples=["ls", "ps", "filehash"],
        ),
        command_string: str | None = Field(
            default=None,
            description=(
                "Optional full command line to execute. Example: "
                "`cat C:\\Windows\\win.ini`."
            ),
        ),
        persist: bool = Field(
            default=False,
            description="Persist the read-only command in the RTR session history.",
        ),
        timeout_seconds: int = Field(
            default=60,
            ge=1,
            le=600,
            description="Maximum time to wait for command completion. Max: 600 seconds.",
        ),
        poll_interval_seconds: float = Field(
            default=2.0,
            ge=0.5,
            le=30.0,
            description="Seconds to wait between command status checks.",
        ),
    ) -> dict[str, Any]:
        """Execute a read-only RTR command and poll until completion.

        Use this for simple, focused RTR evidence collection when the user
        wants the command output directly and does not need to manually manage
        a cloud request ID. This polls command status until completion or
        timeout, accumulating output chunks into one result. It still executes
        an RTR command and creates RTR command activity, but it does not expose
        RTR Admin or remediation APIs.
        """
        refusal = _validate_read_only_command(base_command, command_string)
        if refusal:
            return {**_format_error_response(refusal), "phase": "validate"}

        execute_result = self._base_query_api_call(
            operation="RTR_ExecuteCommand",
            body_params={
                "session_id": session_id,
                "base_command": base_command,
                "command_string": command_string,
                "persist": persist,
            },
            error_message="Failed to execute RTR read-only command",
        )

        if self._is_error(execute_result):
            execute_result["phase"] = "execute"
            return execute_result

        if not isinstance(execute_result, list) or not execute_result:
            return {
                "error": "RTR command execution did not return a command request.",
                "phase": "execute",
                "results": execute_result,
            }

        command_request = execute_result[0]
        if not isinstance(command_request, dict):
            return {
                "error": "RTR command execution returned an unexpected response shape.",
                "phase": "execute",
                "results": execute_result,
            }

        cloud_request_id = command_request.get("cloud_request_id")
        if not cloud_request_id:
            return {
                "error": "RTR command execution did not return a cloud_request_id.",
                "phase": "execute",
                "execution": command_request,
            }

        deadline = time.monotonic() + timeout_seconds
        status_chunks: list[dict[str, Any]] = []
        sequence_id = 0

        while True:
            status_result = self._base_query_api_call(
                operation="RTR_CheckCommandStatus",
                query_params={
                    "cloud_request_id": cloud_request_id,
                    "sequence_id": sequence_id,
                },
                error_message="Failed to check RTR command status",
            )

            if self._is_error(status_result):
                status_result["phase"] = "status"
                status_result["cloud_request_id"] = cloud_request_id
                return status_result

            if isinstance(status_result, list):
                status_chunks.extend(
                    chunk for chunk in status_result if isinstance(chunk, dict)
                )

            complete = any(chunk.get("complete") is True for chunk in status_chunks)
            if complete:
                return self._format_wait_result(
                    cloud_request_id=cloud_request_id,
                    command_request=command_request,
                    status_chunks=status_chunks,
                    complete=True,
                    timed_out=False,
                )

            if time.monotonic() >= deadline:
                return self._format_wait_result(
                    cloud_request_id=cloud_request_id,
                    command_request=command_request,
                    status_chunks=status_chunks,
                    complete=False,
                    timed_out=True,
                )

            if status_chunks:
                sequence_id = status_chunks[-1].get("sequence_id", sequence_id)
            time.sleep(poll_interval_seconds)

    def run_read_only_command_on_hosts(
        self,
        device_ids: list[str] = Field(
            description=(
                "Host agent IDs (AIDs, 32 hex characters) to run the command on. "
                f"Duplicates are dropped. Max: {MAX_BATCH_HOSTS}."
            ),
        ),
        base_command: str = Field(
            description=(
                "Read-only RTR base command to execute, such as `ls`, `ps`, `cat`, "
                "`filehash`, or `reg`."
            ),
            examples=["ps", "netstat", "filehash"],
        ),
        command_string: str | None = Field(
            default=None,
            description=(
                "Optional full command line, starting with the base command. Defaults to "
                "the base command alone. Example: `filehash C:\\Windows\\System32\\cmd.exe`."
            ),
        ),
        timeout_seconds: int = Field(
            default=30,
            ge=10,
            le=300,
            description=(
                "Seconds to wait for sessions to open and again for hosts to answer. Max: 300."
            ),
        ),
    ) -> dict[str, Any]:
        """Run one read-only RTR command on several hosts at once and return each host's output.

        Use this to ask the same question of a set of hosts, such as which of them run a
        process or hold a file with a given hash. It accepts the same read-only commands
        as falcon_execute_rtr_read_only_command and nothing more. It opens an RTR batch
        session on online hosts only (nothing is queued for offline hosts), runs the
        command, and reports output per host, with hosts that couldn't be reached listed
        under `failed_hosts`. This creates RTR session and command activity, recorded in
        the RTR audit log. Sessions expire on their own; close one early with
        falcon_delete_rtr_session.
        """
        effective_command = command_string if command_string is not None else base_command
        refusal = _validate_read_only_command(base_command, effective_command)
        if refusal:
            return _format_error_response(refusal, operation="BatchCmd")

        hosts, refusal = _validate_device_ids(device_ids)
        if refusal:
            return _format_error_response(refusal, operation="BatchInitSessions")

        batch = self._open_batch_sessions(hosts, timeout_seconds)
        if "error" in batch:
            return batch

        return self._run_batch_command(
            operation="BatchCmd",
            batch=batch,
            hosts=hosts,
            base_command=base_command,
            command_string=effective_command,
            timeout_seconds=timeout_seconds,
            parse_json=False,
        )

    def list_falcon_scripts(
        self,
        platform: Literal["windows", "mac", "linux"] | None = Field(
            default=None,
            description="Only return scripts that support this platform.",
        ),
        refresh: bool = Field(
            default=False,
            description="Fetch the catalog again instead of using the copy cached by this server.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """List the CrowdStrike-published RTR scripts (Falcon scripts) available to this tenant.

        Falcon scripts are host introspection scripts that CrowdStrike maintains, such as
        Process, Service, RegistryKey, EventLog and BitLocker, and that return structured
        JSON. Use this to find a script's exact name, its platforms and any input it
        takes before calling falcon_run_falcon_script. This only reads the catalog; it
        doesn't contact any host.
        """
        catalog, error = self._falcon_script_catalog(refresh=refresh)
        if error is not None:
            return error

        scripts = [_summarize_falcon_script(script) for script in catalog.values()]
        if platform:
            scripts = [s for s in scripts if _supports_platform(s.get("platform"), platform)]
        return sorted(scripts, key=lambda s: str(s.get("name", "")).lower())

    def run_falcon_script(
        self,
        script_name: str = Field(
            description=(
                "Exact name of a CrowdStrike-published script, as listed by "
                "falcon_list_falcon_scripts. Case-sensitive."
            ),
            examples=["Process", "Service", "BitLocker"],
        ),
        device_ids: list[str] = Field(
            description=(
                "Host agent IDs (AIDs, 32 hex characters) to run the script on. "
                f"Duplicates are dropped. Max: {MAX_BATCH_HOSTS}."
            ),
        ),
        json_input: dict[str, Any] | None = Field(
            default=None,
            description=(
                "Input object for scripts that take parameters, for example "
                '`{"Key": "HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"}` '
                "for RegistryKey. Values must not contain backticks, single quotes, "
                f"newlines or control characters. Max {MAX_FALCON_SCRIPT_JSON_INPUT} "
                "characters once serialized."
            ),
        ),
        timeout_seconds: int = Field(
            default=60,
            ge=10,
            le=300,
            description=(
                "Seconds to wait for sessions to open and again for hosts to answer. Max: 300."
            ),
        ),
    ) -> dict[str, Any]:
        """Run a CrowdStrike-published Falcon script on one or more hosts.

        Use this to collect structured host state, such as running processes, services,
        registry keys or BitLocker status, from several hosts in one call. The script
        name must come from falcon_list_falcon_scripts. Falcon scripts inspect hosts,
        but they run through an RTR Admin batch session, so this needs the RTR Admin
        scope and is recorded in the RTR audit log. Nothing is queued for offline hosts;
        they are listed under `failed_hosts`. Each host's JSON output is decoded into
        `output` when it parses, otherwise returned as `stdout`.
        """
        if not isinstance(script_name, str) or not FALCON_SCRIPT_NAME_PATTERN.fullmatch(
            script_name
        ):
            return _format_error_response(
                f"Invalid Falcon script name {script_name!r}. Use an exact name from "
                "falcon_list_falcon_scripts.",
                operation="BatchAdminCmd",
            )

        serialized_input: str | None = None
        if json_input is not None:
            serialized_input, refusal = _serialize_falcon_script_input(json_input)
            if refusal:
                return _format_error_response(refusal, operation="BatchAdminCmd")

        hosts, refusal = _validate_device_ids(device_ids)
        if refusal:
            return _format_error_response(refusal, operation="BatchInitSessions")

        catalog, error = self._falcon_script_catalog()
        if error is not None:
            return {**error, "phase": "catalog"}
        if script_name not in catalog:
            return _format_error_response(
                f"Unknown Falcon script {script_name!r}. Use an exact name from "
                "falcon_list_falcon_scripts.",
                operation="RTR_ListFalconScripts",
            )

        batch = self._open_batch_sessions(hosts, timeout_seconds)
        if "error" in batch:
            return batch

        result = self._run_batch_command(
            operation="BatchAdminCmd",
            batch=batch,
            hosts=hosts,
            base_command="falconscript",
            command_string=_build_falcon_script_command(script_name, serialized_input),
            timeout_seconds=timeout_seconds,
            parse_json=True,
        )
        if "error" not in result:
            result["script_name"] = script_name
        return result

    def wait_for_sessions(
        self,
        device_ids: list[str] = Field(
            description=(
                "Host agent IDs (AIDs, 32 hex characters) to wait for. "
                f"Duplicates are dropped. Max: {MAX_BATCH_HOSTS}."
            ),
        ),
        timeout_seconds: int = Field(
            default=180,
            ge=30,
            le=600,
            description="Total seconds to keep trying before giving up. Max: 600.",
        ),
        interval_seconds: int = Field(
            default=15,
            ge=5,
            le=60,
            description="Seconds to wait between attempts.",
        ),
    ) -> dict[str, Any]:
        """Wait until hosts accept RTR sessions, retrying until they do or time runs out.

        Use this after a change that briefly blocks RTR on a host, such as moving it into
        a new host group or policy, or a reboot, before running RTR commands or scripts.
        Each attempt opens an RTR batch session on the hosts that aren't ready yet; the
        first attempt is immediate. It runs no commands, and the sessions expire on their
        own. Returns `ready` (true when every host connected), the hosts that connected
        with their session IDs, and the last error for hosts that never did.
        """
        hosts, refusal = _validate_device_ids(device_ids)
        if refusal:
            return _format_error_response(refusal, operation="BatchInitSessions")

        started = time.monotonic()
        deadline = started + timeout_seconds
        connected: dict[str, str] = {}
        last_errors: dict[str, Any] = {}
        attempts = 0
        while True:
            attempts += 1
            pending = [aid for aid in hosts if aid not in connected]
            batch = self._open_batch_sessions(pending, 30)
            if "error" in batch:
                for aid in pending:
                    last_errors[aid] = batch.get("error")
            else:
                connected.update(batch["sessions"])
                for failure in batch["failed_hosts"]:
                    last_errors[failure["device_id"]] = failure["errors"]
                for aid in batch["sessions"]:
                    last_errors.pop(aid, None)

            if len(connected) == len(hosts):
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(interval_seconds, remaining))

        not_ready = [aid for aid in hosts if aid not in connected]
        return {
            "ready": not not_ready,
            "timed_out": bool(not_ready),
            "attempts": attempts,
            "waited_seconds": round(time.monotonic() - started),
            "ready_hosts": [
                {"device_id": aid, "session_id": connected[aid]} for aid in hosts if aid in connected
            ],
            "not_ready_hosts": [
                {"device_id": aid, "last_error": last_errors.get(aid)} for aid in not_ready
            ],
        }

    def search_custom_scripts(
        self,
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter on custom script fields such as `name`, `platform`, "
                "`permission_type`, `created_by` and `modified_timestamp`."
            ),
            examples=["name:'collect-triage'", "platform:'windows'"],
        ),
        limit: int = Field(
            default=50,
            ge=1,
            le=100,
            description="Maximum number of scripts to return. Max: 100.",
        ),
        offset: int | None = Field(
            default=None,
            ge=0,
            description="Starting index of the result set.",
        ),
        sort: str | None = Field(
            default=None,
            description="Sort by a script field, for example `modified_timestamp.desc`.",
            examples=["modified_timestamp.desc", "name.asc"],
        ),
        include_content: bool = Field(
            default=False,
            description="Include each script's full text. Off by default to keep results small.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search the tenant's custom RTR script library.

        Custom scripts are scripts your organization uploaded for RTR Admins to run with
        `runscript -CloudFile`. They are separate from the CrowdStrike-published scripts
        listed by falcon_list_falcon_scripts. Use this to find a script's exact name
        before calling falcon_run_rtr_script_on_hosts, or to review what is in the
        library. This only reads the library; it doesn't contact any host.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        script_ids, pagination = self._base_search_with_meta(
            operation="RTR_ListScripts",
            search_params={
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
            },
            error_message="Failed to search RTR custom scripts",
        )
        if self._is_error(script_ids):
            return script_ids
        if not script_ids:
            return self._build_pagination_envelope([], pagination, filter)

        details = self._base_get_by_ids(
            operation="RTR_GetScriptsV2",
            ids=script_ids,
            use_params=True,
        )
        if self._is_error(details):
            return details

        details = self._reorder_by_ids(script_ids, details, id_field="id")
        if not include_content:
            details = [
                {key: value for key, value in script.items() if key != "content"}
                for script in details
                if isinstance(script, dict)
            ]
        return self._build_pagination_envelope(details, pagination, filter)

    def create_custom_script(
        self,
        name: str = Field(
            description=(
                "Unique name for the script in the library, used later to run it. "
                "1-100 letters, digits, `.`, `_` or `-`."
            ),
            examples=["collect-triage", "remove-anydesk"],
        ),
        content: str = Field(
            description=(
                "Full script text: PowerShell for Windows, shell for macOS and Linux. "
                f"Max {MAX_CUSTOM_SCRIPT_BYTES} bytes."
            ),
        ),
        platform: Literal["windows", "mac", "linux"] = Field(
            default="windows",
            description="Platform the script runs on.",
        ),
        permission_type: Literal["private", "group", "public"] = Field(
            default="private",
            description=(
                "Who can run the script: `private` (only this API client), `group` "
                "(all RTR Admins) or `public` (RTR Admins and Active Responders)."
            ),
        ),
        description: str | None = Field(
            default=None,
            description=(
                "Description shown in the script library. "
                f"Max {MAX_CUSTOM_SCRIPT_DESCRIPTION} characters."
            ),
        ),
        comments_for_audit_log: str | None = Field(
            default=None,
            description="Reason for the upload, recorded in the Falcon audit log.",
        ),
    ) -> dict[str, Any]:
        """Upload a script to the tenant's custom RTR script library.

        Use this to stage a script that falcon_run_rtr_script_on_hosts will run. Uploading
        doesn't run anything, but anyone with the chosen permission can run the script
        on hosts afterwards, so review the content first. Prefer `private` unless others
        need it, and delete one-off scripts with falcon_delete_rtr_scripts once they've
        run. Needs the RTR Admin write scope.
        """
        refusal = _validate_custom_script_name(name)
        if refusal is None and (not isinstance(content, str) or not content.strip()):
            refusal = "content must be non-empty script text."
        if refusal is None and len(content.encode("utf-8")) > MAX_CUSTOM_SCRIPT_BYTES:
            refusal = f"content is larger than {MAX_CUSTOM_SCRIPT_BYTES} bytes."
        if refusal is None and description and len(description) > MAX_CUSTOM_SCRIPT_DESCRIPTION:
            refusal = f"description is longer than {MAX_CUSTOM_SCRIPT_DESCRIPTION} characters."
        if refusal:
            return _format_error_response(refusal, operation="RTR_CreateScripts")

        existing, error = self._find_custom_script(name)
        if error is not None:
            return {**error, "phase": "lookup"}
        if existing is not None:
            return _format_error_response(
                f"A custom script named {name!r} already exists (id {existing.get('id')}). "
                "Choose another name, or delete the existing script first.",
                operation="RTR_CreateScripts",
            )

        form = prepare_api_parameters(
            {
                "name": name,
                "platform": platform,
                "permission_type": permission_type,
                "description": description,
                "comments_for_audit_log": comments_for_audit_log,
            }
        )
        file_name = f"{name}.{CUSTOM_SCRIPT_EXTENSIONS[platform]}"
        response = self.client.command(
            "RTR_CreateScripts",
            data=form,
            files=[("file", (file_name, content.encode("utf-8"), "application/script"))],
        )
        status = response.get("status_code")
        if status is None or status >= 300:
            return handle_api_response(
                response,
                operation="RTR_CreateScripts",
                error_message="Failed to upload RTR custom script",
            )

        created, error = self._find_custom_script(name)
        if error is not None or created is None:
            return {
                "created": True,
                "name": name,
                "warning": "The script was uploaded, but looking it up afterwards failed.",
                **({"lookup_error": error} if error else {}),
            }
        return {
            "created": True,
            "id": created.get("id"),
            "name": name,
            "platform": platform,
            "permission_type": permission_type,
        }

    def delete_custom_scripts(
        self,
        ids: list[str] = Field(
            description=(
                "Custom script IDs to delete, from falcon_search_rtr_scripts. "
                f"Max: {MAX_STATUS_REQUESTS}."
            ),
        ),
    ) -> dict[str, Any]:
        """Delete scripts from the tenant's custom RTR script library.

        Use this to remove one-off scripts after they've run, or scripts nobody should
        run any more. Deletion can't be undone. It doesn't affect commands already
        sent to hosts. Needs the RTR Admin write scope.
        """
        script_ids, refusal = _validate_opaque_ids(ids, "script ID", MAX_STATUS_REQUESTS)
        if refusal:
            return _format_error_response(refusal, operation="RTR_DeleteScripts")

        deleted: list[str] = []
        failed: list[dict[str, Any]] = []
        for script_id in script_ids:
            response = self.client.command("RTR_DeleteScripts", parameters={"ids": script_id})
            status = response.get("status_code")
            if status is not None and status < 300:
                deleted.append(script_id)
            else:
                error = handle_api_response(
                    response,
                    operation="RTR_DeleteScripts",
                    error_message="Failed to delete RTR custom script",
                )
                failed.append({"id": script_id, "error": error})
        return {"deleted": deleted, "failed": failed}

    def run_custom_script_on_hosts(
        self,
        script_name: str = Field(
            description=(
                "Exact name of a script in the custom script library, as listed by "
                "falcon_search_rtr_scripts. Case-sensitive."
            ),
        ),
        device_ids: list[str] = Field(
            description=(
                "Host agent IDs (AIDs, 32 hex characters) to run the script on. "
                f"Duplicates are dropped. Max: {MAX_BATCH_HOSTS}."
            ),
        ),
        timeout_seconds: int = Field(
            default=60,
            ge=10,
            le=300,
            description=(
                "Seconds to wait for sessions to open and again for hosts to finish. "
                "Scripts still running afterwards keep running. Max: 300."
            ),
        ),
    ) -> dict[str, Any]:
        """Run a script from the custom RTR script library on one or more hosts.

        This runs your organization's own code on the hosts with `runscript -CloudFile`,
        so it can change anything on them. Only scripts already in the library can run;
        upload one with falcon_create_rtr_script first. Hosts must be online: nothing is
        queued, and hosts that can't be reached are listed under `failed_hosts`. Hosts
        that haven't finished within the timeout keep running the script. Check them
        later with falcon_check_rtr_admin_command_status and each host's `task_id`
        rather than running the script again. Needs the RTR Admin scope; every run is
        recorded in the RTR audit log.
        """
        refusal = _validate_custom_script_name(script_name)
        if refusal:
            return _format_error_response(refusal, operation="BatchAdminCmd")

        hosts, refusal = _validate_device_ids(device_ids)
        if refusal:
            return _format_error_response(refusal, operation="BatchInitSessions")

        script, error = self._find_custom_script(script_name)
        if error is not None:
            return {**error, "phase": "lookup"}
        if script is None:
            return _format_error_response(
                f"No custom script named {script_name!r}. Use an exact name from "
                "falcon_search_rtr_scripts, or upload one with falcon_create_rtr_script.",
                operation="RTR_ListScripts",
            )

        batch = self._open_batch_sessions(hosts, timeout_seconds)
        if "error" in batch:
            return batch

        result = self._run_batch_command(
            operation="BatchAdminCmd",
            batch=batch,
            hosts=hosts,
            base_command="runscript",
            command_string=f'runscript -CloudFile="{script_name}"',
            timeout_seconds=timeout_seconds,
            parse_json=False,
        )
        if "error" in result:
            return result

        result["script_name"] = script_name
        result["script_id"] = script.get("id")
        for host in result["results"]:
            if not host["complete"]:
                host["warning"] = (
                    "The script was still running when the timeout ended and may still be "
                    "running. Check it with falcon_check_rtr_admin_command_status using this "
                    "task_id; don't run the script again."
                )
        return result

    def check_admin_command_status(
        self,
        cloud_request_ids: list[str] = Field(
            description=(
                "Command request IDs to check: the `task_id` of each host from "
                "falcon_run_rtr_script_on_hosts or falcon_run_falcon_script. "
                f"Max: {MAX_STATUS_REQUESTS}."
            ),
        ),
    ) -> dict[str, Any]:
        """Check whether RTR Admin commands sent to hosts have finished, and get their output.

        Use this after falcon_run_rtr_script_on_hosts or falcon_run_falcon_script returns
        hosts that hadn't finished within the timeout. It only reads command status; it
        doesn't run anything again.
        """
        request_ids, refusal = _validate_opaque_ids(
            cloud_request_ids, "cloud request ID", MAX_STATUS_REQUESTS
        )
        if refusal:
            return _format_error_response(refusal, operation="RTR_CheckAdminCommandStatus")

        results: list[dict[str, Any]] = []
        for request_id in request_ids:
            status = self._base_query_api_call(
                operation="RTR_CheckAdminCommandStatus",
                query_params={"cloud_request_id": request_id, "sequence_id": 0},
                error_message="Failed to check RTR admin command status",
            )
            if isinstance(status, dict):
                results.append({"cloud_request_id": request_id, "complete": False, **status})
                continue
            chunk = status[0] if isinstance(status, list) and status else {}
            chunk = chunk if isinstance(chunk, dict) else {}
            entry: dict[str, Any] = {
                "cloud_request_id": request_id,
                "complete": chunk.get("complete") is True,
                "stdout": str(chunk.get("stdout") or ""),
                "stderr": str(chunk.get("stderr") or ""),
            }
            if chunk.get("errors"):
                entry["errors"] = chunk["errors"]
            results.append(entry)

        return {
            "requested": len(request_ids),
            "complete": sum(1 for r in results if r.get("complete")),
            "results": results,
        }

    def _find_custom_script(
        self, name: str
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Look up one custom script by exact name. Returns (script or None, error or None)."""
        script_ids = self._base_search_api_call(
            operation="RTR_ListScripts",
            # The name pattern rules out quotes, so it can't end the FQL string.
            search_params={"filter": f"name:'{name}'", "limit": 100},
            error_message="Failed to look up RTR custom script",
        )
        if self._is_error(script_ids):
            return None, script_ids
        if not script_ids:
            return None, None
        details = self._base_get_by_ids(
            operation="RTR_GetScriptsV2",
            ids=script_ids,
            use_params=True,
        )
        if self._is_error(details):
            return None, details
        for script in details:
            if isinstance(script, dict) and script.get("name") == name:
                return script, None
        return None, None

    def _falcon_script_catalog(
        self, refresh: bool = False
    ) -> tuple[dict[str, dict[str, Any]], dict[str, Any] | None]:
        """Return the Falcon script catalog keyed by name, fetching it on first use.

        Only a successful fetch is cached, so a permission error can be retried.
        """
        if self._falcon_script_cache is not None and not refresh:
            return self._falcon_script_cache, None

        script_ids: list[str] = []
        for page in range(MAX_FALCON_SCRIPT_PAGES):
            page_ids = self._base_search_api_call(
                operation="RTR_ListFalconScripts",
                search_params={
                    "limit": FALCON_SCRIPT_PAGE_SIZE,
                    "offset": page * FALCON_SCRIPT_PAGE_SIZE,
                },
                error_message="Failed to list Falcon scripts",
            )
            if self._is_error(page_ids):
                return {}, page_ids
            new_ids = [i for i in page_ids if isinstance(i, str) and i not in script_ids]
            script_ids.extend(new_ids)
            if len(page_ids) < FALCON_SCRIPT_PAGE_SIZE or not new_ids:
                break

        scripts: list[dict[str, Any]] = []
        for start in range(0, len(script_ids), FALCON_SCRIPT_PAGE_SIZE):
            details = self._base_get_by_ids(
                operation="RTR_GetFalconScripts",
                ids=script_ids[start : start + FALCON_SCRIPT_PAGE_SIZE],
                use_params=True,
            )
            if self._is_error(details):
                return {}, details
            scripts.extend(s for s in details if isinstance(s, dict))

        catalog = {
            script["name"]: script for script in scripts if isinstance(script.get("name"), str)
        }
        self._falcon_script_cache = catalog
        return catalog, None

    def _open_batch_sessions(self, hosts: list[str], timeout_seconds: int) -> dict[str, Any]:
        """Open an RTR batch session on online hosts, recording hosts that didn't connect."""
        response = self.client.command(
            "BatchInitSessions",
            parameters={
                "timeout": timeout_seconds,
                "host_timeout_duration": f"{max(1, timeout_seconds - 5)}s",
            },
            body={"host_ids": hosts, "queue_offline": False},
        )
        status = response.get("status_code")
        if status is None or status >= 300:
            error = handle_api_response(
                response,
                operation="BatchInitSessions",
                error_message="Failed to open RTR batch session",
            )
            return {**error, "phase": "init"}

        body = response.get("body") or {}
        batch_id = body.get("batch_id")
        if not batch_id:
            return {
                **_format_error_response(
                    "RTR batch session did not return a batch_id.", operation="BatchInitSessions"
                ),
                "phase": "init",
            }

        resources = {
            str(aid).lower(): value
            for aid, value in (body.get("resources") or {}).items()
            if isinstance(value, dict)
        }
        sessions: dict[str, str] = {}
        failed: list[dict[str, Any]] = []
        for aid in hosts:
            host = resources.get(aid, {})
            if host.get("session_id") and not host.get("errors"):
                sessions[aid] = host["session_id"]
            else:
                failed.append(
                    {
                        "device_id": aid,
                        "phase": "init",
                        "errors": host.get("errors")
                        or "No session opened. The host may be offline or unknown.",
                    }
                )
        return {"batch_id": batch_id, "sessions": sessions, "failed_hosts": failed}

    def _run_batch_command(
        self,
        operation: str,
        batch: dict[str, Any],
        hosts: list[str],
        base_command: str,
        command_string: str,
        timeout_seconds: int,
        parse_json: bool,
    ) -> dict[str, Any]:
        """Send one command to every host with an open batch session and collect results."""
        sessions: dict[str, str] = batch["sessions"]
        failed: list[dict[str, Any]] = list(batch["failed_hosts"])
        summary: dict[str, Any] = {
            "batch_id": batch["batch_id"],
            "base_command": base_command,
            "command_string": command_string,
            "hosts_requested": len(hosts),
            "hosts_with_session": len(sessions),
            "results": [],
            "failed_hosts": failed,
        }
        if not sessions:
            summary["warning"] = "No host had an open RTR session, so nothing was run."
            return summary

        response = self.client.command(
            operation,
            parameters={
                "timeout": timeout_seconds,
                "host_timeout_duration": f"{max(1, timeout_seconds - 5)}s",
            },
            body={
                "base_command": base_command,
                "batch_id": batch["batch_id"],
                "command_string": command_string,
                "optional_hosts": list(sessions),
            },
        )
        status = response.get("status_code")
        if status is None or status >= 300:
            error = handle_api_response(
                response,
                operation=operation,
                error_message="Failed to run RTR batch command",
            )
            return {**error, "phase": "command", "batch_id": batch["batch_id"]}

        combined = ((response.get("body") or {}).get("combined") or {}).get("resources") or {}
        by_host = {str(aid).lower(): value for aid, value in combined.items()}
        for aid, session_id in sessions.items():
            host = by_host.get(aid)
            if not isinstance(host, dict):
                failed.append(
                    {"device_id": aid, "phase": "command", "errors": "No result was returned."}
                )
                continue
            summary["results"].append(_format_batch_host_result(aid, session_id, host, parse_json))
        summary["hosts_completed"] = sum(1 for r in summary["results"] if r["complete"])
        return summary

    def list_session_files(
        self,
        session_id: str = Field(
            description="RTR session ID to retrieve extracted session files for.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """List files extracted during an RTR session.

        Returns file metadata for artifacts captured during the session, such as
        files pulled with the `get` command.
        """
        return self._base_query_api_call(
            operation="RTR_ListFilesV2",
            query_params={"session_id": session_id},
            error_message="Failed to list RTR session files",
        )

    def delete_session(
        self,
        session_id: str = Field(
            description="RTR session ID to close.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Close an RTR session and release the host connection.

        Use this when investigation is complete to free up session resources.
        """
        return self._base_query_api_call(
            operation="RTR_DeleteSession",
            query_params={"session_id": session_id},
            error_message="Failed to delete RTR session",
        )

    def _format_wait_result(
        self,
        cloud_request_id: str,
        command_request: dict[str, Any],
        status_chunks: list[dict[str, Any]],
        complete: bool,
        timed_out: bool,
    ) -> dict[str, Any]:
        """Format command-and-wait output for model-friendly consumption."""
        stdout = "".join(
            str(chunk.get("stdout", "")) for chunk in status_chunks if chunk.get("stdout")
        )
        stderr = "".join(
            str(chunk.get("stderr", "")) for chunk in status_chunks if chunk.get("stderr")
        )

        result: dict[str, Any] = {
            "cloud_request_id": cloud_request_id,
            "complete": complete,
            "timed_out": timed_out,
            "execution": command_request,
            "status": status_chunks,
            "stdout": stdout,
            "stderr": stderr,
        }

        if timed_out:
            result["warning"] = "Timed out waiting for RTR command completion."

        return result
