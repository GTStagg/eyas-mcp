"""
Threat Graph module for Falcon MCP Server

This module provides read-only tools for looking up vertices and walking edges in
CrowdStrike Falcon Threat Graph.
"""

import ipaddress
import re
from typing import Any, Literal

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from pydantic import AnyUrl, Field

from falcon_mcp.common.errors import _format_error_response, handle_api_response
from falcon_mcp.common.logging import get_logger
from falcon_mcp.common.utils import prepare_api_parameters
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.threatgraph import THREATGRAPH_GUIDE

logger = get_logger(__name__)

GUIDE_URI = "falcon://threatgraph/graph/pivot-guide"

RAN_ON_TYPES = ("sha256", "sha1", "md5", "domain", "ipv4", "ipv6")
HASH_TYPES = ("sha256", "sha1", "md5")
NETWORK_TYPES = ("domain", "ipv4", "ipv6")
SCOPES = ("device", "customer")
DIRECTIONS = ("in", "out")

_HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}"
)
# Vertex type is sent as a URL path segment, so it gets a strict shape check on top
# of the enum check below.
_VERTEX_TYPE_RE = re.compile(r"[a-z0-9_-]{1,64}")
_EDGE_TYPE_RE = re.compile(r"[a-z][a-z0-9_]{0,79}")
# Vertex ids are opaque (e.g. "pid:<aid>:<process id>"). Reject whitespace and
# control characters, which no vertex id contains, and cap the length.
_VERTEX_ID_RE = re.compile(r"[^\s\x00-\x1f\x7f]{1,1024}")
_MAX_SUMMARY_IDS = 100


def _load_vertex_types() -> frozenset[str]:
    """Read the vertex types FalconPy lists for combined_summary_get.

    Kept in step with FalconPy rather than copied here, so new vertex types arrive
    with a FalconPy upgrade. Returns an empty set if FalconPy's layout changes, in
    which case only the shape check applies.
    """
    try:
        from falconpy._endpoint._threatgraph import (  # type: ignore[import-untyped]
            _threatgraph_endpoints,
        )
    except ImportError:  # pragma: no cover - depends on FalconPy internals
        return frozenset()
    endpoints: list[Any] = _threatgraph_endpoints
    for endpoint in endpoints:
        if endpoint[0] != "combined_summary_get":
            continue
        for param in endpoint[5]:
            if param.get("name") == "vertex_type":
                return frozenset(param.get("enum", []))
    return frozenset()  # pragma: no cover


VERTEX_TYPES = _load_vertex_types()


def _validate_indicator(value: str, indicator_type: str) -> str | None:
    """Check that an indicator value has the shape its type requires.

    Returns:
        An error message, or None if the value is valid.
    """
    if indicator_type in _HASH_LENGTHS:
        expected = _HASH_LENGTHS[indicator_type]
        if len(value) != expected or not _HEX_RE.fullmatch(value):
            return f"Invalid {indicator_type}: expected {expected} hex characters, got {value!r}"
    elif indicator_type == "domain":
        if not _DOMAIN_RE.fullmatch(value.lower()):
            return f"Invalid domain: {value!r}"
    elif indicator_type in ("ipv4", "ipv6"):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return f"Invalid {indicator_type} address: {value!r}"
        if address.version != (4 if indicator_type == "ipv4" else 6):
            return f"Invalid {indicator_type} address: {value!r}"
    return None


def _validate_vertex_id(vertex_id: str) -> str | None:
    """Check a vertex id's shape. Returns an error message, or None if valid."""
    if not isinstance(vertex_id, str) or not _VERTEX_ID_RE.fullmatch(vertex_id):
        return (
            f"Invalid vertex id {vertex_id!r}: it must be 1-1024 characters with no "
            "whitespace or control characters"
        )
    return None


def _validate_common(scope: str, limit: int | None = None) -> str | None:
    """Check the scope and limit parameters shared by several tools."""
    if scope not in SCOPES:
        return f"Invalid scope {scope!r}: expected one of {', '.join(SCOPES)}"
    if limit is not None and (
        isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100
    ):
        return f"Invalid limit {limit!r}: expected an integer from 1 to 100"
    return None


RAN_ON_NOT_FOUND_NOTE = "No devices in this tenant ran this indicator within the retention period."


def _is_retention_not_found(response: dict[str, Any]) -> bool:
    """Check for the 404 Threat Graph sends when an indicator has no ran-on records.

    The API answers an indicator it has no data for with a 404 saying the resource
    was not found or has passed the retention period. That is an empty answer, not
    a failure.
    """
    if response.get("status_code") != 404:
        return False
    errors = (response.get("body") or {}).get("errors") or []
    for error in errors:
        message = str(error.get("message", "")).lower() if isinstance(error, dict) else ""
        if "not found" in message or "retention" in message:
            return True
    return False


def _next_cursor(response: dict[str, Any]) -> str | None:
    """Find the next-page cursor in a Threat Graph response, if there is one.

    Threat Graph reports paging under `meta.paging`; the other spellings are
    accepted so a change of shape doesn't silently drop the cursor.
    """
    meta = (response.get("body") or {}).get("meta") or {}
    for block_name in ("paging", "pagination"):
        block = meta.get(block_name)
        if isinstance(block, dict):
            for key in ("next", "next_page", "after"):
                if block.get(key):
                    return str(block[key])
    if meta.get("next"):
        return str(meta["next"])
    return None


class ThreatGraphModule(BaseModule):
    """Module for read-only lookups in CrowdStrike Falcon Threat Graph."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(
            server=server,
            method=self.get_threatgraph_summary,
            name="get_threatgraph_summary",
        )
        self._add_tool(
            server=server,
            method=self.get_threatgraph_ran_on,
            name="get_threatgraph_ran_on",
        )
        self._add_tool(
            server=server,
            method=self.get_threatgraph_edges,
            name="get_threatgraph_edges",
        )
        self._add_tool(
            server=server,
            method=self.list_threatgraph_edge_types,
            name="list_threatgraph_edge_types",
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP server.

        Args:
            server: MCP server instance
        """
        guide = TextResource(
            uri=AnyUrl(GUIDE_URI),
            name="falcon_threatgraph_guide",
            description=(
                "Guide to Threat Graph vertex types, vertex ids, edge types and the "
                "`falcon_*threatgraph*` tools."
            ),
            text=THREATGRAPH_GUIDE,
        )
        self._add_resource(server, guide)

    def get_threatgraph_summary(
        self,
        ids: list[str] = Field(
            description=(
                "Threat Graph vertex ids to summarize, all of the same vertex type "
                "(1-100). Take them from Falcon data, such as an alert's "
                "`triggering_process_graph_id` or `parent_process_graph_id` "
                "(`pid:<aid>:<number>`), or from an earlier Threat Graph result. Raw "
                "domain, IP or hash values are not vertex ids and are rejected."
            ),
            examples=[["pid:0123456789abcdef0123456789abcdef:123456789012"]],
        ),
        vertex_type: str = Field(
            default="any-vertex",
            description=(
                "Vertex type of the ids, such as 'processes' for `pid:` ids, 'module' "
                "or 'any-vertex'. File hashes are not vertex types: use "
                f"falcon_get_threatgraph_ran_on. See `{GUIDE_URI}`."
            ),
            examples=["processes", "any-vertex"],
        ),
        scope: Literal["device", "customer"] = Field(
            default="device",
            description=(
                "'device' for device-scoped vertices such as processes, 'customer' "
                "for tenant-wide vertices."
            ),
        ),
        nano: bool = Field(
            default=False,
            description="Return timestamps with nanosecond precision.",
        ),
    ) -> list[dict[str, Any]]:
        """Summarize Threat Graph vertices.

        Use this to see what Threat Graph knows about a vertex, such as the process
        behind an alert: its properties, device and the edges that touch it. The ids
        must be Threat Graph vertex ids taken from Falcon data, such as an alert's
        `triggering_process_graph_id`; raw domain, IP or hash values are rejected.
        For file hashes use falcon_get_threatgraph_ran_on instead. See
        falcon://threatgraph/graph/pivot-guide for vertex types and id formats.
        Returns one record per vertex.
        """
        operation = "combined_summary_get"
        vertex_type = vertex_type.strip().lower() if isinstance(vertex_type, str) else ""

        error = self._validate_summary(ids, vertex_type, scope)
        if error:
            return [_format_error_response(error, operation=operation)]

        params = prepare_api_parameters(
            {"ids": [i.strip() for i in ids], "scope": scope, "nano": nano or None}
        )
        logger.debug("Threat Graph summary for %s with params: %s", vertex_type, params)

        response = self.client.command(operation, vertex_type=vertex_type, parameters=params)
        results = handle_api_response(
            response,
            operation=operation,
            error_message="Failed to get Threat Graph summary",
            default_result=[],
        )
        if self._is_error(results):
            return [results]
        return results

    @staticmethod
    def _validate_summary(ids: Any, vertex_type: str, scope: str) -> str | None:
        """Validate the summary tool's arguments. Returns an error message or None."""
        if vertex_type in HASH_TYPES:
            return (
                f"'{vertex_type}' is not a Threat Graph vertex type. Use "
                "falcon_get_threatgraph_ran_on to find the devices that ran a file hash."
            )
        if not _VERTEX_TYPE_RE.fullmatch(vertex_type) or (
            VERTEX_TYPES and vertex_type not in VERTEX_TYPES
        ):
            return (
                f"Unknown vertex type {vertex_type!r}. Common types: processes, module, "
                f"sensor, any-vertex. See {GUIDE_URI} for the list."
            )
        if not isinstance(ids, list) or not ids:
            return "Provide at least one vertex id in `ids`."
        if len(ids) > _MAX_SUMMARY_IDS:
            return f"Too many ids: {len(ids)} given, at most {_MAX_SUMMARY_IDS} allowed."
        for vertex_id in ids:
            stripped = vertex_id.strip() if isinstance(vertex_id, str) else vertex_id
            error = _validate_vertex_id(stripped)
            if error:
                return error
        return _validate_common(scope)

    def get_threatgraph_ran_on(
        self,
        value: str = Field(
            description="The indicator value, such as a SHA256 hash.",
            examples=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        ),
        indicator_type: Literal["sha256", "sha1", "md5", "domain", "ipv4", "ipv6"] = Field(
            default="sha256",
            description=(
                "Indicator type. File hashes (sha256, sha1, md5) are the reliable "
                "case; tenants have been seen to reject domain, ipv4 and ipv6 here."
            ),
        ),
        limit: int = Field(
            default=100,
            ge=1,
            le=100,
            description="Maximum records to return per page. [1-100]",
        ),
        offset: str | None = Field(
            default=None,
            description="Cursor for the next page: `pagination.next` from the previous call.",
        ),
        nano: bool = Field(
            default=False,
            description="Return timestamps with nanosecond precision.",
        ),
    ) -> dict[str, Any]:
        """Find the devices where an indicator was seen in Threat Graph.

        Use this to answer "which devices ran this file?" for a SHA256, SHA1 or MD5
        hash. Tenants have been seen to reject domain and IP lookups here; for those,
        walk from a process with falcon_get_threatgraph_edges. Returns the matching
        Threat Graph records and a `pagination.next` cursor, which is null when the
        API returns no cursor. An indicator no device ran within the retention
        period gives empty results with a `note`, not an error.
        """
        operation = "combined_ran_on_get"
        normalized_type = indicator_type.strip().lower() if isinstance(indicator_type, str) else ""
        value = value.strip() if isinstance(value, str) else ""

        error: str | None
        if normalized_type not in RAN_ON_TYPES:
            error = (
                f"Invalid indicator type {indicator_type!r}: expected one of "
                f"{', '.join(RAN_ON_TYPES)}"
            )
        elif not value:
            error = "Provide the indicator `value`."
        else:
            error = _validate_indicator(value, normalized_type) or _validate_common("device", limit)
        if not error and offset is not None and _validate_vertex_id(offset):
            error = f"Invalid offset {offset!r}"
        if error:
            return _format_error_response(error, operation=operation)

        params = prepare_api_parameters(
            {
                "value": value,
                "type": normalized_type,
                "limit": limit,
                "offset": offset,
                "nano": nano or None,
            }
        )
        logger.debug("Threat Graph ran-on lookup with params: %s", params)

        response = self.client.command(operation, parameters=params)
        results = handle_api_response(
            response,
            operation=operation,
            error_message="Failed to look up where the indicator ran",
            default_result=[],
        )
        if _is_retention_not_found(response):
            return {
                "results": [],
                "pagination": {"next": None},
                "note": RAN_ON_NOT_FOUND_NOTE,
            }
        if self._is_error(results):
            if normalized_type in NETWORK_TYPES:
                results["hint"] = (
                    "Threat Graph may not support ran-on lookups for this type. Pivot "
                    "from a process vertex instead: falcon_get_threatgraph_edges with "
                    "edge_type dns_request, connected_ip4 or connected_ip6."
                )
            return results
        return {"results": results, "pagination": {"next": _next_cursor(response)}}

    def get_threatgraph_edges(
        self,
        vertex_id: str = Field(
            description=(
                "The vertex id to walk from, taken from an earlier Threat Graph result "
                f"or a detection. See `{GUIDE_URI}` for id formats."
            ),
            examples=["pid:0123456789abcdef0123456789abcdef:123456789012"],
        ),
        edge_type: str = Field(
            description=(
                "The edge type to follow, such as 'child_process', 'dns_request' or "
                "'connected_ip4'. List them with falcon_list_threatgraph_edge_types."
            ),
            examples=["child_process", "dns_request"],
        ),
        direction: Literal["in", "out"] | None = Field(
            default=None,
            description="Follow only incoming ('in') or outgoing ('out') edges. Omit for both.",
        ),
        scope: Literal["device", "customer"] = Field(
            default="device",
            description=(
                "'device' for device-scoped vertices, 'customer' for tenant-wide vertices."
            ),
        ),
        limit: int = Field(
            default=100,
            ge=1,
            le=100,
            description="Maximum edges to return per page. [1-100]",
        ),
        offset: str | None = Field(
            default=None,
            description="Cursor for the next page: `pagination.next` from the previous call.",
        ),
        nano: bool = Field(
            default=False,
            description="Return timestamps with nanosecond precision.",
        ),
    ) -> dict[str, Any]:
        """Follow one edge type from a Threat Graph vertex.

        Use this to pivot one hop at a time, for example from a process to its child
        processes, the domains it looked up or the files it wrote. Each edge names
        its neighbouring vertex id, which you can pass back in for the next hop.
        Returns the edges and a `pagination.next` cursor, which is null when the API
        returns no cursor.
        """
        operation = "combined_edges_get"
        vertex_id = vertex_id.strip() if isinstance(vertex_id, str) else vertex_id
        edge_type = edge_type.strip() if isinstance(edge_type, str) else edge_type

        error = _validate_vertex_id(vertex_id)
        if not error and (not isinstance(edge_type, str) or not _EDGE_TYPE_RE.fullmatch(edge_type)):
            error = (
                f"Invalid edge type {edge_type!r}: use lowercase letters, digits and "
                "underscores, as listed by falcon_list_threatgraph_edge_types."
            )
        if not error and direction is not None and direction not in DIRECTIONS:
            # The API has no "both" value; omitting direction means both.
            error = f"Invalid direction {direction!r}: use 'in' or 'out', or omit it for both."
        if not error:
            error = _validate_common(scope, limit)
        if not error and offset is not None and _validate_vertex_id(offset):
            error = f"Invalid offset {offset!r}"
        if error:
            return _format_error_response(error, operation=operation)

        params = prepare_api_parameters(
            {
                "ids": vertex_id,
                "edge_type": edge_type,
                "direction": direction,
                "scope": scope,
                "limit": limit,
                "offset": offset,
                "nano": nano or None,
            }
        )
        logger.debug("Threat Graph edges with params: %s", params)

        response = self.client.command(operation, parameters=params)
        results = handle_api_response(
            response,
            operation=operation,
            error_message="Failed to get Threat Graph edges",
            default_result=[],
        )
        if self._is_error(results):
            return results
        return {"results": results, "pagination": {"next": _next_cursor(response)}}

    def list_threatgraph_edge_types(self) -> list[Any]:
        """List the Threat Graph edge types.

        Use this to find the right `edge_type` for falcon_get_threatgraph_edges
        instead of guessing a name. Returns the edge type names the API accepts.
        """
        operation = "queries_edgetypes_get"
        response = self.client.command(operation)
        results = handle_api_response(
            response,
            operation=operation,
            error_message="Failed to list Threat Graph edge types",
            default_result=[],
        )
        if self._is_error(results):
            return [results]
        return results
