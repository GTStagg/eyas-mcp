"""
Hosts module for Falcon MCP Server

This module provides tools for accessing and managing CrowdStrike Falcon hosts/devices.
"""

import re
from textwrap import dedent
from typing import Any

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from mcp.types import ToolAnnotations
from pydantic import AnyUrl, Field

from falcon_mcp.common.errors import _format_error_response, handle_api_response
from falcon_mcp.common.logging import get_logger
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.hosts import SEARCH_HOSTS_FQL_DOCUMENTATION

logger = get_logger(__name__)

# A host's `tags` array mixes two namespaces that are not interchangeable:
# FalconGroupingTags are set cloud-side and are what UpdateDeviceTags edits;
# SensorGroupingTags are baked in by the sensor installer and are read-only.
GROUPING_PREFIX = "FalconGroupingTags/"
SENSOR_PREFIX = "SensorGroupingTags/"

VALID_TAG_ACTIONS = ("add", "remove")

# Caps the API enforces, checked here because it reports neither cleanly
MAX_TAG_DEVICE_IDS = 5000
MAX_TAGS_PER_REQUEST = 50


# Containment goes through PerformActionV2, which takes the action as a query param
CONTAINMENT_OPERATION = "PerformActionV2"

# A Falcon agent ID (AID) is 32 hex characters
DEVICE_ID_PATTERN = re.compile(r"[0-9a-fA-F]{32}")

# The swagger states no cap. Containment takes hosts off the network, so one call is
# held to a batch small enough to review and verify.
MAX_CONTAINMENT_DEVICE_IDS = 100


def _validate_device_ids(ids: list[str] | None) -> tuple[list[str], str | None]:
    """Normalize and check device IDs before any containment call.

    Returns the deduplicated, lowercased IDs in their original order, or an error
    message when any ID is malformed or the count is out of range.
    """
    if not ids:
        return [], "`ids` must contain at least one host device ID (AID)."

    normalized: list[str] = []
    seen: set[str] = set()
    invalid: list[str] = []
    for raw in ids:
        candidate = raw.strip() if isinstance(raw, str) else ""
        if not DEVICE_ID_PATTERN.fullmatch(candidate):
            invalid.append(repr(raw))
            continue
        lowered = candidate.lower()
        if lowered not in seen:
            seen.add(lowered)
            normalized.append(lowered)

    if invalid:
        shown = ", ".join(invalid[:5])
        more = f" (and {len(invalid) - 5} more)" if len(invalid) > 5 else ""
        return [], (
            f"Invalid device ID(s): {shown}{more}. A host device ID (AID) is 32 "
            "hexadecimal characters. Find AIDs with falcon_search_hosts."
        )

    if len(normalized) > MAX_CONTAINMENT_DEVICE_IDS:
        return [], (
            f"Too many device IDs: {len(normalized)}. At most "
            f"{MAX_CONTAINMENT_DEVICE_IDS} hosts can be changed per call."
        )

    return normalized, None


def _tag_error(message: str) -> list[dict[str, Any]]:
    """Wrap a tag validation failure in the module's standard error shape."""
    return [_format_error_response(message, operation="UpdateDeviceTags")]


def _has_prefix(tag: str, prefix: str) -> bool:
    """Check for a namespace prefix without regard to how the caller cased it.

    The API compares the prefix exactly, so a miscased one is not a prefix to it:
    `falcongroupingtags/x` is rejected outright, and blindly prepending the
    canonical prefix would instead build the real-but-meaningless
    `FalconGroupingTags/falcongroupingtags/x`. Recognizing prefixes
    case-insensitively lets the caller's intent be honored either way.
    """
    return tag.casefold().startswith(prefix.casefold())


class HostsModule(BaseModule):
    """Module for accessing and managing CrowdStrike Falcon hosts/devices."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        # Register tools
        self._add_tool(
            server=server,
            method=self.search_hosts,
            name="search_hosts",
        )

        self._add_tool(
            server=server,
            method=self.get_host_details,
            name="get_host_details",
        )

        self._add_tool(
            server=server,
            method=self.manage_host_grouping_tags,
            name="manage_host_grouping_tags",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.contain_hosts,
            name="contain_hosts",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.lift_host_containment,
            name="lift_host_containment",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP server.

        Args:
            server: MCP server instance
        """
        search_hosts_fql_resource = TextResource(
            uri=AnyUrl("falcon://hosts/search/fql-guide"),
            name="falcon_search_hosts_fql_guide",
            description="Contains the guide for the `filter` param of the `falcon_search_hosts` tool.",
            text=SEARCH_HOSTS_FQL_DOCUMENTATION,
        )

        self._add_resource(
            server,
            search_hosts_fql_resource,
        )

    def search_hosts(
        self,
        filter: str | None = Field(
            default=None,
            description="FQL filter expression. See `falcon://hosts/search/fql-guide` for syntax.",
            examples={"platform_name:'Windows'", "hostname:'PC*'"},
        ),
        limit: int = Field(
            default=10,
            ge=1,
            le=5000,
            description="The maximum records to return. [1-5000]",
        ),
        offset: int | None = Field(
            default=None,
            description="The offset to start retrieving records from.",
        ),
        sort: str | None = Field(
            default=None,
            description=dedent("""
                Sort hosts using these options:

                hostname: Host name/computer name
                last_seen: Timestamp when the host was last seen
                first_seen: Timestamp when the host was first seen
                modified_timestamp: When the host record was last modified
                platform_name: Operating system platform
                agent_version: CrowdStrike agent version
                os_version: Operating system version
                external_ip: External IP address

                Sort either asc (ascending) or desc (descending). Use the dot
                separator ('hostname.desc'), which is supported on every Falcon
                sort endpoint. The pipe form ('hostname|desc') is accepted here
                but rejected by some endpoints, so prefer the dot form.

                Examples: 'hostname.asc', 'last_seen.desc', 'platform_name.asc'
            """).strip(),
            examples={"hostname.asc", "last_seen.desc"},
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search hosts and their sensor state: filter by hostname, platform, IP, sensor version, containment (network-quarantine) status, assigned policies, or grouping tags.

        Use this to find devices and check their protection state - whether a host is
        contained, what sensor version it runs, which policies apply. For drive encryption,
        disk/memory/CPU, OS security settings, or internet exposure, use
        `falcon_search_managed_assets`. See `falcon://hosts/search/fql-guide` for filters;
        returns full host details.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        device_ids, pagination = self._base_search_with_meta(
            operation="QueryDevicesByFilter",
            search_params={
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
            },
            error_message="Failed to search hosts",
        )

        if self._is_error(device_ids):
            return self._format_fql_error_response(
                [device_ids], filter, SEARCH_HOSTS_FQL_DOCUMENTATION
            )

        if not device_ids:
            return self._build_pagination_envelope([], pagination, filter)

        details = self._base_get_by_ids(
            operation="PostDeviceDetailsV2",
            ids=device_ids,
            id_key="ids",
        )

        if self._is_error(details):
            return [details]

        # Restore the query-step sort order in case the details endpoint
        # returns entities in a different order (validated field: device_id).
        details = self._reorder_by_ids(device_ids, details, id_field="device_id")
        return self._build_pagination_envelope(details, pagination, filter)

    def get_host_details(
        self,
        ids: list[str] = Field(
            description="Host device IDs to retrieve details for. You can get device IDs from the search_hosts operation, the Falcon console, or the Streaming API. Maximum: 5000 IDs per request."
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Retrieve detailed information for one or more host device IDs.

        Use when you already have specific device IDs from search results, the Falcon
        console, or the Streaming API. For discovering hosts by criteria, use
        falcon_search_hosts instead. Returns comprehensive host details.
        """
        logger.debug("Getting host details for IDs: %s", ids)

        # Handle empty list case - return empty list without making API call
        if not ids:
            return []

        return self._base_get_by_ids(
            operation="PostDeviceDetailsV2",
            ids=ids,
            id_key="ids",
        )

    def manage_host_grouping_tags(
        self,
        ids: list[str] = Field(
            description=(
                "Host device IDs (AIDs) to tag. You can get device IDs from the "
                "falcon_search_hosts operation, the Falcon console, or the Streaming API. "
                "Maximum: 5000 IDs per request."
            ),
        ),
        action: str = Field(
            description="Action to perform. Values: 'add' or 'remove'.",
        ),
        tags: list[str] = Field(
            description=(
                "Falcon Grouping Tags to add or remove. The 'FalconGroupingTags/' "
                "prefix is optional and is added automatically. Sensor grouping tags "
                "('SensorGroupingTags/') are applied by the sensor installer and "
                "cannot be changed through this API. Maximum: 50 tags per request."
            ),
        ),
    ) -> list[dict[str, Any]]:
        """Add or remove Falcon Grouping Tags on one or more hosts.

        Set action to 'add' to attach tags, or 'remove' to detach them, on every device
        in `ids`. Grouping tags can drive dynamic host group assignment and therefore
        policy assignment, so changing them may change a host's security posture.
        Adding a tag a host already has, or removing one it lacks, is a no-op. Returns
        one record per device, each with `device_id`, `updated`, and `code`. Tag names
        are case-sensitive, so removing a tag requires the exact casing it was created
        with.
        """
        if action not in VALID_TAG_ACTIONS:
            return _tag_error(f"Invalid action {action!r}. Must be 'add' or 'remove'.")

        if not ids:
            return _tag_error("`ids` must be provided to manage host grouping tags.")

        if len(ids) > MAX_TAG_DEVICE_IDS:
            return _tag_error(
                f"Too many device IDs: {len(ids)}. The API accepts at most "
                f"{MAX_TAG_DEVICE_IDS} per request."
            )

        if not tags:
            return _tag_error("`tags` must be provided to manage host grouping tags.")

        if len(tags) > MAX_TAGS_PER_REQUEST:
            return _tag_error(
                f"Too many tags: {len(tags)}. The API accepts at most "
                f"{MAX_TAGS_PER_REQUEST} per request and fails the whole call above that."
            )

        normalized_tags: list[str] = []
        for tag in tags:
            # Trim before prefixing: ' Quarantined' would otherwise become the
            # distinct (and real) tag 'FalconGroupingTags/ Quarantined'.
            stripped = tag.strip()

            if not stripped:
                return _tag_error("Tag values cannot be empty.")

            # Reject before prefixing. Prefixing a sensor tag would build a real but
            # meaningless 'FalconGroupingTags/SensorGroupingTags/...' tag rather than
            # failing, so the guard has to come first.
            if _has_prefix(stripped, SENSOR_PREFIX):
                return _tag_error(
                    f"{stripped!r} is a sensor grouping tag. Those are applied by "
                    "the sensor installer and cannot be changed through the API."
                )

            if _has_prefix(stripped, GROUPING_PREFIX):
                # Re-apply the canonical prefix so a miscased one still lands on the
                # tag the caller meant, rather than being rejected by the API.
                normalized_tags.append(GROUPING_PREFIX + stripped[len(GROUPING_PREFIX):])
            else:
                normalized_tags.append(GROUPING_PREFIX + stripped)

        logger.debug(
            "Performing tag %s on %d host(s): %s", action, len(ids), normalized_tags
        )

        result = self._base_query_api_call(
            operation="UpdateDeviceTags",
            # The Uber class (APIHarnessV2) takes the raw swagger body, so these are
            # `action`/`device_ids` — not the `action_name`/`ids` keyword names used
            # by FalconPy's Hosts.update_device_tags() service-class method.
            body_params={
                "action": action,
                "device_ids": ids,
                "tags": normalized_tags,
            },
            error_message="Failed to manage host grouping tags",
            default_result=[],
        )

        if self._is_error(result):
            return [result]

        return result

    def contain_hosts(
        self,
        ids: list[str] = Field(
            description=(
                "Host device IDs (AIDs, 32 hex characters) to contain. Get them from "
                "falcon_search_hosts. Duplicates are ignored. Maximum: "
                f"{MAX_CONTAINMENT_DEVICE_IDS} hosts per call."
            ),
        ),
    ) -> dict[str, Any]:
        """Network-contain one or more hosts.

        Use this to isolate a compromised or suspicious host during incident response.
        A contained host loses all network access except to the CrowdStrike Falcon
        cloud (and any IPs the tenant's containment policy allows) until containment
        is lifted with `falcon_lift_host_containment`, which interrupts its users and
        services. Containing an already-contained host is a no-op. Returns the API's
        per-host results as `succeeded_ids` and `resources`; on a partial failure,
        `partial_failure` is true and `failed_ids` and `errors` say which hosts were
        not contained and why. The sensor applies containment asynchronously, so
        verify the state afterwards with `falcon_search_hosts` filtering on `status`
        (`containment_pending`, then `contained`).
        """
        return self._perform_containment_action("contain", ids)

    def lift_host_containment(
        self,
        ids: list[str] = Field(
            description=(
                "Host device IDs (AIDs, 32 hex characters) to release from containment. "
                "Find contained hosts with falcon_search_hosts and the filter "
                "status:'contained'. Duplicates are ignored. Maximum: "
                f"{MAX_CONTAINMENT_DEVICE_IDS} hosts per call."
            ),
        ),
    ) -> dict[str, Any]:
        """Lift network containment from one or more hosts.

        Use this once remediation is complete to restore a contained host's normal
        network access. Lifting containment on a host that is not contained is a
        no-op. Returns the API's per-host results as `succeeded_ids` and `resources`;
        on a partial failure, `partial_failure` is true and `failed_ids` and `errors`
        say which hosts were not released and why. The sensor applies the change
        asynchronously, so verify the state afterwards with `falcon_search_hosts`
        filtering on `status` (`lift_containment_pending`, then `normal`).
        """
        return self._perform_containment_action("lift_containment", ids)

    def _perform_containment_action(
        self, action_name: str, ids: list[str] | None
    ) -> dict[str, Any]:
        """Run a containment action and report per-host results.

        PerformActionV2 can answer with `resources` for some IDs and `errors` for
        others, and may do so under a non-2xx status. handle_api_response would drop
        the resources on a non-2xx and hide hosts whose state did change, so the
        response is read here instead.
        """
        device_ids, problem = _validate_device_ids(ids)
        if problem:
            return _format_error_response(problem, operation=CONTAINMENT_OPERATION)

        logger.debug("Performing %s on %d host(s)", action_name, len(device_ids))

        # action_name is `in: query`; the IDs travel in the body
        response = self.client.command(
            CONTAINMENT_OPERATION,
            parameters={"action_name": action_name},
            body={"ids": device_ids},
        )

        status_code = response.get("status_code")
        body = response.get("body") or {}
        resources = [r for r in body.get("resources") or [] if isinstance(r, dict)]
        errors = body.get("errors") or []
        error_message = f"Failed to perform {action_name}"

        if not resources:
            # Nothing changed. Report a plain error, keeping the 403 scope hints.
            if status_code is None or status_code >= 300:
                error: dict[str, Any] = handle_api_response(
                    response,
                    operation=CONTAINMENT_OPERATION,
                    error_message=error_message,
                )
                return error
            if errors:
                api_messages = [e.get("message") for e in errors if e.get("message")]
                detail = f" API said: {'; '.join(api_messages)}" if api_messages else ""
                return _format_error_response(
                    f"{error_message}:{detail}",
                    details=response,
                    operation=CONTAINMENT_OPERATION,
                )

        confirmed = {str(r.get("id", "")).lower() for r in resources}
        succeeded_ids = [i for i in device_ids if i in confirmed]
        failed_ids = [i for i in device_ids if i not in confirmed]

        result: dict[str, Any] = {
            "action": action_name,
            "status_code": status_code,
            "requested_ids": device_ids,
            "succeeded_ids": succeeded_ids,
            "resources": resources,
        }
        if failed_ids or errors:
            result["partial_failure"] = True
            result["failed_ids"] = failed_ids
            result["errors"] = errors
            result["warning"] = (
                f"{action_name} was accepted for {len(succeeded_ids)} of "
                f"{len(device_ids)} host(s). `failed_ids` lists hosts the API did not "
                "confirm, and `errors` gives its reasons."
            )
        return result
