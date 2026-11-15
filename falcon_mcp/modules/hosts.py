"""
Hosts module for Falcon MCP Server

This module provides tools for accessing and managing CrowdStrike Falcon hosts/devices.
"""

import ipaddress
import re
from collections.abc import Callable
from textwrap import dedent
from typing import Any, Literal

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from mcp.types import ToolAnnotations
from pydantic import AnyUrl, Field

from falcon_mcp.common.errors import (
    _format_error_response,
    error_details,
    handle_api_response,
)
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


# Containment and hiding go through PerformActionV2, which takes the action as a query
# param
HOST_ACTION_OPERATION = "PerformActionV2"

# A Falcon agent ID (AID) is 32 hex characters
DEVICE_ID_PATTERN = re.compile(r"[0-9a-fA-F]{32}")

# The swagger states no cap for host actions. They take hosts off the network or out of
# view, so one call is held to a batch small enough to review and verify.
MAX_CONTAINMENT_DEVICE_IDS = 100

# Caps the API enforces (checked live): GetOnlineState_V1 takes 100 IDs, the address and
# login history endpoints 500, and the interactive (v2) login history 10.
MAX_ONLINE_STATE_IDS = 100
MAX_HISTORY_IDS = 500
MAX_INTERACTIVE_LOGIN_IDS = 10

# The per-host read endpoints fail a whole call when one ID is unknown, with this
# message (GetOnlineState_V1 under HTTP 200, the history endpoints under 400).
UNKNOWN_HOST_MESSAGE = "invalid device id"

# Network containment allowlist: what contained hosts may still reach. Rule types as
# CrowdStrike documents them; every rule lives in the `containment` context.
ALLOWLIST_CONTEXT = "containment"
ALLOWLIST_TYPES = ("ip_range", "ip_dns", "fqdn")
MAX_ALLOWLIST_CHANGES = 50
MAX_ALLOWLIST_LABEL = 255
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_FQDN = re.compile(
    r"(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+"
)


def _validate_device_ids(
    ids: list[str] | None, max_ids: int = MAX_CONTAINMENT_DEVICE_IDS
) -> tuple[list[str], str | None]:
    """Normalize and check device IDs before any per-host call.

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

    if len(normalized) > max_ids:
        return [], (
            f"Too many device IDs: {len(normalized)}. At most {max_ids} hosts per call."
        )

    return normalized, None


def _bad_label(label: Any) -> bool:
    """True when an allowlist label is missing, too long or holds control characters."""
    return (
        not isinstance(label, str)
        or not label.strip()
        or len(label) > MAX_ALLOWLIST_LABEL
        or bool(CONTROL_CHARS.search(label))
    )


def _allowlist_rule_problem(rule_type: Any, value: Any, allow_subdomains: Any) -> str | None:
    """Check one allowlist rule's type and value; None when it is valid."""
    if rule_type not in ALLOWLIST_TYPES:
        return f"type must be one of {list(ALLOWLIST_TYPES)}, not {rule_type!r}."
    text = value.strip() if isinstance(value, str) else ""
    if rule_type == "ip_range":
        try:
            ipaddress.ip_network(text, strict=False)
        except ValueError:
            return f"{value!r} is not an IP address or CIDR block."
    elif rule_type == "ip_dns":
        try:
            ipaddress.ip_address(text)
        except ValueError:
            return f"{value!r} is not an IP address; a DNS rule names one DNS server."
    elif not _FQDN.fullmatch(text):
        return f"{value!r} is not a domain name such as updates.example.com."
    if allow_subdomains and rule_type != "fqdn":
        return "allow_subdomains applies only to fqdn rules."
    return None


def _rejects_unknown_host(response: dict[str, Any]) -> bool:
    """True when the API failed a per-host call because an ID matched no host."""
    errors = (response.get("body") or {}).get("errors") or []
    return any(
        UNKNOWN_HOST_MESSAGE in str(e.get("message", "")).lower()
        for e in errors
        if isinstance(e, dict)
    )


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

        self._add_tool(
            server=server,
            method=self.get_host_online_state,
            name="get_host_online_state",
        )

        self._add_tool(
            server=server,
            method=self.search_containment_allowlist,
            name="search_containment_allowlist",
        )

        self._add_tool(
            server=server,
            method=self.create_containment_allowlist_rules,
            name="create_containment_allowlist_rules",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.update_containment_allowlist_labels,
            name="update_containment_allowlist_labels",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.delete_containment_allowlist_rules,
            name="delete_containment_allowlist_rules",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.get_host_network_history,
            name="get_host_network_history",
        )

        self._add_tool(
            server=server,
            method=self.get_host_login_history,
            name="get_host_login_history",
        )

        self._add_tool(
            server=server,
            method=self.search_hidden_hosts,
            name="search_hidden_hosts",
        )

        self._add_tool(
            server=server,
            method=self.hide_hosts,
            name="hide_hosts",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.unhide_hosts,
            name="unhide_hosts",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.delete_hosts,
            name="delete_hosts",
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
            examples=["platform_name:'Windows'", "hostname:'PC*'"],
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
            examples=["hostname.asc", "last_seen.desc"],
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
        return self._perform_host_action("contain", ids)

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
        return self._perform_host_action("lift_containment", ids)

    def get_host_online_state(
        self,
        ids: list[str] = Field(
            description=(
                "Host device IDs (AIDs, 32 hex characters). Get them from "
                "falcon_search_hosts. Duplicates are ignored. Maximum: "
                f"{MAX_ONLINE_STATE_IDS} hosts per call."
            ),
        ),
    ) -> dict[str, Any]:
        """Check whether hosts are online right now: `state` is online, offline or unknown.

        Use this before starting an RTR session, containing a host or running a script,
        to know whether the sensor will act now or queue the request. Returns
        `results` (one record per host with `id`, `state` and `last_seen`) and
        `not_found` (IDs that match no host).
        """
        device_ids, problem = _validate_device_ids(ids, MAX_ONLINE_STATE_IDS)
        if problem:
            return _format_error_response(problem, operation="GetOnlineState_V1")

        def call(batch: list[str]) -> dict[str, Any]:
            return self.client.command("GetOnlineState_V1", parameters={"ids": batch})

        return self._per_host_read(
            call,
            device_ids,
            operation="GetOnlineState_V1",
            error_message="Failed to get host online state",
        )

    def get_host_network_history(
        self,
        ids: list[str] = Field(
            description=(
                "Host device IDs (AIDs, 32 hex characters). Get them from "
                "falcon_search_hosts. Duplicates are ignored. Maximum: "
                f"{MAX_HISTORY_IDS} hosts per call."
            ),
        ),
    ) -> dict[str, Any]:
        """Get the history of IP and MAC addresses each host has used.

        Use this to tie an IP address seen at a point in time back to the host that held
        it, or to see where a host has been on the network. Returns `results` (one
        record per host with `device_id` and `history`, a list of `ip_address`,
        `mac_address` and `timestamp`) and `not_found` (IDs that match no host).
        To find hosts by their current IP, use falcon_search_hosts with `local_ip` or
        `external_ip`.
        """
        device_ids, problem = _validate_device_ids(ids, MAX_HISTORY_IDS)
        if problem:
            return _format_error_response(
                problem, operation="QueryGetNetworkAddressHistoryV1"
            )

        def call(batch: list[str]) -> dict[str, Any]:
            return self.client.command(
                "QueryGetNetworkAddressHistoryV1", body={"ids": batch}
            )

        return self._per_host_read(
            call,
            device_ids,
            operation="QueryGetNetworkAddressHistoryV1",
            error_message="Failed to get host network address history",
        )

    def get_host_login_history(
        self,
        ids: list[str] = Field(
            description=(
                "Host device IDs (AIDs, 32 hex characters). Get them from "
                "falcon_search_hosts. Duplicates are ignored. Maximum: "
                f"{MAX_HISTORY_IDS} hosts per call, or {MAX_INTERACTIVE_LOGIN_IDS} "
                "when `interactive_only` is true."
            ),
        ),
        interactive_only: bool = Field(
            default=False,
            description=(
                "False (default): each host's most recent logins of any kind, up to 10 "
                "per host. True: interactive logins only, from the Host Timeline, "
                "within the `since`/`until` window and up to `limit` per host."
            ),
        ),
        since: str = Field(
            default="now-7d",
            description=(
                "Start of the window, inclusive. Relative ('now-30d') or an ISO 8601 "
                "timestamp. Used only when `interactive_only` is true."
            ),
        ),
        until: str = Field(
            default="now",
            description=(
                "End of the window, inclusive. Used only when `interactive_only` is true."
            ),
        ),
        limit: int = Field(
            default=10,
            ge=1,
            le=100,
            description=(
                "Maximum logins per host [1-100]. Used only when `interactive_only` "
                "is true."
            ),
        ),
    ) -> dict[str, Any]:
        """Get the users who recently logged in to each host, with login times.

        Use this to see who was on a host around an incident, or which accounts touch a
        machine. Returns `results` (one record per host with `device_id` and
        `recent_logins`, a list of `user_name` and `login_time`) and `not_found` (IDs
        that match no host). To go the other way, from a user to the hosts they used,
        use falcon_get_user_endpoint_history.
        """
        max_ids = MAX_INTERACTIVE_LOGIN_IDS if interactive_only else MAX_HISTORY_IDS
        operation = (
            "QueryDeviceLoginHistoryV2" if interactive_only else "QueryDeviceLoginHistory"
        )
        device_ids, problem = _validate_device_ids(ids, max_ids)
        if problem:
            return _format_error_response(problem, operation=operation)

        def call(batch: list[str]) -> dict[str, Any]:
            if interactive_only:
                return self.client.command(
                    "QueryDeviceLoginHistoryV2",
                    parameters={"from": since, "to": until, "limit": limit},
                    body={"ids": batch},
                )
            return self.client.command("QueryDeviceLoginHistory", body={"ids": batch})

        return self._per_host_read(
            call,
            device_ids,
            operation=operation,
            error_message="Failed to get host login history",
        )

    def search_hidden_hosts(
        self,
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter expression, with the same fields as falcon_search_hosts. "
                "See `falcon://hosts/search/fql-guide` for syntax."
            ),
            examples=["platform_name:'Windows'", "hostname:'PC*'"],
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
            description=(
                "Sort field and direction with the dot separator, as in "
                "falcon_search_hosts. Examples: 'hostname.asc', 'last_seen.desc'"
            ),
            examples=["hostname.asc", "last_seen.desc"],
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search hidden hosts: hosts removed from the console, which falcon_search_hosts does not return.

        Hidden hosts drop out of Falcon's reporting, so check them when scoping an
        incident or when a known machine is missing from host searches. Returns full
        host details (`host_hidden_status` is `hidden`). Restore a host with
        falcon_unhide_hosts.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count).
        """
        device_ids, pagination = self._base_search_with_meta(
            operation="QueryHiddenDevices",
            search_params={
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
            },
            error_message="Failed to search hidden hosts",
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

        details = self._reorder_by_ids(device_ids, details, id_field="device_id")
        return self._build_pagination_envelope(details, pagination, filter)

    def hide_hosts(
        self,
        ids: list[str] = Field(
            description=(
                "Host device IDs (AIDs, 32 hex characters) to hide. Get them from "
                "falcon_search_hosts. While a host is hidden, no new detections for it "
                "are reported in the console or the APIs. Duplicates are ignored. "
                f"Maximum: {MAX_CONTAINMENT_DEVICE_IDS} hosts per call."
            ),
        ),
    ) -> dict[str, Any]:
        """Hide hosts: take them out of the console and out of Falcon's reporting.

        Use this for decommissioned or duplicate hosts. A hidden host goes silent:
        Falcon reports nothing new for it, so never hide a host that is part of an
        active investigation. Reverse it with falcon_unhide_hosts;
        find hidden hosts with falcon_search_hidden_hosts. Hiding an already hidden host
        is a no-op. Returns per-host results as `succeeded_ids` and `resources`; on a
        partial failure, `partial_failure` is true and `failed_ids` and `errors` say
        which hosts were not hidden and why.
        """
        return self._perform_host_action("hide_host", ids)

    def unhide_hosts(
        self,
        ids: list[str] = Field(
            description=(
                "Host device IDs (AIDs, 32 hex characters) to restore. Find them with "
                "falcon_search_hidden_hosts. Duplicates are ignored. Maximum: "
                f"{MAX_CONTAINMENT_DEVICE_IDS} hosts per call."
            ),
        ),
    ) -> dict[str, Any]:
        """Unhide hosts: restore hidden hosts to the console and to Falcon's reporting.

        Unhiding a host that is not hidden is a no-op. Returns per-host results as
        `succeeded_ids` and `resources`; on a partial failure, `partial_failure` is true
        and `failed_ids` and `errors` say which hosts were not restored and why.
        """
        return self._perform_host_action("unhide_host", ids)

    def delete_hosts(
        self,
        ids: list[str] = Field(
            description=(
                "Host device IDs (AIDs, 32 hex characters) to delete permanently. "
                "Duplicates are ignored. Maximum: "
                f"{MAX_CONTAINMENT_DEVICE_IDS} hosts per call."
            ),
        ),
    ) -> dict[str, Any]:
        """Permanently delete hosts from Falcon. This cannot be undone.

        Use this only for hosts that are gone for good, such as retired machines. To
        take a host out of view reversibly, use falcon_hide_hosts instead. Returns
        per-host results as `succeeded_ids` and `resources`; when the API confirms only
        some hosts, `partial_failure` is true and `failed_ids` and `errors` say which.
        Verify afterwards with falcon_search_hosts and falcon_search_hidden_hosts before
        retrying.
        """
        device_ids, problem = _validate_device_ids(ids)
        if problem:
            return _format_error_response(problem, operation="DevicesActionsDeleteV1")

        logger.debug("Permanently deleting %d host(s)", len(device_ids))

        # IDs only: the endpoint also takes a `filter`, which this tool never sends
        response = self.client.command("DevicesActionsDeleteV1", body={"ids": device_ids})
        return self._summarize_host_action(
            "delete", "DevicesActionsDeleteV1", device_ids, response
        )

    # ------------------------------------------------------------------ #
    # Network containment allowlist
    # ------------------------------------------------------------------ #

    def search_containment_allowlist(
        self,
        rule_type: Literal["ip_range", "ip_dns", "fqdn"] | None = Field(
            default=None,
            description=(
                "Only rules of this type: ip_range (IP or CIDR), ip_dns (DNS servers) or "
                "fqdn (domains). Omit for all."
            ),
        ),
    ) -> dict[str, Any]:
        """List the network containment allowlist: what contained hosts can still reach.

        A contained host loses network access except to the Falcon cloud and these
        rules: IP addresses and ranges (ip_range), DNS servers (ip_dns) and domains
        (fqdn). Check them before containing a host, for example to keep a remediation
        server or patch source reachable. Returns `results`, each with `id`, `type`,
        `rule`, `label`, `options` (`allow_subdomain` for fqdn rules), `created_by` and
        `created_on`, and `counts` by type.
        """
        rules = self._allowlist_rules()
        if isinstance(rules, dict):
            return rules
        shown = [r for r in rules if rule_type is None or r.get("type") == rule_type]
        counts: dict[str, int] = {t: 0 for t in ALLOWLIST_TYPES}
        for rule in rules:
            counts[str(rule.get("type"))] = counts.get(str(rule.get("type")), 0) + 1
        return {"results": shown, "counts": counts}

    def create_containment_allowlist_rules(
        self,
        rules: list[dict[str, Any]] = Field(
            description=(
                f"Rules to add, at most {MAX_ALLOWLIST_CHANGES}. Each has `type` (ip_range, "
                "ip_dns or fqdn), `rule` (an IP address or CIDR block, a DNS server's IP, "
                "or a domain), `label` (a name shown in the console) and, for fqdn only, "
                "optional `allow_subdomains` (also allow one level of subdomains)."
            ),
            examples=[[{"type": "ip_range", "rule": "10.20.0.0/16", "label": "Remediation subnet"}]],
        ),
    ) -> dict[str, Any] | list[Any]:
        """Add rules to the network containment allowlist so contained hosts can still reach them.

        Every contained host in the tenant can reach what this allowlist names, so add
        only what remediation needs. A domain (fqdn) rule needs at least one DNS server
        (ip_dns) rule, existing or in the same call. Rules that already exist with the
        same type and value are skipped and listed in `already_present`. Returns the
        API's response for the rules added.
        """
        operation = "CreateContainmentAllowlistRules"
        if not rules or not isinstance(rules, list):
            return _format_error_response("Give at least one rule.", operation=operation)
        if len(rules) > MAX_ALLOWLIST_CHANGES:
            return _format_error_response(
                f"At most {MAX_ALLOWLIST_CHANGES} rules per call.", operation=operation
            )

        wanted: list[dict[str, Any]] = []
        for index, item in enumerate(rules):
            if not isinstance(item, dict):
                return _format_error_response(f"Rule {index} is not an object.", operation=operation)
            rule_type, value = item.get("type"), item.get("rule")
            allow_subdomains = bool(item.get("allow_subdomains"))
            problem = _allowlist_rule_problem(rule_type, value, allow_subdomains)
            label = item.get("label")
            if not problem and _bad_label(label):
                problem = f"label must be 1-{MAX_ALLOWLIST_LABEL} characters without control characters."
            if problem:
                return _format_error_response(f"Rule {index}: {problem}", operation=operation)
            entry: dict[str, Any] = {
                "context": ALLOWLIST_CONTEXT,
                "type": rule_type,
                "rule": value.strip(),
                "label": label.strip(),
            }
            if rule_type == "fqdn":
                entry["options"] = {"allow_subdomain": allow_subdomains}
            wanted.append(entry)

        existing = self._allowlist_rules()
        if isinstance(existing, dict):
            return existing
        present = {(r.get("type"), str(r.get("rule", "")).lower()) for r in existing}
        new = [w for w in wanted if (w["type"], w["rule"].lower()) not in present]
        already = [w for w in wanted if (w["type"], w["rule"].lower()) in present]

        has_dns = any(r.get("type") == "ip_dns" for r in existing) or any(
            w["type"] == "ip_dns" for w in new
        )
        if any(w["type"] == "fqdn" for w in new) and not has_dns:
            return _format_error_response(
                "A domain (fqdn) rule needs a DNS server (ip_dns) rule so contained hosts "
                "can resolve it. Add an ip_dns rule first, or in the same call.",
                operation=operation,
            )
        if not new:
            return {"added": [], "already_present": already}

        # DNS servers first, so a domain rule in the same call finds one
        new.sort(key=lambda w: 0 if w["type"] == "ip_dns" else 1)
        logger.debug("Adding %d containment allowlist rule(s)", len(new))
        response = self.client.command(operation, body={"rules": new})
        added = handle_api_response(
            response, operation=operation, error_message="Failed to add allowlist rules"
        )
        if isinstance(added, dict):
            return added
        return {"added": added, "already_present": already}

    def update_containment_allowlist_labels(
        self,
        updates: list[dict[str, Any]] = Field(
            description=(
                f"At most {MAX_ALLOWLIST_CHANGES} entries of `id` (from "
                "falcon_search_containment_allowlist) and the new `label`."
            ),
        ),
    ) -> dict[str, Any] | list[Any]:
        """Rename network containment allowlist rules.

        Only the label changes. To change a rule's type, value or subdomain option,
        delete it and add a new one.
        """
        operation = "UpdateContainmentAllowlistRules"
        if not updates or not isinstance(updates, list) or len(updates) > MAX_ALLOWLIST_CHANGES:
            return _format_error_response(
                f"Give between 1 and {MAX_ALLOWLIST_CHANGES} updates.", operation=operation
            )
        existing = self._allowlist_rules()
        if isinstance(existing, dict):
            return existing
        by_id = {str(r.get("id")): r for r in existing}

        changed: list[dict[str, Any]] = []
        for index, item in enumerate(updates):
            rule_id = item.get("id") if isinstance(item, dict) else None
            label = item.get("label") if isinstance(item, dict) else None
            if rule_id not in by_id:
                return _format_error_response(
                    f"Update {index}: no allowlist rule with id {rule_id!r}.", operation=operation
                )
            if _bad_label(label):
                return _format_error_response(
                    f"Update {index}: label must be 1-{MAX_ALLOWLIST_LABEL} characters "
                    "without control characters.",
                    operation=operation,
                )
            current = by_id[rule_id]
            entry = {
                key: current[key]
                for key in ("id", "context", "type", "rule", "options")
                if current.get(key) is not None
            }
            entry["label"] = label.strip()
            changed.append(entry)

        response = self.client.command(operation, body={"rules": changed})
        result: dict[str, Any] | list[Any] = handle_api_response(
            response, operation=operation, error_message="Failed to rename allowlist rules"
        )
        return result

    def delete_containment_allowlist_rules(
        self,
        ids: list[str] = Field(
            description=(
                f"Rule IDs from falcon_search_containment_allowlist, at most "
                f"{MAX_ALLOWLIST_CHANGES}."
            ),
        ),
    ) -> dict[str, Any]:
        """Remove rules from the network containment allowlist.

        Contained hosts immediately lose access to what the rules allowed, which can cut
        a remediation tool or patch source off from them. The last DNS server (ip_dns)
        rule can't be removed while any domain (fqdn) rule remains. Returns `deleted` and,
        if any removal failed, `failed` with the API's reason.
        """
        operation = "DeleteContainmentAllowlistRules"
        wanted = list(dict.fromkeys(i for i in ids or [] if isinstance(i, str) and i.strip()))
        if not wanted or len(wanted) > MAX_ALLOWLIST_CHANGES:
            return _format_error_response(
                f"Give between 1 and {MAX_ALLOWLIST_CHANGES} rule IDs.", operation=operation
            )
        existing = self._allowlist_rules()
        if isinstance(existing, dict):
            return existing
        by_id = {str(r.get("id")): r for r in existing}
        unknown = [i for i in wanted if i not in by_id]
        if unknown:
            return _format_error_response(
                f"No allowlist rule with id {unknown}. List rules with "
                "falcon_search_containment_allowlist.",
                operation=operation,
            )
        remaining = [r for r in existing if str(r.get("id")) not in wanted]
        if any(r.get("type") == "fqdn" for r in remaining) and not any(
            r.get("type") == "ip_dns" for r in remaining
        ):
            return _format_error_response(
                "This would remove the last DNS server (ip_dns) rule while domain (fqdn) "
                "rules remain, which the API refuses. Delete the fqdn rules too, or keep a "
                "DNS rule.",
                operation=operation,
            )

        deleted: list[str] = []
        failed: list[dict[str, Any]] = []
        # The endpoint takes one ID per call
        for rule_id in wanted:
            response = self.client.command(operation, parameters={"ids": rule_id})
            if response.get("status_code") in (200, 202, 204):
                deleted.append(rule_id)
            else:
                failed.append(
                    {
                        "id": rule_id,
                        "error": handle_api_response(
                            response, operation=operation, error_message="Failed to delete"
                        ),
                    }
                )
        result: dict[str, Any] = {"deleted": deleted}
        if failed:
            result["failed"] = failed
        return result

    def _allowlist_rules(self) -> list[dict[str, Any]] | dict[str, Any]:
        """Every containment allowlist rule, or an error.

        The query returns all rule IDs at once. Looking up an unknown ID makes the API
        answer 500, so only IDs it just returned are looked up.
        """
        response = self.client.command(
            "QueryContainmentAllowlistRules",
            parameters={"filter": f"context:'{ALLOWLIST_CONTEXT}'"},
        )
        rule_ids = handle_api_response(
            response,
            operation="QueryContainmentAllowlistRules",
            error_message="Failed to list allowlist rules",
        )
        if isinstance(rule_ids, dict):
            return rule_ids
        if not rule_ids:
            return []
        rules = self._base_get_by_ids(
            operation="GetContainmentAllowlistRules", ids=rule_ids, use_params=True
        )
        if isinstance(rules, dict):
            return rules
        return sorted(rules, key=lambda r: (str(r.get("type")), str(r.get("rule"))))

    def _per_host_read(
        self,
        call: Callable[[list[str]], dict[str, Any]],
        device_ids: list[str],
        operation: str,
        error_message: str,
    ) -> dict[str, Any]:
        """Run a per-host read, setting aside IDs that match no host.

        These endpoints fail the whole call when any one ID is unknown (a deleted host,
        a typo). On that failure the IDs are checked against host details, the call is
        retried with the hosts that exist, and the rest are returned as `not_found`.
        """
        response = call(device_ids)
        not_found: list[str] = []

        if _rejects_unknown_host(response):
            known = self._existing_host_ids(device_ids)
            if known is not None:
                not_found = [i for i in device_ids if i not in known]
                remaining = [i for i in device_ids if i in known]
                if not remaining:
                    return {"results": [], "not_found": not_found}
                response = call(remaining)

        status_code = response.get("status_code")
        body = response.get("body") or {}
        resources = body.get("resources")
        if status_code is None or status_code >= 300:
            error: dict[str, Any] = handle_api_response(
                response, operation=operation, error_message=error_message
            )
            return error
        if body.get("errors") and not resources:
            # GetOnlineState_V1 reports failures under HTTP 200
            api_messages = [
                e.get("message") for e in body["errors"] if isinstance(e, dict) and e.get("message")
            ]
            return _format_error_response(
                f"{error_message}: {'; '.join(api_messages)}",
                details=error_details(response),
                operation=operation,
            )

        return {"results": resources or [], "not_found": not_found}

    def _existing_host_ids(self, device_ids: list[str]) -> set[str] | None:
        """Return which IDs belong to a host, or None when that can't be told.

        PostDeviceDetailsV2 returns the hosts it found even when it rejects the call
        for an unknown ID, and it finds hidden hosts too.
        """
        response = self.client.command("PostDeviceDetailsV2", body={"ids": device_ids})
        body = response.get("body") or {}
        found = {
            str(r.get("device_id", "")).lower()
            for r in body.get("resources") or []
            if isinstance(r, dict)
        }
        if not found and not _rejects_unknown_host(response):
            return None
        return found

    def _perform_host_action(
        self, action_name: str, ids: list[str] | None
    ) -> dict[str, Any]:
        """Run a PerformActionV2 action (contain, lift, hide, unhide) on hosts."""
        device_ids, problem = _validate_device_ids(ids)
        if problem:
            return _format_error_response(problem, operation=HOST_ACTION_OPERATION)

        logger.debug("Performing %s on %d host(s)", action_name, len(device_ids))

        # action_name is `in: query`; the IDs travel in the body
        response = self.client.command(
            HOST_ACTION_OPERATION,
            parameters={"action_name": action_name},
            body={"ids": device_ids},
        )
        return self._summarize_host_action(
            action_name, HOST_ACTION_OPERATION, device_ids, response
        )

    @staticmethod
    def _summarize_host_action(
        action_name: str,
        operation: str,
        device_ids: list[str],
        response: dict[str, Any],
    ) -> dict[str, Any]:
        """Report per-host results of a host action.

        The action endpoints can answer with `resources` for some IDs and `errors` for
        others, and may do so under a non-2xx status. handle_api_response would drop
        the resources on a non-2xx and hide hosts whose state did change, so the
        response is read here instead.
        """
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
                    operation=operation,
                    error_message=error_message,
                )
                return error
            if errors:
                api_messages = [e.get("message") for e in errors if e.get("message")]
                detail = f" API said: {'; '.join(api_messages)}" if api_messages else ""
                return _format_error_response(
                    f"{error_message}:{detail}",
                    details=error_details(response),
                    operation=operation,
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
