"""
Host Groups module for Falcon MCP Server

This module provides tools for searching, creating, updating, and deleting
CrowdStrike Falcon host groups, as well as managing group membership.
"""

import re
import time
from concurrent.futures import FIRST_EXCEPTION, Future, ThreadPoolExecutor, wait
from textwrap import dedent
from typing import Any, Literal

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from mcp.types import ToolAnnotations
from pydantic import AnyUrl, Field

from falcon_mcp.common.errors import _format_error_response
from falcon_mcp.common.logging import get_logger
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.host_groups import SEARCH_HOST_GROUPS_FQL_DOCUMENTATION

logger = get_logger(__name__)

# Membership checks run this many at a time, within this many seconds, so a full
# check stays under a 60-second MCP client timeout.
MEMBERSHIP_CHECK_WORKERS = 8
MEMBERSHIP_CHECK_BUDGET_SECONDS = 50
GROUP_PAGE_SIZE = 500
GROUP_DETAILS_BATCH = 100
# device_id is written into a quoted FQL value, so only a real AID is accepted.
DEVICE_ID_PATTERN = re.compile(r"[0-9a-fA-F]{32}")
STATIC_GROUP_FILTER = "group_type:'static',group_type:'staticByID'"


class MembershipCheckError(Exception):
    """A group membership check failed, so the answer would be incomplete."""

    def __init__(self, group_id: str, detail: Any) -> None:
        super().__init__(group_id)
        self.group_id = group_id
        self.detail = detail


class HostGroupsModule(BaseModule):
    """Module for managing CrowdStrike Falcon host groups and their membership."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(
            server=server,
            method=self.search_host_groups,
            name="search_host_groups",
        )

        self._add_tool(
            server=server,
            method=self.search_host_group_members,
            name="search_host_group_members",
        )

        self._add_tool(
            server=server,
            method=self.get_host_group_membership,
            name="get_host_group_membership",
        )

        self._add_tool(
            server=server,
            method=self.create_host_group,
            name="create_host_group",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.update_host_group,
            name="update_host_group",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.delete_host_groups,
            name="delete_host_groups",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.perform_host_group_action,
            name="perform_host_group_action",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP server.

        Args:
            server: MCP server instance
        """
        search_host_groups_fql_resource = TextResource(
            uri=AnyUrl("falcon://host-groups/search/fql-guide"),
            name="falcon_search_host_groups_fql_guide",
            description=(
                "Contains the guide for the `filter` param of the "
                "`falcon_search_host_groups` tool."
            ),
            text=SEARCH_HOST_GROUPS_FQL_DOCUMENTATION,
        )

        self._add_resource(
            server,
            search_host_groups_fql_resource,
        )

    def search_host_groups(
        self,
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter expression. See `falcon://host-groups/search/fql-guide` "
                "for syntax."
            ),
            examples={"group_type:'static'", "name:'Production Servers'"},
        ),
        limit: int = Field(
            default=100,
            ge=1,
            le=5000,
            description="The maximum records to return. [1-5000]",
        ),
        offset: int | None = Field(
            default=None,
            description="The offset to start retrieving records from.",
        ),
        sort: str = Field(
            default="name.asc",
            description=dedent("""
                Sort host groups using these options:

                name: Host group name
                group_type: Host group type (static/dynamic)
                created_by: User who created the group
                created_timestamp: When the group was created
                modified_by: User who last modified the group
                modified_timestamp: When the group was last modified

                Sort either asc (ascending) or desc (descending).
                Use the dot separator ('name.desc'), which is supported on every
                Falcon sort endpoint. The pipe form ('name|desc') is accepted
                here but rejected by some endpoints, so prefer the dot form.

                Examples: 'name.asc', 'created_timestamp.desc'
            """).strip(),
            examples={"name.asc", "created_timestamp.desc"},
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search for host groups in your CrowdStrike environment.

        Use this to find host groups by name, type, creator, or timestamps. Consult
        falcon://host-groups/search/fql-guide before constructing filter expressions.
        Returns full host group details including id, name, group_type, description,
        and audit metadata in a single call.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        host_groups, pagination = self._base_search_with_meta(
            operation="queryCombinedHostGroups",
            search_params={
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
            },
            error_message="Failed to search host groups",
        )

        if self._is_error(host_groups):
            return self._format_fql_error_response(
                [host_groups], filter, SEARCH_HOST_GROUPS_FQL_DOCUMENTATION
            )

        return self._build_pagination_envelope(host_groups or [], pagination, filter)

    def search_host_group_members(
        self,
        id: str = Field(
            description=(
                "The host group ID whose members should be retrieved. If you don't "
                "already have it, use falcon_search_host_groups to look it up."
            ),
        ),
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter expression on HOST attributes. See "
                "`falcon://hosts/search/fql-guide` for syntax."
            ),
            examples={"platform_name:'Windows'", "hostname:'PC*'"},
        ),
        limit: int = Field(
            default=100,
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
            description="Sort members using host FQL sort syntax (e.g. 'hostname.asc', 'last_seen.desc').",
            examples={"hostname.asc", "last_seen.desc"},
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search for the host members of a specific host group.

        Use this to list the devices that belong to a host group. Requires the group
        `id` and filters on HOST attributes (platform, hostname, etc.) — consult
        falcon://hosts/search/fql-guide for the filter syntax. Returns full host device
        entities including device_id, hostname, platform, and network context.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        members, pagination = self._base_search_with_meta(
            operation="queryCombinedGroupMembers",
            search_params={
                "id": id,
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
            },
            error_message="Failed to search host group members",
        )

        if self._is_error(members):
            return [members]

        return self._build_pagination_envelope(members or [], pagination, filter)

    def get_host_group_membership(
        self,
        device_id: str = Field(
            description=(
                "The host device ID (AID) whose host groups should be listed. If you "
                "don't already have it, use falcon_search_hosts to look it up."
            ),
        ),
        verify: Literal["none", "record", "static", "all"] = Field(
            default="none",
            description=dedent("""
                How to confirm membership. The host record's group list can be stale.

                • none: trust the host record (one call, fastest).
                • record: check each group on the host record and drop any the host is
                  no longer in.
                • static: also check every static group, to find static memberships the
                  host record is missing. Use this before saving groups to restore later:
                  dynamic groups re-evaluate on their own, static ones don't.
                • all: check every host group. On tenants with many groups this can run
                  past the time budget, which fails the call.

                Any mode except none checks groups 8 at a time within 50 seconds. If any
                check fails (permission, upstream or network error) or the budget runs
                out, the whole call fails rather than reporting the host as not a member.
            """).strip(),
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """List every host group a single host belongs to.

        Use this to answer "which groups is this host in" before changing its group
        membership or to explain which policies reach it. Reads the host's group IDs
        from its device record, then returns full details for each group, including
        name, group_type, and assignment_rule. Dynamic group membership reflects
        Falcon's latest evaluation, so a recent tag or attribute change may not show
        yet. The host record can be stale; set verify to check membership group by
        group, for example verify='static' before saving groups to restore after
        incident response.
        """
        verify = verify if isinstance(verify, str) else "none"
        device_id = device_id.strip() if isinstance(device_id, str) else ""
        if not device_id:
            return [
                _format_error_response(
                    "`device_id` must be provided to look up host group membership.",
                    operation="PostDeviceDetailsV2",
                )
            ]

        devices = self._base_get_by_ids(
            operation="PostDeviceDetailsV2",
            ids=[device_id],
        )
        if not isinstance(devices, list):
            return [devices]

        if not devices:
            return [
                _format_error_response(
                    f"No host found with device ID {device_id!r}.",
                    operation="PostDeviceDetailsV2",
                )
            ]

        device = devices[0]
        group_ids = [group_id for group_id in device.get("groups") or [] if group_id]

        response: dict[str, Any] = {
            "device_id": device.get("device_id", device_id),
            "hostname": device.get("hostname"),
            "results": [],
            "count": 0,
        }

        if verify != "none":
            verified = self._verify_membership(device_id, group_ids, verify)
            if "error" in verified:
                return [verified]
            group_ids = verified.pop("member_group_ids")
            response["verification"] = verified

        if not group_ids:
            return response

        groups = self._base_get_by_ids(
            operation="getHostGroups",
            ids=group_ids,
            use_params=True,
        )
        if not isinstance(groups, list):
            return [groups]

        groups = self._reorder_by_ids(group_ids, groups, id_field="id")
        response["results"] = groups
        response["count"] = len(groups)

        resolved = {str(group.get("id")) for group in groups}
        unresolved = [group_id for group_id in group_ids if group_id not in resolved]
        if unresolved:
            response["unresolved_group_ids"] = unresolved

        return response

    def _verify_membership(
        self,
        device_id: str,
        record_group_ids: list[str],
        mode: str,
    ) -> dict[str, Any]:
        """Check, group by group, which host groups really contain the device.

        Returns `member_group_ids` plus a summary, or an error response when any
        check fails or the time budget runs out. A failed check never counts as
        "not a member".
        """
        if not DEVICE_ID_PATTERN.fullmatch(device_id):
            return _format_error_response(
                "verify needs `device_id` to be a 32-character host ID (AID).",
                operation="queryGroupMembers",
            )

        started = time.monotonic()
        candidates = list(dict.fromkeys(record_group_ids))
        if mode in ("static", "all"):
            listed = self._list_group_ids(STATIC_GROUP_FILTER if mode == "static" else None)
            if isinstance(listed, dict):
                return listed
            candidates = list(dict.fromkeys([*candidates, *listed]))

        deadline = started + MEMBERSHIP_CHECK_BUDGET_SECONDS
        members: set[str] = set()
        deleted: list[str] = []
        executor = ThreadPoolExecutor(max_workers=MEMBERSHIP_CHECK_WORKERS)
        try:
            futures: dict[Future[str], str] = {
                executor.submit(self._check_group_member, group_id, device_id): group_id
                for group_id in candidates
            }
            done, pending = wait(
                futures, timeout=max(deadline - time.monotonic(), 0), return_when=FIRST_EXCEPTION
            )
            for future in done:
                error = future.exception()
                if isinstance(error, MembershipCheckError):
                    return _format_error_response(
                        f"Membership check failed for host group {error.group_id}, so the "
                        "membership list would be incomplete. Nothing was assumed.",
                        details=error.detail,
                        operation="queryGroupMembers",
                    )
                if error is not None:
                    return _format_error_response(
                        f"Membership check failed for host group {futures[future]}: {error}",
                        operation="queryGroupMembers",
                    )
                outcome = future.result()
                if outcome == "member":
                    members.add(futures[future])
                elif outcome == "deleted":
                    deleted.append(futures[future])
            if pending:
                return _format_error_response(
                    f"Checked {len(done)} of {len(candidates)} host groups before the "
                    f"{MEMBERSHIP_CHECK_BUDGET_SECONDS}-second budget ran out, so the "
                    "membership list would be incomplete. Try verify='record' or "
                    "verify='static', which check fewer groups.",
                    operation="queryGroupMembers",
                )
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        record = set(record_group_ids)
        return {
            "member_group_ids": [g for g in candidates if g in members],
            "mode": mode,
            "groups_checked": len(candidates),
            "seconds": round(time.monotonic() - started, 1),
            "stale_record_group_ids": [g for g in record_group_ids if g not in members],
            "missing_from_record_group_ids": [g for g in candidates if g in members and g not in record],
            "deleted_group_ids": deleted,
        }

    def _check_group_member(self, group_id: str, device_id: str) -> str:
        """Return 'member', 'not_member' or 'deleted', or raise MembershipCheckError."""
        try:
            response = self.client.command(
                "queryGroupMembers",
                parameters={"id": group_id, "filter": f"device_id:'{device_id}'", "limit": 1},
            )
        except Exception as exc:  # noqa: BLE001 - any transport failure must fail the call
            raise MembershipCheckError(group_id, {"exception": str(exc)}) from exc

        status = response.get("status_code")
        body = response.get("body") or {}
        if status == 200:
            return "member" if body.get("resources") else "not_member"
        messages = [str(e.get("message", "")) for e in body.get("errors") or []]
        if status == 404 and any("group not found" in m.lower() for m in messages):
            return "deleted"
        raise MembershipCheckError(group_id, {"status_code": status, "errors": body.get("errors")})

    def _list_group_ids(self, group_filter: str | None) -> list[str] | dict[str, Any]:
        """List host group IDs, optionally filtered, across every page."""
        ids: list[str] = []
        offset = 0
        while True:
            params: dict[str, Any] = {"limit": GROUP_PAGE_SIZE, "offset": offset}
            if group_filter:
                params["filter"] = group_filter
            response = self.client.command("queryHostGroups", parameters=params)
            if response.get("status_code") != 200:
                return _format_error_response(
                    "Failed to list host groups for the membership check.",
                    details=response.get("body"),
                    operation="queryHostGroups",
                )
            page = (response.get("body") or {}).get("resources") or []
            ids.extend(page)
            total = ((response.get("body") or {}).get("meta") or {}).get("pagination", {}).get("total")
            offset += len(page)
            if not page or len(page) < GROUP_PAGE_SIZE or (isinstance(total, int) and offset >= total):
                return ids

    def create_host_group(
        self,
        name: str = Field(
            description="Name for the new host group.",
        ),
        group_type: str = Field(
            description=(
                "Type of host group. One of: 'static' (hosts added manually by ID "
                "via falcon_perform_host_group_action), 'staticByID' (same, populated "
                "after creation), or 'dynamic' (hosts matched automatically by an "
                "assignment_rule)."
            ),
        ),
        description: str | None = Field(
            default=None,
            description="Description for the host group.",
        ),
        assignment_rule: str | None = Field(
            default=None,
            description="FQL assignment rule for dynamic groups (e.g. \"platform_name:'Windows'\"). Required for 'dynamic' groups; the API rejects it for 'static'/'staticByID' groups.",
        ),
    ) -> list[dict[str, Any]]:
        """Create a host group.

        Provide a name and group_type. 'dynamic' groups take an assignment_rule (host
        FQL) that automatically includes matching hosts. 'static' and 'staticByID' groups
        are created empty (no assignment_rule) and populated afterwards via
        falcon_perform_host_group_action. Returns the created host group record on success.
        """
        resource: dict[str, Any] = {
            "name": name,
            "group_type": group_type,
        }
        if description is not None:
            resource["description"] = description
        if assignment_rule is not None:
            resource["assignment_rule"] = assignment_rule

        result = self._base_query_api_call(
            operation="createHostGroups",
            body_params={"resources": [resource]},
            error_message="Failed to create host group",
            default_result=[],
        )

        if self._is_error(result):
            return [result]

        return result

    def update_host_group(
        self,
        id: str = Field(
            description="The host group ID to update. If you don't already have it, use falcon_search_host_groups to look it up.",
        ),
        name: str | None = Field(
            default=None,
            description="New name for the host group.",
        ),
        description: str | None = Field(
            default=None,
            description="New description for the host group.",
        ),
        assignment_rule: str | None = Field(
            default=None,
            description="New FQL assignment rule (e.g. \"platform_name:'Windows'\"). Only set this for 'dynamic' groups. The API does not block setting it on 'static'/'staticByID' groups, but doing so leaves the group in an inconsistent state and should be avoided.",
        ),
    ) -> list[dict[str, Any]]:
        """Update an existing host group.

        Provide the group `id` and any fields to change. name and description are safe
        for any group type; only set assignment_rule on 'dynamic' groups. Unspecified
        fields are left unchanged. Returns the updated host group record on success.
        """
        resource: dict[str, Any] = {"id": id}
        if name is not None:
            resource["name"] = name
        if description is not None:
            resource["description"] = description
        if assignment_rule is not None:
            resource["assignment_rule"] = assignment_rule

        result = self._base_query_api_call(
            operation="updateHostGroups",
            body_params={"resources": [resource]},
            error_message="Failed to update host group",
            default_result=[],
        )

        if self._is_error(result):
            return [result]

        return result

    def delete_host_groups(
        self,
        ids: list[str] = Field(
            description="Host group IDs to delete. If you don't already have them, use falcon_search_host_groups to look them up.",
        ),
    ) -> list[dict[str, Any]]:
        """Delete one or more host groups.

        Provide the host group `ids` to delete. This permanently removes the groups.
        Returns an empty list on success.
        """
        if not ids:
            return [
                _format_error_response(
                    "`ids` must be provided to delete host groups.",
                    operation="deleteHostGroups",
                )
            ]

        result = self._base_query_api_call(
            operation="deleteHostGroups",
            query_params={"ids": ids},
            error_message="Failed to delete host groups",
            default_result=[],
        )

        if self._is_error(result):
            return [result]

        return result

    def perform_host_group_action(
        self,
        action_name: str = Field(
            description="The membership action to perform. Either 'add-hosts' or 'remove-hosts'.",
        ),
        ids: list[str] = Field(
            description="Host group IDs to add hosts to or remove hosts from. If you don't already have them, use falcon_search_host_groups to look them up.",
        ),
        filter: str = Field(
            description="Host FQL expression selecting which hosts to add or remove (e.g. \"device_id:['id1','id2']\" or \"platform_name:'Windows'\"). See `falcon://hosts/search/fql-guide` for syntax.",
        ),
    ) -> list[dict[str, Any]]:
        """Add or remove hosts from one or more host groups.

        Set action_name to 'add-hosts' or 'remove-hosts', provide the target group
        `ids`, and a host FQL filter selecting which hosts to act on. Applies only to
        static groups. Returns the updated host group records on success.
        """
        result = self._base_query_api_call(
            operation="performGroupAction",
            query_params={"action_name": action_name},
            body_params={
                "ids": ids,
                "action_parameters": [{"name": "filter", "value": filter}],
            },
            error_message="Failed to perform host group action",
            default_result=[],
        )

        if self._is_error(result):
            return [result]

        return result
