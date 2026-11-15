"""
Users module for Falcon MCP Server

This module provides tools for Falcon console users and roles: search users, see who
holds which roles and what a role permits, grant or revoke roles, reset a user's
password or 2FA, and create, rename or delete users.
"""

import asyncio
import re
from datetime import UTC, datetime
from typing import Any

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from mcp.types import ToolAnnotations
from pydantic import AnyUrl, Field

from falcon_mcp.common.errors import _format_error_response, handle_api_response
from falcon_mcp.common.logging import get_logger
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.users import SEARCH_USERS_FQL_DOCUMENTATION

logger = get_logger(__name__)

# Limits the API enforces or that keep one call reviewable
MAX_USER_SEARCH = 500
MAX_ROLE_CHECK_USERS = 100
MAX_ALL_USERS_SCAN = 500
MAX_ROLE_IDS = 50
MAX_CREDENTIAL_RESETS = 100
MAX_PERMISSIONS_RETURNED = 500
MAX_PERMISSION_DETAILS = 500
ROLE_CHECK_CONCURRENCY = 10

UUID_PATTERN = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
# Built-in roles have names like falconhost_admin; custom roles have hex IDs
ROLE_ID_PATTERN = re.compile(r"[A-Za-z0-9_\-]{1,128}")
EMAIL_PATTERN = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")

ROLE_ACTIONS = ("grant", "revoke")
CREDENTIAL_ACTIONS = ("reset_2fa", "reset_password")
ROLE_TYPES = ("default", "custom")

WRITE = {"readOnlyHint": False, "openWorldHint": True}


def _error(message: str, operation: str) -> dict[str, Any]:
    return _format_error_response(message, operation=operation)


def _validate_uuids(uuids: list[str] | None, limit: int) -> tuple[list[str], str | None]:
    """Normalize user UUIDs, keeping order and dropping repeats."""
    if not uuids:
        return [], "Provide at least one user UUID. Find them with falcon_search_users."
    seen: list[str] = []
    for raw in uuids:
        value = raw.strip().lower() if isinstance(raw, str) else ""
        if not UUID_PATTERN.fullmatch(value):
            return [], (
                f"Invalid user UUID {raw!r}. User UUIDs look like "
                "'1a2b3c4d-0000-0000-0000-000000000000'; find them with falcon_search_users."
            )
        if value not in seen:
            seen.append(value)
    if len(seen) > limit:
        return [], f"Too many user UUIDs: {len(seen)}. At most {limit} per call."
    return seen, None


def _validate_role_ids(role_ids: list[str] | None) -> tuple[list[str], str | None]:
    if not role_ids:
        return [], "Provide at least one role ID. Find them with falcon_search_roles."
    cleaned = list(dict.fromkeys(r.strip() for r in role_ids if isinstance(r, str)))
    bad = [r for r in cleaned if not ROLE_ID_PATTERN.fullmatch(r)]
    if bad or not cleaned:
        return [], f"Invalid role ID(s): {bad or role_ids}. Find role IDs with falcon_search_roles."
    if len(cleaned) > MAX_ROLE_IDS:
        return [], f"Too many role IDs: {len(cleaned)}. At most {MAX_ROLE_IDS} per call."
    return cleaned, None


class UsersModule(BaseModule):
    """Module for Falcon console users and roles."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(server=server, method=self.search_users, name="search_users")
        self._add_tool(server=server, method=self.get_user_roles, name="get_user_roles")
        self._add_tool(server=server, method=self.search_roles, name="search_roles")
        self._add_tool(
            server=server, method=self.get_role_permissions, name="get_role_permissions"
        )
        self._add_tool(
            server=server,
            method=self.manage_user_roles,
            name="manage_user_roles",
            annotations=ToolAnnotations(**WRITE, destructiveHint=True, idempotentHint=True),
        )
        self._add_tool(
            server=server,
            method=self.reset_user_credentials,
            name="reset_user_credentials",
            annotations=ToolAnnotations(**WRITE, destructiveHint=True, idempotentHint=False),
        )
        self._add_tool(
            server=server,
            method=self.create_user,
            name="create_user",
            annotations=ToolAnnotations(**WRITE, destructiveHint=False, idempotentHint=False),
        )
        self._add_tool(
            server=server,
            method=self.update_user,
            name="update_user",
            annotations=ToolAnnotations(**WRITE, destructiveHint=False, idempotentHint=True),
        )
        self._add_tool(
            server=server,
            method=self.delete_user,
            name="delete_user",
            annotations=ToolAnnotations(**WRITE, destructiveHint=True, idempotentHint=True),
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_resource(
            server,
            TextResource(
                uri=AnyUrl("falcon://users/search/fql-guide"),
                name="falcon_search_users_fql_guide",
                description="Contains the guide for the `filter` param of the `falcon_search_users` tool.",
                text=SEARCH_USERS_FQL_DOCUMENTATION,
            ),
        )

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #

    def search_users(
        self,
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter on users, e.g. on uid (the login email) or status. See "
                "`falcon://users/search/fql-guide` for syntax."
            ),
            examples=["uid:*'*jdoe*'", "status:'active'"],
        ),
        user_type: str | None = Field(
            default=None,
            description="'internal' or 'external' (users homed in a partner CID). Omit for all.",
        ),
        limit: int = Field(
            default=50,
            ge=1,
            le=MAX_USER_SEARCH,
            description=f"The maximum records to return. [1-{MAX_USER_SEARCH}]",
        ),
        offset: int | None = Field(
            default=None,
            description="The offset to start retrieving records from.",
        ),
        sort: str | None = Field(
            default=None,
            description="Sort as 'field.direction', e.g. 'uid.asc' or 'last_login_at.desc'.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search Falcon console users: login email, name, status, MFA factors, last login and user type.

        Use this to find a user's UUID before checking or changing their roles, or to
        review accounts (for example ones that have not logged in recently). Each
        record has `uuid`, `uid` (login email), `first_name`, `last_name`, `status`,
        `factors`, `last_login_at`, `created_at` and `user_type`. For each user's
        roles, use falcon_get_user_roles.
        Responses include `pagination.total`.
        """
        if user_type is not None and user_type not in ("internal", "external"):
            return _error("user_type must be 'internal' or 'external'.", "queryUserV2")

        uuids, pagination = self._base_search_with_meta(
            operation="queryUserV2",
            search_params={
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
                "user_type": user_type,
            },
            error_message="Failed to search users",
        )
        if self._is_error(uuids):
            return self._format_fql_error_response(
                [uuids], filter, SEARCH_USERS_FQL_DOCUMENTATION
            )
        if not uuids:
            return self._build_pagination_envelope([], pagination, filter)

        users = self._base_get_by_ids(operation="retrieveUsersGETV2", ids=uuids)
        if self._is_error(users):
            return [users]

        users = self._reorder_by_ids(uuids, users, id_field="uuid")
        return self._build_pagination_envelope(users, pagination, filter)

    async def get_user_roles(
        self,
        user_uuids: list[str] | None = Field(
            default=None,
            description=(
                f"User UUIDs to check, at most {MAX_ROLE_CHECK_USERS}. Omit to check every "
                f"user in the tenant (up to {MAX_ALL_USERS_SCAN}), for example to find who "
                "holds a role."
            ),
        ),
        role_ids: list[str] | None = Field(
            default=None,
            description=(
                "Only report these roles, e.g. ['falconhost_admin'] (Falcon "
                "Administrator) or ['remote_responder_three'] (RTR Administrator). "
                "Find role IDs with falcon_search_roles."
            ),
        ),
        direct_only: bool = Field(
            default=False,
            description="Only direct grants, leaving out grants inherited through Flight Control.",
        ),
    ) -> dict[str, Any]:
        """Get the roles each user holds, or find which users hold a given role.

        Returns `results`, one record per user with `uuid` and `grants` (each with
        `role_id`, `role_name`, `grant_type` and `expires_at` when temporary), and
        `not_found` for UUIDs that match no user. With `role_ids`, only those roles are
        reported and `holders` lists the users that hold any of them, which answers
        questions like "who is a Falcon Administrator?".
        """
        wanted: list[str] = []
        if role_ids:
            wanted, problem = _validate_role_ids(role_ids)
            if problem:
                return _error(problem, "CombinedUserRolesV3")

        truncated = False
        if user_uuids:
            uuids, problem = _validate_uuids(user_uuids, MAX_ROLE_CHECK_USERS)
            if problem:
                return _error(problem, "CombinedUserRolesV3")
        else:
            listing = await self.client.command_async(
                "queryUserV2", parameters={"limit": MAX_ALL_USERS_SCAN}
            )
            if listing.get("status_code") != 200:
                error: dict[str, Any] = handle_api_response(
                    listing, operation="queryUserV2", error_message="Failed to list users"
                )
                return error
            body = listing.get("body") or {}
            uuids = [u for u in body.get("resources") or [] if isinstance(u, str)]
            total = ((body.get("meta") or {}).get("pagination") or {}).get("total")
            truncated = isinstance(total, int) and total > len(uuids)

        limiter = asyncio.Semaphore(ROLE_CHECK_CONCURRENCY)

        async def grants_for(uuid: str) -> tuple[str, dict[str, Any]]:
            params: dict[str, Any] = {"user_uuid": uuid, "limit": 500}
            if direct_only:
                params["direct_only"] = True
            async with limiter:
                return uuid, await self.client.command_async(
                    "CombinedUserRolesV3", parameters=params
                )

        responses = await asyncio.gather(*(grants_for(u) for u in uuids))

        results: list[dict[str, Any]] = []
        not_found: list[str] = []
        for uuid, response in responses:
            status = response.get("status_code")
            body = response.get("body") or {}
            if status != 200:
                messages = " ".join(
                    str(e.get("message", "")) for e in body.get("errors") or [] if isinstance(e, dict)
                )
                if status == 400 and "invalid user uuid" in messages.lower():
                    not_found.append(uuid)
                    continue
                failure: dict[str, Any] = handle_api_response(
                    response,
                    operation="CombinedUserRolesV3",
                    error_message="Failed to get user roles",
                )
                return failure
            grants = [g for g in body.get("resources") or [] if isinstance(g, dict)]
            if wanted:
                grants = [g for g in grants if g.get("role_id") in wanted]
            results.append({"uuid": uuid, "grants": grants})

        envelope: dict[str, Any] = {"results": results, "not_found": not_found}
        if wanted:
            envelope["holders"] = [r["uuid"] for r in results if r["grants"]]
            # Checking every user for a role: users without it are noise
            if not user_uuids:
                envelope["results"] = [r for r in results if r["grants"]]
        if not user_uuids:
            envelope["users_checked"] = len(uuids)
            if truncated:
                envelope["warning"] = (
                    f"The tenant has more than {MAX_ALL_USERS_SCAN} users; only the first "
                    f"{MAX_ALL_USERS_SCAN} were checked. Pass user_uuids to check others."
                )
        return envelope

    def search_roles(
        self,
        name_contains: str | None = Field(
            default=None,
            description="Only roles whose ID or display name contains this text (case-insensitive).",
            examples=["administrator", "responder"],
        ),
        role_type: str | None = Field(
            default=None,
            description="'default' for CrowdStrike's built-in roles, 'custom' for the tenant's own.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """List the Falcon roles available in this tenant, with their IDs and descriptions.

        Built-in roles have readable IDs (falconhost_admin is Falcon Administrator,
        remote_responder_three is Real Time Responder - Administrator); custom roles
        have generated IDs. Returns `results` sorted by display name, each with `id`,
        `display_name`, `description`, `type` and `is_global`. Use the IDs with
        falcon_get_user_roles, falcon_get_role_permissions and falcon_manage_user_roles.
        """
        if role_type is not None and role_type not in ROLE_TYPES:
            return _error("role_type must be 'default' or 'custom'.", "queriesRolesV1")

        response = self.client.command("queriesRolesV1")
        role_ids = handle_api_response(
            response, operation="queriesRolesV1", error_message="Failed to list roles"
        )
        if self._is_error(role_ids):
            return [role_ids]
        if not role_ids:
            return {"results": [], "total": 0}

        roles = self._base_get_by_ids(operation="entitiesRolesGETV2", ids=role_ids)
        if self._is_error(roles):
            return [roles]

        needle = (name_contains or "").strip().lower()
        matched = [
            r
            for r in roles
            if (role_type is None or r.get("type") == role_type)
            and (
                not needle
                or needle in str(r.get("id", "")).lower()
                or needle in str(r.get("display_name", "")).lower()
            )
        ]
        matched.sort(key=lambda r: str(r.get("display_name", "")).lower())
        return {"results": matched, "total": len(matched)}

    def get_role_permissions(
        self,
        role_id: str = Field(
            description="The role ID, e.g. 'falconhost_admin'. Find IDs with falcon_search_roles.",
        ),
        contains: str | None = Field(
            default=None,
            description=(
                "Only permissions whose ID contains this text, e.g. 'rtr', 'user', "
                "'policy' (case-insensitive). Broad roles hold thousands of permissions."
            ),
        ),
        include_details: bool = Field(
            default=False,
            description=(
                "Add each permission's display name, description and permission group "
                f"(for at most {MAX_PERMISSION_DETAILS} matching permissions)."
            ),
        ),
    ) -> dict[str, Any]:
        """List what a role permits: the permission IDs it grants.

        Use this to see whether a role allows an action, for example whether a role can
        run RTR commands or manage users. Returns `role_id`, `total` (all permissions in
        the role), `matched` (after `contains`) and `permissions` (IDs, or full records
        with `include_details`), capped at 500 with `truncated` set when there are more.
        """
        cleaned, problem = _validate_role_ids([role_id])
        if problem:
            return _error(problem, "entitiesRolePermissionsV1")
        rid = cleaned[0]

        response = self.client.command("entitiesRolePermissionsV1", parameters={"id": rid})
        if response.get("status_code") != 200:
            error: dict[str, Any] = handle_api_response(
                response,
                operation="entitiesRolePermissionsV1",
                error_message=f"Failed to get permissions for role {rid!r}",
            )
            return error
        permission_ids = [
            p for p in (response.get("body") or {}).get("resources") or [] if isinstance(p, str)
        ]

        needle = (contains or "").strip().lower()
        matched = [p for p in permission_ids if needle in p.lower()] if needle else permission_ids
        shown = matched[:MAX_PERMISSIONS_RETURNED]

        permissions: list[Any] = shown
        if include_details and shown:
            details = self._base_get_by_ids(
                operation="entitiesPermissionsGETV1", ids=shown[:MAX_PERMISSION_DETAILS]
            )
            if isinstance(details, dict):
                return details
            permissions = details

        result: dict[str, Any] = {
            "role_id": rid,
            "total": len(permission_ids),
            "matched": len(matched),
            "permissions": permissions,
        }
        if len(matched) > len(shown):
            result["truncated"] = True
            result["hint"] = "Narrow the list with `contains`."
        return result

    # ------------------------------------------------------------------ #
    # Writes
    # ------------------------------------------------------------------ #

    def manage_user_roles(
        self,
        user_uuid: str = Field(
            description="The user's UUID. Find it with falcon_search_users.",
        ),
        action: str = Field(
            description="'grant' to give the roles, 'revoke' to take them away.",
        ),
        role_ids: list[str] = Field(
            description=(
                f"Role IDs to grant or revoke, at most {MAX_ROLE_IDS}, e.g. "
                "['falconhost_read_only']. Find them with falcon_search_roles."
            ),
        ),
        expires_at: str | None = Field(
            default=None,
            description=(
                "For a temporary grant: when it ends, as an ISO 8601 timestamp (UTC when "
                "it has no offset). Only used with 'grant'."
            ),
            examples=["2026-12-01T00:00:00Z"],
        ),
    ) -> dict[str, Any]:
        """Grant roles to a Falcon user or revoke them.

        Roles decide what a user can see and do in Falcon, so a grant can give
        administrator or RTR access and a revoke can lock a user out of their work.
        The roles are checked against the tenant's role list and the user against the
        user list before anything changes; the grant applies in the user's own CID.
        Re-granting a held role or revoking one the user lacks changes nothing. Verify
        afterwards with falcon_get_user_roles.
        """
        operation = "userRolesActionV2"
        if action not in ROLE_ACTIONS:
            return _error("action must be 'grant' or 'revoke'.", operation)
        uuids, problem = _validate_uuids([user_uuid], 1)
        if problem:
            return _error(problem, operation)
        roles, problem = _validate_role_ids(role_ids)
        if problem:
            return _error(problem, operation)

        expiry: str | None = None
        if expires_at:
            if action != "grant":
                return _error("expires_at applies only to 'grant'.", operation)
            try:
                moment = datetime.fromisoformat(expires_at.strip())
            except ValueError:
                return _error(f"Invalid expires_at {expires_at!r}. Use ISO 8601.", operation)
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=UTC)
            expiry = moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        # The grant names a CID: use the user's own, and refuse an unknown user
        users = self._base_get_by_ids(operation="retrieveUsersGETV2", ids=uuids)
        if isinstance(users, dict):
            return users
        user = next((u for u in users if str(u.get("uuid", "")).lower() == uuids[0]), None)
        if user is None or not user.get("cid"):
            return _error(f"No user with UUID {uuids[0]}.", operation)

        # Check against the tenant's role list: looking up an unknown role ID by ID
        # makes the API answer 500 rather than reporting it missing
        listing = handle_api_response(
            self.client.command("queriesRolesV1"),
            operation="queriesRolesV1",
            error_message="Failed to list roles",
        )
        if isinstance(listing, dict):
            return listing
        known_ids = set(listing)
        unknown = [r for r in roles if r not in known_ids]
        if unknown:
            return _error(
                f"Unknown role ID(s): {unknown}. Find role IDs with falcon_search_roles.",
                operation,
            )

        body: dict[str, Any] = {
            "action": action,
            "cid": user["cid"],
            "uuid": uuids[0],
            "role_ids": roles,
        }
        if expiry:
            body["expires_at"] = expiry

        logger.debug("%s %d role(s) for one user", action, len(roles))
        response = self.client.command(operation, body=body)
        if response.get("status_code") not in (200, 201, 202):
            error: dict[str, Any] = handle_api_response(
                response, operation=operation, error_message=f"Failed to {action} roles"
            )
            return error
        return {
            "action": action,
            "user_uuid": uuids[0],
            "role_ids": roles,
            "expires_at": expiry,
            "status_code": response.get("status_code"),
            "resources": (response.get("body") or {}).get("resources") or [],
        }

    def reset_user_credentials(
        self,
        user_uuids: list[str] = Field(
            description=(
                f"UUIDs of the users to reset, at most {MAX_CREDENTIAL_RESETS}. Find them "
                "with falcon_search_users."
            ),
        ),
        action: str = Field(
            description=(
                "'reset_2fa' to make the users enrol their two-factor device again, or "
                "'reset_password' to make them set a new password."
            ),
        ),
    ) -> dict[str, Any]:
        """Reset users' two-factor authentication or password.

        Use this when an account may be compromised or a user lost their 2FA device.
        The users must set up 2FA again or choose a new password before they can sign
        in; Falcon emails them. No credential passes through this tool.
        """
        operation = "userActionV1"
        if action not in CREDENTIAL_ACTIONS:
            return _error("action must be 'reset_2fa' or 'reset_password'.", operation)
        uuids, problem = _validate_uuids(user_uuids, MAX_CREDENTIAL_RESETS)
        if problem:
            return _error(problem, operation)

        response = self.client.command(
            operation, body={"action": {"action_name": action}, "ids": uuids}
        )
        if response.get("status_code") not in (200, 201, 202):
            error: dict[str, Any] = handle_api_response(
                response, operation=operation, error_message=f"Failed to {action}"
            )
            return error
        body = response.get("body") or {}
        result: dict[str, Any] = {
            "action": action,
            "user_uuids": uuids,
            "status_code": response.get("status_code"),
            "resources": body.get("resources") or [],
        }
        if body.get("errors"):
            result["errors"] = body["errors"]
        return result

    def create_user(
        self,
        email: str = Field(
            description="The new user's email address, which becomes their Falcon login (uid).",
        ),
        first_name: str | None = Field(default=None, description="First name."),
        last_name: str | None = Field(default=None, description="Last name."),
        validate_only: bool = Field(
            default=False,
            description="Check that the user could be created, without creating it.",
        ),
    ) -> dict[str, Any]:
        """Create a Falcon console user. The new user has no roles until granted some.

        Falcon emails the user an activation link to set their own password, or signs
        them in through single sign-on where that is enabled; this tool never sets a
        password. Returns the new user record with its `uuid`; grant roles next with
        falcon_manage_user_roles.
        """
        operation = "createUserV1"
        address = email.strip() if isinstance(email, str) else ""
        if not EMAIL_PATTERN.fullmatch(address):
            return _error(f"Invalid email address {email!r}.", operation)

        body: dict[str, Any] = {"uid": address}
        if first_name and first_name.strip():
            body["firstName"] = first_name.strip()
        if last_name and last_name.strip():
            body["lastName"] = last_name.strip()

        parameters = {"validate_only": True} if validate_only else None
        response = self.client.command(operation, parameters=parameters, body=body)
        if response.get("status_code") not in (200, 201):
            error: dict[str, Any] = handle_api_response(
                response, operation=operation, error_message="Failed to create user"
            )
            return error
        resources = (response.get("body") or {}).get("resources") or []
        return {
            "validate_only": validate_only,
            "created": not validate_only,
            "user": resources[0] if resources else None,
        }

    def update_user(
        self,
        user_uuid: str = Field(description="The user's UUID. Find it with falcon_search_users."),
        first_name: str = Field(description="The user's first name."),
        last_name: str = Field(description="The user's last name."),
    ) -> dict[str, Any]:
        """Change a Falcon user's first and last name. Both are required.

        The login email (uid), roles and status are not changed by this tool.
        """
        operation = "updateUserV1"
        uuids, problem = _validate_uuids([user_uuid], 1)
        if problem:
            return _error(problem, operation)
        first = first_name.strip() if isinstance(first_name, str) else ""
        last = last_name.strip() if isinstance(last_name, str) else ""
        if not first or not last:
            return _error("Both first_name and last_name are required.", operation)

        response = self.client.command(
            operation,
            parameters={"user_uuid": uuids[0]},
            body={"firstName": first, "lastName": last},
        )
        if response.get("status_code") != 200:
            error: dict[str, Any] = handle_api_response(
                response, operation=operation, error_message="Failed to update user"
            )
            return error
        resources = (response.get("body") or {}).get("resources") or []
        return {"updated": True, "user": resources[0] if resources else None}

    def delete_user(
        self,
        user_uuid: str = Field(description="The user's UUID. Find it with falcon_search_users."),
    ) -> dict[str, Any]:
        """Permanently delete a Falcon console user. This cannot be undone.

        The user loses all access at once. To cut access but keep the account, revoke
        their roles with falcon_manage_user_roles instead.
        """
        operation = "deleteUserV1"
        uuids, problem = _validate_uuids([user_uuid], 1)
        if problem:
            return _error(problem, operation)

        response = self.client.command(operation, parameters={"user_uuid": uuids[0]})
        if response.get("status_code") not in (200, 202, 204):
            error: dict[str, Any] = handle_api_response(
                response, operation=operation, error_message="Failed to delete user"
            )
            return error
        return {
            "deleted": True,
            "user_uuid": uuids[0],
            "status_code": response.get("status_code"),
        }
