"""
Identity Protection (IDP) module for Falcon MCP Server

This module provides tools for accessing CrowdStrike Falcon Identity Protection capabilities.
Core use cases:
1. Entity Lookup & Investigation
2. Identity Protection sensor and policy rule inventory
3. Highest-risk identity listing
"""

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from pydantic import AnyUrl, Field

from falcon_mcp.common.errors import _format_error_response
from falcon_mcp.common.logging import get_logger
from falcon_mcp.common.utils import sanitize_input, unwrap_field_default
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.idp import SEARCH_IDP_SENSORS_FQL_DOCUMENTATION

logger = get_logger(__name__)

# GraphQL enums are written unquoted, so they can't be escaped like strings.
GRAPHQL_ENUM_PATTERN = re.compile(r"[A-Z][A-Z0-9_]*")

# Allowlists for the unquoted enum values search_risky_identities writes into its query
RISKY_ENTITY_TYPES = ("USER", "ENDPOINT")
RISK_SEVERITIES = ("LOW", "MEDIUM", "HIGH")
MAX_RISKY_IDENTITIES = 200

# Entity fields read by search_risky_identities and correlate_host_identity
IDENTITY_RISK_FIELDS = """
                    entityId
                    primaryDisplayName
                    secondaryDisplayName
                    type
                    riskScore
                    riskScoreSeverity
                    riskFactors {
                        type
                        severity
                    }
                    accounts {
                        ... on ActiveDirectoryAccountDescriptor {
                            domain
                            samAccountName
                            enabled
                            passwordAttributes {
                                lastChange
                                strength
                            }
                        }
                    }
"""

# get_policy_rules takes at most 100 IDs per request
POLICY_RULE_BATCH_SIZE = 100

# A Falcon agent ID (AID) is 32 hex characters
DEVICE_ID_PATTERN = re.compile(r"[0-9a-fA-F]{32}")

# Account names written into a quoted FQL value. Quotes, backslashes, control
# characters and the `*` wildcard are all left out, so a name can neither close
# the string nor widen the match. AD logon names never contain those.
USER_NAME_PATTERN = re.compile(r"[\w.@$#&~^%!(){}\- ]+")
MAX_USER_NAME_LENGTH = 104

MAX_LOGIN_LOOKBACK_HOURS = 2160  # 90 days
MAX_ENDPOINT_HISTORY = 100

MAX_DETECTION_LOOKBACK_DAYS = 90
# How many recent Identity Protection detections are scanned for the user
IDP_DETECTION_SCAN_LIMIT = 200
# PostEntitiesAlertsV2 is fed at most this many composite IDs per request
ALERT_DETAILS_BATCH_SIZE = 100
OPEN_DETECTION_STATUSES = ("new", "reopened", "in_progress")

ENDPOINT_HISTORY_FIELDS = (
    "device_id",
    "hostname",
    "last_login_user",
    "last_login_timestamp",
    "platform_name",
    "os_product_name",
    "last_seen",
)
CORRELATED_HOST_FIELDS = (
    "device_id",
    "hostname",
    "machine_domain",
    "last_login_user",
    "last_login_timestamp",
    "platform_name",
)
IDP_DETECTION_FIELDS = (
    "composite_id",
    "severity",
    "severity_name",
    "display_name",
    "created_timestamp",
    "status",
    "tactic",
    "technique",
    "user_name",
    "source_account_name",
    "destination_account_name",
    "source_endpoint_host_name",
    "destination_endpoint_host_name",
)


def _account_key(name: Any) -> str:
    """Normalize an account name for comparison: drop any `DOMAIN\\` prefix, lowercase."""
    if not isinstance(name, str):
        return ""
    return name.rsplit("\\", 1)[-1].strip().lower()


def _utc_cutoff(**delta: int) -> str:
    """Return now minus `delta` as the UTC timestamp form FQL compares against."""
    return (datetime.now(timezone.utc) - timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_int_in_range(value: Any, low: int, high: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


class IdpModule(BaseModule):
    """Module for accessing and managing CrowdStrike Falcon Identity Protection."""

    def register_tools(self, server: FastMCP) -> None:
        """Register IDP tools with the MCP server.

        Args:
            server: MCP server instance
        """
        # Entity Investigation Tool
        self._add_tool(
            server=server,
            method=self.investigate_entity,
            name="idp_investigate_entity",
        )

        self._add_tool(
            server=server,
            method=self.search_idp_sensors,
            name="search_idp_sensors",
        )

        self._add_tool(
            server=server,
            method=self.search_idp_policy_rules,
            name="search_idp_policy_rules",
        )

        self._add_tool(
            server=server,
            method=self.search_risky_identities,
            name="search_risky_identities",
        )

        self._add_tool(
            server=server,
            method=self.get_user_endpoint_history,
            name="get_user_endpoint_history",
        )

        self._add_tool(
            server=server,
            method=self.correlate_host_identity,
            name="correlate_host_identity",
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register IDP resources with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_resource(
            server,
            TextResource(
                uri=AnyUrl("falcon://idp/sensors/fql-guide"),
                name="falcon_search_idp_sensors_fql_guide",
                description=(
                    "Contains the guide for the `filter` param of the "
                    "`falcon_search_idp_sensors` tool."
                ),
                text=SEARCH_IDP_SENSORS_FQL_DOCUMENTATION,
            ),
        )

    # ==========================================
    #  Sensor, Policy Rule, and Risk Inventory Tools
    # ==========================================

    def search_idp_sensors(
        self,
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter expression on Identity Protection sensor fields, "
                "such as hostname, status, or machine_domain. "
                "See `falcon://idp/sensors/fql-guide` for syntax."
            ),
            examples={"hostname:'DC01*'", "status:'Protected'"},
        ),
        limit: int = Field(
            default=50,
            ge=1,
            le=200,
            description="The maximum records to return. [1-200]",
        ),
        offset: int | None = Field(
            default=None,
            description="The offset to start retrieving records from.",
        ),
        sort: str | None = Field(
            default=None,
            description="Sort field and direction, e.g. 'hostname.asc' or 'status.desc'.",
            examples={"hostname.asc", "status.desc"},
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search Identity Protection sensors on domain controllers and other identity hosts.

        Use this to check Identity Protection coverage and health: which domain
        controllers run the identity sensor, their status and status causes, the
        assigned identity policy, and per-protocol enforcement settings (Kerberos,
        NTLM, LDAP, LDAPS, SMB, RDP). Returns full sensor details.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        filter = unwrap_field_default(filter)
        limit = unwrap_field_default(limit)
        offset = unwrap_field_default(offset)
        sort = unwrap_field_default(sort)

        sensor_ids, pagination = self._base_search_with_meta(
            operation="QuerySensorsByFilter",
            search_params={
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
            },
            error_message="Failed to search Identity Protection sensors",
        )

        if self._is_error(sensor_ids):
            return [sensor_ids]

        if not sensor_ids:
            return self._build_pagination_envelope([], pagination, filter)

        # GetSensorDetails reads by POST, with the IDs in the body
        details = self._base_get_by_ids(
            operation="GetSensorDetails",
            ids=sensor_ids,
        )

        if self._is_error(details):
            return [details]

        details = self._reorder_by_ids(sensor_ids, details, id_field="device_id")
        return self._build_pagination_envelope(details, pagination, filter)

    def search_idp_policy_rules(
        self,
        enabled: bool | None = Field(
            default=None,
            description="Return only enabled (true) or only disabled (false) rules. Omit for both.",
        ),
        simulation_mode: bool | None = Field(
            default=None,
            description=(
                "Return only rules in simulation mode (true) or only enforced rules "
                "(false). Omit for both."
            ),
        ),
        name: str | None = Field(
            default=None,
            description="Return only the rule with this exact name.",
        ),
        limit: int = Field(
            default=100,
            ge=1,
            le=1000,
            description="The maximum rules to return details for. [1-1000]",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search Identity Protection policy rules.

        Use this to review which identity policies are in place, such as rules that
        block, require MFA for, or allow authentication traffic, and whether each is
        enabled or running in simulation mode. Returns full rule details including
        conditions and actions.
        Responses include `pagination.total` (the total number of matching rules) — use it to answer "how many" questions.
        When it exceeds the number of results, raise `limit` to get the rest.
        """
        enabled = unwrap_field_default(enabled)
        simulation_mode = unwrap_field_default(simulation_mode)
        name = unwrap_field_default(name)
        limit = unwrap_field_default(limit)

        rule_ids, pagination = self._base_search_with_meta(
            operation="get_policy_rules_query",
            search_params={
                "enabled": enabled,
                "simulation_mode": simulation_mode,
                "name": name,
            },
            error_message="Failed to search Identity Protection policy rules",
        )

        if not isinstance(rule_ids, list):
            return [rule_ids]

        # The query takes no limit or offset and returns every matching ID, so
        # when it reports no count the ID list itself is the real total.
        if not pagination or pagination.get("total") is None:
            pagination = {**(pagination or {}), "total": len(rule_ids or [])}

        if not rule_ids:
            return self._build_pagination_envelope([], pagination)

        selected = rule_ids[:limit]
        rules: list[dict[str, Any]] = []
        for start in range(0, len(selected), POLICY_RULE_BATCH_SIZE):
            batch = selected[start : start + POLICY_RULE_BATCH_SIZE]
            details = self._base_get_by_ids(
                operation="get_policy_rules",
                ids=batch,
                use_params=True,
            )
            if self._is_error(details):
                return [details]
            rules.extend(details)

        return self._build_pagination_envelope(rules, pagination)

    def search_risky_identities(
        self,
        limit: int = Field(
            default=25,
            ge=1,
            le=MAX_RISKY_IDENTITIES,
            description=f"The maximum identities to return. [1-{MAX_RISKY_IDENTITIES}]",
        ),
        entity_type: str = Field(
            default="USER",
            description="Entity type to rank. Values: 'USER' or 'ENDPOINT'.",
        ),
        min_risk_severity: str | None = Field(
            default=None,
            description=(
                "Return only entities at or above this risk severity. "
                "Values: 'LOW', 'MEDIUM', or 'HIGH'. Omit for all."
            ),
        ),
        domain_names: list[str] | None = Field(
            default=None,
            description="Return only entities in these domains (e.g., ['CORP.LOCAL']).",
        ),
        after: str | None = Field(
            default=None,
            description="Pagination cursor. Pass `pagination.next` from a previous response to get the next page.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """List the highest-risk identities from Identity Protection.

        Use this to answer "who are my riskiest users" questions. Returns active
        entities sorted by risk score, highest first, each with its risk score,
        severity, risk factors (such as stale account, exposed password, or
        privileged), and Active Directory account details. To dig into one identity,
        pass its entityId to `falcon_idp_investigate_entity`.
        Responses include `pagination.next` when more results are available.
        """
        limit = unwrap_field_default(limit)
        entity_type = unwrap_field_default(entity_type)
        min_risk_severity = unwrap_field_default(min_risk_severity)
        domain_names = unwrap_field_default(domain_names)
        after = unwrap_field_default(after)

        operation = "api_preempt_proxy_post_graphql"

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not (1 <= limit <= MAX_RISKY_IDENTITIES)
        ):
            return [
                _format_error_response(
                    f"limit must be an integer from 1 to {MAX_RISKY_IDENTITIES}.",
                    operation=operation,
                )
            ]

        normalized_type = str(entity_type).upper()
        if normalized_type not in RISKY_ENTITY_TYPES:
            return [
                _format_error_response(
                    f"Invalid entity_type {entity_type!r}. Must be one of {list(RISKY_ENTITY_TYPES)}.",
                    operation=operation,
                )
            ]

        normalized_severity = None
        if min_risk_severity is not None:
            normalized_severity = str(min_risk_severity).upper()
            if normalized_severity not in RISK_SEVERITIES:
                return [
                    _format_error_response(
                        f"Invalid min_risk_severity {min_risk_severity!r}. "
                        f"Must be one of {list(RISK_SEVERITIES)}.",
                        operation=operation,
                    )
                ]

        query = self._build_risky_identities_query(
            limit=limit,
            entity_type=normalized_type,
            min_risk_severity=normalized_severity,
            domain_names=domain_names,
            after=after,
        )

        result = self._base_query_api_call(
            operation=operation,
            body_params={"query": query},
            error_message="Failed to list risky identities",
            default_result=None,
        )
        if self._is_error(result):
            return [result]

        # GraphQL reports query errors in a 200 body rather than with a status code
        if isinstance(result, dict) and result.get("errors"):
            messages = [
                error.get("message")
                for error in result["errors"]
                if isinstance(error, dict) and error.get("message")
            ]
            detail = f": {'; '.join(messages)}" if messages else ""
            return [
                _format_error_response(
                    f"Failed to list risky identities{detail}",
                    details=result,
                    operation=operation,
                )
            ]

        data = (result.get("data") or {}) if isinstance(result, dict) else {}
        entities = data.get("entities") or {}
        nodes = entities.get("nodes") or []
        page_info = entities.get("pageInfo") or {}
        next_cursor = page_info.get("endCursor") if page_info.get("hasNextPage") else None

        return self._build_pagination_envelope(nodes, {"next": next_cursor})

    def _build_risky_identities_query(
        self,
        limit: int,
        entity_type: str,
        min_risk_severity: str | None,
        domain_names: list[str] | None,
        after: str | None,
    ) -> str:
        """Build the GraphQL query that ranks entities by risk score.

        Enum values are written unquoted, so they must come from the allowlists.
        Strings go through `json.dumps`, and `limit` must be a real integer.
        """
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError("limit must be an integer")
        if entity_type not in RISKY_ENTITY_TYPES:
            raise ValueError(f"Unsupported entity_type: {entity_type!r}")
        if min_risk_severity is not None and min_risk_severity not in RISK_SEVERITIES:
            raise ValueError(f"Unsupported min_risk_severity: {min_risk_severity!r}")

        arguments = [
            f"first: {limit}",
            "sortKey: RISK_SCORE",
            "sortOrder: DESCENDING",
            f"types: [{entity_type}]",
            "archived: false",
        ]
        if min_risk_severity:
            arguments.append(f"minRiskScoreSeverity: {min_risk_severity}")
        if domain_names:
            query_fields: list[str] = []
            self._add_domain_filter({"domain_names": domain_names}, query_fields, arguments)
        if after:
            arguments.append(f"after: {json.dumps(str(after))}")

        arguments_string = ", ".join(arguments)

        return f"""
        query {{
            entities({arguments_string}) {{
                nodes {{
                    {IDENTITY_RISK_FIELDS}
                }}
                pageInfo {{
                    hasNextPage
                    endCursor
                }}
            }}
        }}
        """

    # ==========================================
    #  Endpoint and Identity Correlation Tools
    # ==========================================

    def get_user_endpoint_history(
        self,
        user_name: str = Field(
            description=(
                "The account name to look up, as Falcon records it in a host's "
                "`last_login_user` (usually the AD sAMAccountName, e.g. 'jdoe'). "
                "Leave off any 'DOMAIN\\' prefix. Matched case-insensitively."
            ),
            examples={"jdoe", "svc_backup"},
        ),
        hours: int = Field(
            default=168,
            ge=1,
            le=MAX_LOGIN_LOOKBACK_HOURS,
            description=(
                "Only include hosts whose last login was within this many hours. "
                f"Default 168 (7 days). [1-{MAX_LOGIN_LOOKBACK_HOURS}]"
            ),
        ),
        limit: int = Field(
            default=25,
            ge=1,
            le=MAX_ENDPOINT_HISTORY,
            description=f"The maximum hosts to return. [1-{MAX_ENDPOINT_HISTORY}]",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """List the endpoints a user has recently logged into.

        Use this to scope a possibly compromised account: it returns the hosts
        whose most recent logged-in user is this account, within the lookback
        window, newest login first. Each host has device_id, hostname,
        last_login_user, last_login_timestamp, platform_name, os_product_name and
        last_seen. Only the latest login per host is known, so a host where
        someone else has logged in since will not appear. Pass a device_id to
        `falcon_correlate_host_identity` for the identity side of one host.
        Responses include `pagination.total`, the number of matching hosts.
        """
        user_name = unwrap_field_default(user_name)
        hours = unwrap_field_default(hours)
        limit = unwrap_field_default(limit)

        operation = "QueryDevicesByFilter"

        account, error = self._validate_user_name(user_name)
        if error:
            return [_format_error_response(error, operation=operation)]
        if not _is_int_in_range(hours, 1, MAX_LOGIN_LOOKBACK_HOURS):
            return [
                _format_error_response(
                    f"hours must be an integer from 1 to {MAX_LOGIN_LOOKBACK_HOURS}.",
                    operation=operation,
                )
            ]
        if not _is_int_in_range(limit, 1, MAX_ENDPOINT_HISTORY):
            return [
                _format_error_response(
                    f"limit must be an integer from 1 to {MAX_ENDPOINT_HISTORY}.",
                    operation=operation,
                )
            ]

        # `account` passed USER_NAME_PATTERN, so it can't leave the quoted value
        fql = f"last_login_user:'{account}'+last_login_timestamp:>'{_utc_cutoff(hours=hours)}'"

        device_ids, pagination = self._base_search_with_meta(
            operation=operation,
            search_params={
                "filter": fql,
                "limit": limit,
                "sort": "last_login_timestamp.desc",
            },
            error_message="Failed to search hosts by last logged-in user",
        )
        if self._is_error(device_ids):
            return [device_ids]
        if not device_ids:
            return self._build_pagination_envelope([], pagination, fql)

        details = self._base_get_by_ids(operation="PostDeviceDetailsV2", ids=device_ids)
        if self._is_error(details):
            return [details]

        hosts = [
            {field: host.get(field) for field in ENDPOINT_HISTORY_FIELDS}
            for host in details
            if isinstance(host, dict)
        ]
        # The details call doesn't keep the query's order, so rank again here
        hosts.sort(key=lambda host: str(host.get("last_login_timestamp") or ""), reverse=True)

        return self._build_pagination_envelope(hosts, pagination, fql)

    def correlate_host_identity(
        self,
        device_id: str = Field(
            description="The host's device ID (AID): 32 hexadecimal characters.",
        ),
        detection_lookback_days: int = Field(
            default=14,
            ge=1,
            le=MAX_DETECTION_LOOKBACK_DAYS,
            description=(
                "How far back to look for Identity Protection detections naming "
                f"the user. Default 14. [1-{MAX_DETECTION_LOOKBACK_DAYS}]"
            ),
        ),
        include_policy_matches: bool = Field(
            default=False,
            description=(
                "Include 'Policy rule match' enforcement events, which carry no "
                "tactic. Off by default because they crowd out attack detections."
            ),
        ),
        include_closed: bool = Field(
            default=False,
            description="Include closed detections. By default only new, reopened and in-progress ones.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Correlate a host with the identity last logged into it.

        Use this to bridge an endpoint investigation to Identity Protection.
        Returns `host` (device_id, hostname, machine_domain, last_login_user,
        last_login_timestamp, platform_name); `identity`, the Identity Protection
        entity for that user with its risk score, severity, risk factors and AD
        accounts, or null when none matches; and `idp_detections`, recent
        Identity Protection detections whose user, source account or destination
        account is that user. When the host's domain matches one of several
        same-named accounts, that account wins (`identity_match` is 'domain').
        If the identity or detection lookup fails, its error is reported in
        `identity_error` or `idp_detections_error` and the rest is still returned.
        Pass `identity.entityId` to `falcon_idp_investigate_entity` to dig deeper.
        """
        device_id = unwrap_field_default(device_id)
        detection_lookback_days = unwrap_field_default(detection_lookback_days)
        include_policy_matches = unwrap_field_default(include_policy_matches)
        include_closed = unwrap_field_default(include_closed)

        candidate = device_id.strip() if isinstance(device_id, str) else ""
        if not DEVICE_ID_PATTERN.fullmatch(candidate):
            return [
                _format_error_response(
                    f"Invalid device_id {device_id!r}. A host device ID (AID) is 32 "
                    "hexadecimal characters. Find AIDs with falcon_search_hosts.",
                    operation="PostDeviceDetailsV2",
                )
            ]
        if not _is_int_in_range(detection_lookback_days, 1, MAX_DETECTION_LOOKBACK_DAYS):
            return [
                _format_error_response(
                    "detection_lookback_days must be an integer from 1 to "
                    f"{MAX_DETECTION_LOOKBACK_DAYS}.",
                    operation="GetQueriesAlertsV2",
                )
            ]

        devices = self._base_get_by_ids(operation="PostDeviceDetailsV2", ids=[candidate.lower()])
        if self._is_error(devices):
            return [devices]
        device = next((d for d in devices if isinstance(d, dict)), None)
        if device is None:
            return [
                _format_error_response(
                    f"No host found with device ID {candidate!r}.",
                    operation="PostDeviceDetailsV2",
                )
            ]

        host = {field: device.get(field) for field in CORRELATED_HOST_FIELDS}
        response: dict[str, Any] = {
            "host": host,
            "identity": None,
            "identity_match": "none",
            "idp_detections": [],
        }

        account = _account_key(host.get("last_login_user"))
        if not account:
            response["note"] = (
                "The host has no last_login_user, so there is no identity to correlate."
            )
            return response

        identity, match, identity_error = self._find_identity_for_account(
            account, host.get("machine_domain")
        )
        response["identity"] = identity
        response["identity_match"] = match
        if identity_error:
            response["identity_error"] = identity_error

        detections, scan, detections_error = self._find_idp_detections_for_account(
            account,
            lookback_days=detection_lookback_days,
            include_policy_matches=bool(include_policy_matches),
            include_closed=bool(include_closed),
        )
        response["idp_detections"] = detections
        response["idp_detections_scan"] = scan
        if detections_error:
            response["idp_detections_error"] = detections_error

        return response

    @staticmethod
    def _validate_user_name(user_name: Any) -> tuple[str, str | None]:
        """Check an account name before it is written into an FQL string.

        Returns the lowercased name, or an error message. Nothing is escaped:
        a name with a character outside USER_NAME_PATTERN is refused outright.
        """
        # Only spaces are trimmed, so a stray control character is refused, not dropped
        name = user_name.strip(" ") if isinstance(user_name, str) else ""
        if not name:
            return "", "user_name is required."
        if "\\" in name:
            return "", (
                "user_name must not contain a backslash. Pass the account name "
                "without its 'DOMAIN\\' prefix, e.g. 'jdoe'."
            )
        if len(name) > MAX_USER_NAME_LENGTH:
            return "", f"user_name must be at most {MAX_USER_NAME_LENGTH} characters."
        if not USER_NAME_PATTERN.fullmatch(name):
            return "", (
                f"Invalid user_name {user_name!r}. Use the account name only: letters, "
                "digits, spaces and . _ - @ $ # & ~ ^ % ! ( ) { }. Quotes, backslashes, "
                "control characters and '*' wildcards are not allowed."
            )
        return name.lower(), None

    def _build_account_identity_query(self, account_name: str) -> str:
        """Build the GraphQL query that finds user entities by sAMAccountName.

        The name goes through `json.dumps`, so it stays a GraphQL string.
        """
        if not isinstance(account_name, str) or not account_name:
            raise ValueError("account_name must be a non-empty string")

        return f"""
        query {{
            entities(samAccountNames: {json.dumps([account_name])}, types: [USER], archived: false, first: 25) {{
                nodes {{
                    {IDENTITY_RISK_FIELDS}
                }}
            }}
        }}
        """

    def _find_identity_for_account(
        self, account: str, machine_domain: Any
    ) -> tuple[dict[str, Any] | None, str, dict[str, Any] | None]:
        """Look up the Identity Protection user entity behind an account name.

        One sAMAccountName can exist in several trusted domains, so the account
        whose domain matches the host's domain is preferred.

        Returns (entity or None, match method, error or None).
        """
        operation = "api_preempt_proxy_post_graphql"
        result = self._base_query_api_call(
            operation=operation,
            body_params={"query": self._build_account_identity_query(account)},
            error_message="Failed to look up the identity for the host's user",
            default_result=None,
        )
        if self._is_error(result):
            return None, "none", result  # type: ignore[return-value]
        if not isinstance(result, dict):
            return None, "none", None

        # GraphQL reports query errors in a 200 body rather than with a status code
        if result.get("errors"):
            messages = [
                error.get("message")
                for error in result["errors"]
                if isinstance(error, dict) and error.get("message")
            ]
            detail = f": {'; '.join(messages)}" if messages else ""
            return (
                None,
                "none",
                _format_error_response(
                    f"Failed to look up the identity for the host's user{detail}",
                    details=result,
                    operation=operation,
                ),
            )

        nodes = ((result.get("data") or {}).get("entities") or {}).get("nodes") or []
        domain = machine_domain.strip().lower() if isinstance(machine_domain, str) else ""
        first_match: dict[str, Any] | None = None
        for node in nodes:
            if not isinstance(node, dict):
                continue
            for entry in node.get("accounts") or []:
                if not isinstance(entry, dict):
                    continue
                if _account_key(entry.get("samAccountName")) != account:
                    continue
                if domain and str(entry.get("domain") or "").lower() == domain:
                    return node, "domain", None
                if first_match is None:
                    first_match = node
        if first_match is not None:
            return first_match, "account_name", None
        return None, "none", None

    def _find_idp_detections_for_account(
        self,
        account: str,
        lookback_days: int,
        include_policy_matches: bool,
        include_closed: bool,
    ) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any] | None]:
        """Find recent Identity Protection detections that name an account.

        FQL can't OR one value across the three account fields, so the newest
        detections are fetched and matched here. The account never enters FQL.

        Returns (detections, scan summary, error or None).
        """
        fql = f"product:'idp'+created_timestamp:>'{_utc_cutoff(days=lookback_days)}'"
        if not include_closed:
            statuses = ",".join(f"'{status}'" for status in OPEN_DETECTION_STATUSES)
            fql += f"+status:[{statuses}]"

        scan: dict[str, Any] = {"filter_used": fql, "scanned": 0, "total": None}

        composite_ids, pagination = self._base_search_with_meta(
            operation="GetQueriesAlertsV2",
            search_params={
                "filter": fql,
                "limit": IDP_DETECTION_SCAN_LIMIT,
                "sort": "created_timestamp.desc",
            },
            error_message="Failed to search Identity Protection detections",
        )
        if not isinstance(composite_ids, list):
            return [], scan, composite_ids
        scan["total"] = (pagination or {}).get("total")
        if not composite_ids:
            return [], scan, None

        alerts: list[dict[str, Any]] = []
        for start in range(0, len(composite_ids), ALERT_DETAILS_BATCH_SIZE):
            details = self._base_get_by_ids(
                operation="PostEntitiesAlertsV2",
                ids=composite_ids[start : start + ALERT_DETAILS_BATCH_SIZE],
                id_key="composite_ids",
            )
            if self._is_error(details):
                return [], scan, details  # type: ignore[return-value]
            alerts.extend(alert for alert in details if isinstance(alert, dict))
        scan["scanned"] = len(alerts)

        matches: list[dict[str, Any]] = []
        for alert in alerts:
            # Policy rule matches are enforcement events and carry no tactic
            if not include_policy_matches and not alert.get("tactic"):
                continue
            named = {
                _account_key(alert.get(field))
                for field in ("user_name", "source_account_name", "destination_account_name")
            }
            if account in named:
                matches.append({field: alert.get(field) for field in IDP_DETECTION_FIELDS})

        matches.sort(key=lambda alert: str(alert.get("created_timestamp") or ""), reverse=True)
        return matches, scan, None

    # ==========================================
    #  Entity Investigation Tool
    # ==========================================

    def investigate_entity(
        self,
        # Entity Identification (Required - at least one)
        entity_ids: list[str] | None = Field(
            default=None,
            description="List of specific entity IDs to investigate (e.g., ['entity-001'])",
        ),
        entity_names: str | None = Field(
            default=None,
            description=(
                "Entity display name pattern to search for "
                "(e.g., 'John Doe' or 'Doe, John' or 'Administrator' or 'Admin*'). Supports '*' wildcards. "
                "When combined with other parameters, uses AND logic."
            ),
        ),
        email_addresses: str | None = Field(
            default=None,
            description=(
                "UPN, email address, or Azure external identity pattern to search for "
                "(e.g., 'user@example.com', '*@example.com', "
                "or 'john.doe_contoso.com#EXT#@tenant.onmicrosoft.com'). Supports '*' wildcards. "
                "For AD samAccountName lookups, use domain_names + entity_names together instead. "
                "When combined with other parameters, uses AND logic."
            ),
        ),
        ip_addresses: list[str] | None = Field(
            default=None,
            description="List of IP addresses/endpoints to investigate (e.g., ['1.1.1.1']). When combined with other parameters, uses AND logic.",
        ),
        domain_names: list[str] | None = Field(
            default=None,
            description="List of domain names to search for (e.g., ['XDRHOLDINGS.COM', 'CORP.LOCAL']). When combined with other parameters, uses AND logic. Example: entity_names='Administrator' + domain_names=['DOMAIN.COM'] finds Administrator user in that specific domain.",
        ),
        # Investigation Scope Control
        investigation_types: list[str] = Field(
            default=["entity_details"],
            description="Types of investigation to perform: 'entity_details', 'timeline_analysis', 'relationship_analysis', 'risk_assessment'. Use multiple for comprehensive analysis.",
        ),
        # Timeline Parameters (when timeline_analysis is included)
        timeline_start_time: str | None = Field(
            default=None,
            description="Start time for timeline analysis in ISO format (e.g., '2024-01-01T00:00:00Z')",
        ),
        timeline_end_time: str | None = Field(
            default=None,
            description="End time for timeline analysis in ISO format",
        ),
        timeline_event_types: list[str] | None = Field(
            default=None,
            description="Filter timeline by event types: 'ACTIVITY', 'NOTIFICATION', 'THREAT', 'ENTITY', 'AUDIT', 'POLICY', 'SYSTEM'",
        ),
        # Relationship Parameters (when relationship_analysis is included)
        relationship_depth: int = Field(
            default=2,
            ge=1,
            le=3,
            description="Depth of relationship analysis (1-3 levels)",
        ),
        # General Parameters
        limit: int = Field(
            default=10,
            ge=1,
            le=200,
            description="Maximum number of results to return",
        ),
        include_associations: bool = Field(
            default=True,
            description="Include entity associations and relationships in results",
        ),
        include_accounts: bool = Field(
            default=True,
            description="Include account information in results",
        ),
        include_incidents: bool = Field(
            default=True,
            description="Include open security incidents in results",
        ),
    ) -> dict[str, Any]:
        """Investigate one or more Identity Protection entities by ID, name, email, IP, or domain.

        Use this to look up entity details, activity timelines, relationship graphs, and risk
        assessments; at least one identifier must be supplied, and multiple identifiers are
        combined with AND logic (email and IP cannot be combined — email takes precedence).
        Returns a structured response with an investigation_summary, resolved entity IDs,
        and results keyed by each requested investigation type.
        """
        logger.debug("Starting comprehensive entity investigation")

        # Resolve unset Pydantic Field defaults to avoid leaking FieldInfo objects (issue #384)
        entity_ids = unwrap_field_default(entity_ids)
        entity_names = unwrap_field_default(entity_names)
        email_addresses = unwrap_field_default(email_addresses)
        ip_addresses = unwrap_field_default(ip_addresses)
        domain_names = unwrap_field_default(domain_names)
        investigation_types = unwrap_field_default(investigation_types)
        timeline_start_time = unwrap_field_default(timeline_start_time)
        timeline_end_time = unwrap_field_default(timeline_end_time)
        timeline_event_types = unwrap_field_default(timeline_event_types)
        relationship_depth = unwrap_field_default(relationship_depth)
        limit = unwrap_field_default(limit)
        include_associations = unwrap_field_default(include_associations)
        include_accounts = unwrap_field_default(include_accounts)
        include_incidents = unwrap_field_default(include_incidents)

        # Step 1: Validate inputs
        validation_error = self._validate_entity_identifiers(
            entity_ids,
            entity_names,
            email_addresses,
            ip_addresses,
            domain_names,
            investigation_types,
            timeline_event_types,
        )
        if validation_error:
            return validation_error

        # Step 2: Entity Resolution - Find entities from various identifiers
        logger.debug("Resolving entities from provided identifiers")
        search_criteria = {
            "entity_ids": entity_ids,
            "entity_names": entity_names,
            "email_addresses": email_addresses,
            "ip_addresses": ip_addresses,
            "domain_names": domain_names,
        }

        resolved_entity_ids = self._resolve_entities(
            {
                "entity_ids": entity_ids if entity_ids is not None else None,
                "entity_names": entity_names if entity_names is not None else None,
                "email_addresses": email_addresses if email_addresses is not None else None,
                "ip_addresses": ip_addresses if ip_addresses is not None else None,
                "domain_names": domain_names if domain_names is not None else None,
                "limit": limit,
            }
        )

        # Check if entity resolution failed
        if isinstance(resolved_entity_ids, dict) and "error" in resolved_entity_ids:
            return self._create_error_response(
                resolved_entity_ids["error"],
                0,
                investigation_types,
                search_criteria,
            )

        if not resolved_entity_ids:
            return self._create_error_response(
                "No entities found matching the provided criteria",
                0,
                investigation_types,
                search_criteria,
            )

        logger.debug(f"Resolved {len(resolved_entity_ids)} entities for investigation")

        # Step 3: Execute investigations based on requested types
        investigation_results = {}
        investigation_params = {
            "include_associations": include_associations,
            "include_accounts": include_accounts,
            "include_incidents": include_incidents,
            "timeline_start_time": timeline_start_time,
            "timeline_end_time": timeline_end_time,
            "timeline_event_types": timeline_event_types,
            "relationship_depth": relationship_depth,
            "limit": limit,
        }

        for investigation_type in investigation_types:
            result = self._execute_single_investigation(
                investigation_type, resolved_entity_ids, investigation_params
            )
            if "error" in result:
                logger.error(f"Error in {investigation_type} investigation: {result['error']}")
                return self._create_error_response(
                    f"Investigation failed during {investigation_type}: {result['error']}",
                    len(resolved_entity_ids),
                    investigation_types,
                )
            investigation_results[investigation_type] = result

        # Step 4: Synthesize comprehensive response
        return self._synthesize_investigation_response(
            resolved_entity_ids,
            investigation_results,
            {
                "investigation_types": investigation_types,
                "search_criteria": search_criteria,
            },
        )

    # ==========================================
    # Investigation Helper Methods
    # ==========================================

    def _validate_entity_identifiers(
        self,
        entity_ids,
        entity_names,
        email_addresses,
        ip_addresses,
        domain_names,
        investigation_types,
        timeline_event_types=None,
    ):
        """Validate entity identifiers and the unquoted enum values used in queries."""
        if not any(
            [
                entity_ids,
                entity_names,
                email_addresses,
                ip_addresses,
                domain_names,
            ]
        ):
            return {
                "error": "At least one entity identifier must be provided (entity_ids, entity_names, email_addresses, ip_addresses, or domain_names)",
                "investigation_summary": {
                    "entity_count": 0,
                    "investigation_types": investigation_types,
                    "timestamp": datetime.utcnow().isoformat(),
                    "status": "failed",
                },
            }

        if (entity_names and isinstance(entity_names, str) and entity_names.strip("* ") == "") or (
            email_addresses
            and isinstance(email_addresses, str)
            and email_addresses.strip("* ") == ""
        ):
            return {
                "error": (
                    "entity_names/email_addresses cannot be a bare wildcard ('*'). "
                    "Provide a more specific pattern (e.g., 'Admin*') or narrow the search."
                ),
                "investigation_summary": {
                    "entity_count": 0,
                    "investigation_types": investigation_types,
                    "timestamp": datetime.utcnow().isoformat(),
                    "status": "failed",
                },
            }

        invalid_event_types = [
            event_type
            for event_type in timeline_event_types or []
            if not GRAPHQL_ENUM_PATTERN.fullmatch(str(event_type))
        ]
        if invalid_event_types:
            return self._create_error_response(
                f"Invalid timeline_event_types: {invalid_event_types}. "
                "Use values like 'ACTIVITY' or 'THREAT'.",
                0,
                investigation_types,
            )

        return None

    def _create_error_response(
        self,
        error_message,
        entity_count,
        investigation_types,
        search_criteria=None,
    ):
        """Create a standardized error response."""
        response = {
            "error": error_message,
            "investigation_summary": {
                "entity_count": entity_count,
                "investigation_types": investigation_types,
                "timestamp": datetime.utcnow().isoformat(),
                "status": "failed",
            },
        }
        if search_criteria:
            response["search_criteria"] = search_criteria
        return response

    def _execute_single_investigation(
        self,
        investigation_type,
        resolved_entity_ids,
        params,
    ):
        """Execute a single investigation type and return results or error."""
        logger.debug(f"Executing {investigation_type} investigation")

        if investigation_type == "entity_details":
            return self._get_entity_details_batch(
                resolved_entity_ids,
                {
                    "include_associations": params.get("include_associations", True),
                    "include_accounts": params.get("include_accounts", True),
                    "include_incidents": params.get("include_incidents", True),
                },
            )
        if investigation_type == "timeline_analysis":
            return self._get_entity_timelines_batch(
                resolved_entity_ids,
                {
                    "start_time": params.get("timeline_start_time"),
                    "end_time": params.get("timeline_end_time"),
                    "event_types": params.get("timeline_event_types"),
                    "limit": params.get("limit", 50),
                },
            )
        if investigation_type == "relationship_analysis":
            return self._analyze_relationships_batch(
                resolved_entity_ids,
                {
                    "relationship_depth": params.get("relationship_depth", 2),
                    "include_risk_context": True,
                    "limit": params.get("limit", 50),
                },
            )
        if investigation_type == "risk_assessment":
            return self._assess_risks_batch(
                resolved_entity_ids,
                {"include_risk_factors": True},
            )

        logger.warning(f"Unknown investigation type: {investigation_type}")
        return {"error": f"Unknown investigation type: {investigation_type}"}

    # ==========================================
    # GraphQL Query Building Helper Methods
    # ==========================================

    def _build_entity_details_query(
        self,
        entity_ids: list[str],
        include_risk_factors: bool,
        include_associations: bool,
        include_incidents: bool,
        include_accounts: bool,
    ) -> str:
        """Build GraphQL query for detailed entity information."""
        entity_ids_json = json.dumps(entity_ids)

        # Start with minimal safe fields
        fields = [
            "entityId",
            "primaryDisplayName",
            "secondaryDisplayName",
            "type",
            "riskScore",
            "riskScoreSeverity",
        ]

        if include_risk_factors:
            fields.append("""
                riskFactors {
                    type
                    severity
                }
            """)

        if include_associations:
            fields.append("""
                associations {
                    bindingType
                    ... on EntityAssociation {
                        entity {
                            entityId
                            primaryDisplayName
                            secondaryDisplayName
                            type
                        }
                    }
                    ... on LocalAdminLocalUserAssociation {
                        accountName
                    }
                    ... on LocalAdminDomainEntityAssociation {
                        entityType
                        entity {
                            entityId
                            primaryDisplayName
                            secondaryDisplayName
                        }
                    }
                    ... on GeoLocationAssociation {
                        geoLocation {
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }
                    }
                }
            """)

        if include_incidents:
            fields.append("""
                openIncidents(first: 10) {
                    nodes {
                        type
                        startTime
                        endTime
                        compromisedEntities {
                            entityId
                            primaryDisplayName
                        }
                    }
                }
            """)

        if include_accounts:
            fields.append("""
                accounts {
                    ... on ActiveDirectoryAccountDescriptor {
                        domain
                        samAccountName
                        ou
                        servicePrincipalNames
                        passwordAttributes {
                            lastChange
                            strength
                        }
                        expirationTime
                    }
                    ... on SsoUserAccountDescriptor {
                        dataSource
                        mostRecentActivity
                        title
                        creationTime
                        passwordAttributes {
                            lastChange
                        }
                    }
                    ... on AzureCloudServiceAdapterDescriptor {
                        registeredTenantType
                        appOwnerOrganizationId
                        publisherDomain
                        signInAudience
                    }
                    ... on CloudServiceAdapterDescriptor {
                        dataSourceParticipantIdentifier
                    }
                }
            """)

        fields_string = "\n".join(fields)

        return f"""
        query {{
            entities(entityIds: {entity_ids_json}, first: 50) {{
                nodes {{
                    {fields_string}
                }}
            }}
        }}
        """

    def _build_timeline_query(
        self,
        entity_id: str,
        start_time: str | None,
        end_time: str | None,
        event_types: list[str] | None,
        limit: int,
    ) -> str:
        """Build GraphQL query for entity timeline."""
        filters = [f"sourceEntityQuery: {{entityIds: {json.dumps([entity_id])}}}"]

        if start_time and isinstance(start_time, str):
            filters.append(f"startTime: {json.dumps(start_time)}")
        if end_time and isinstance(end_time, str):
            filters.append(f"endTime: {json.dumps(end_time)}")
        if event_types and isinstance(event_types, list):
            # Format event types as unquoted GraphQL enums
            categories_str = "[" + ", ".join(event_types) + "]"
            filters.append(f"categories: {categories_str}")

        filter_string = ", ".join(filters)

        return f"""
        query {{
            timeline({filter_string}, first: {limit}) {{
                nodes {{
                    eventId
                    eventType
                    eventSeverity
                    timestamp
                    ... on TimelineUserOnEndpointActivityEvent {{
                        sourceEntity {{
                            entityId
                            primaryDisplayName
                        }}
                        targetEntity {{
                            entityId
                            primaryDisplayName
                        }}
                        geoLocation {{
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }}
                        locationAssociatedWithUser
                        userDisplayName
                        endpointDisplayName
                        ipAddress
                    }}
                    ... on TimelineAuthenticationEvent {{
                        sourceEntity {{
                            entityId
                            primaryDisplayName
                        }}
                        targetEntity {{
                            entityId
                            primaryDisplayName
                        }}
                        geoLocation {{
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }}
                        locationAssociatedWithUser
                        userDisplayName
                        endpointDisplayName
                        ipAddress
                    }}
                    ... on TimelineAlertEvent {{
                        sourceEntity {{
                            entityId
                            primaryDisplayName
                        }}
                    }}
                    ... on TimelineDceRpcEvent {{
                        sourceEntity {{
                            entityId
                            primaryDisplayName
                        }}
                        targetEntity {{
                            entityId
                            primaryDisplayName
                        }}
                        geoLocation {{
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }}
                        locationAssociatedWithUser
                        userDisplayName
                        endpointDisplayName
                        ipAddress
                    }}
                    ... on TimelineFailedAuthenticationEvent {{
                        sourceEntity {{
                            entityId
                            primaryDisplayName
                        }}
                        targetEntity {{
                            entityId
                            primaryDisplayName
                        }}
                        geoLocation {{
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }}
                        locationAssociatedWithUser
                        userDisplayName
                        endpointDisplayName
                        ipAddress
                    }}
                    ... on TimelineSuccessfulAuthenticationEvent {{
                        sourceEntity {{
                            entityId
                            primaryDisplayName
                        }}
                        targetEntity {{
                            entityId
                            primaryDisplayName
                        }}
                        geoLocation {{
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }}
                        locationAssociatedWithUser
                        userDisplayName
                        endpointDisplayName
                        ipAddress
                    }}
                    ... on TimelineServiceAccessEvent {{
                        sourceEntity {{
                            entityId
                            primaryDisplayName
                        }}
                        targetEntity {{
                            entityId
                            primaryDisplayName
                        }}
                        geoLocation {{
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }}
                        locationAssociatedWithUser
                        userDisplayName
                        endpointDisplayName
                        ipAddress
                    }}
                    ... on TimelineFileOperationEvent {{
                        targetEntity {{
                            entityId
                            primaryDisplayName
                        }}
                        geoLocation {{
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }}
                        locationAssociatedWithUser
                        userDisplayName
                        endpointDisplayName
                        ipAddress
                    }}
                    ... on TimelineLdapSearchEvent {{
                        sourceEntity {{
                            entityId
                            primaryDisplayName
                        }}
                        targetEntity {{
                            entityId
                            primaryDisplayName
                        }}
                        geoLocation {{
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }}
                        locationAssociatedWithUser
                        userDisplayName
                        endpointDisplayName
                        ipAddress
                    }}
                    ... on TimelineRemoteCodeExecutionEvent {{
                        sourceEntity {{
                            entityId
                            primaryDisplayName
                        }}
                        targetEntity {{
                            entityId
                            primaryDisplayName
                        }}
                        geoLocation {{
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }}
                        locationAssociatedWithUser
                        userDisplayName
                        endpointDisplayName
                        ipAddress
                    }}
                    ... on TimelineConnectorConfigurationEvent {{
                        category
                    }}
                    ... on TimelineConnectorConfigurationAddedEvent {{
                        category
                    }}
                    ... on TimelineConnectorConfigurationDeletedEvent {{
                        category
                    }}
                    ... on TimelineConnectorConfigurationModifiedEvent {{
                        category
                    }}
                }}
                pageInfo {{
                    hasNextPage
                    endCursor
                }}
            }}
        }}
        """

    def _build_relationship_analysis_query(
        self,
        entity_id: str,
        relationship_depth: int,
        include_risk_context: bool,
        limit: int,
    ) -> str:
        """Build GraphQL query for relationship analysis."""
        risk_fields = ""
        if include_risk_context:
            risk_fields = """
                riskScore
                riskScoreSeverity
                riskFactors {
                    type
                    severity
                }
            """

        # Build nested association fields based on relationship_depth
        def build_association_fields(depth: int) -> str:
            if depth <= 0:
                return ""

            nested_associations = ""
            if depth > 1:
                nested_associations = build_association_fields(depth - 1)

            return f"""
                associations {{
                    bindingType
                    ... on EntityAssociation {{
                        entity {{
                            entityId
                            primaryDisplayName
                            secondaryDisplayName
                            type
                            {risk_fields}
                            {nested_associations}
                        }}
                    }}
                    ... on LocalAdminLocalUserAssociation {{
                        accountName
                    }}
                    ... on LocalAdminDomainEntityAssociation {{
                        entityType
                        entity {{
                            entityId
                            primaryDisplayName
                            secondaryDisplayName
                            type
                            {risk_fields}
                            {nested_associations}
                        }}
                    }}
                    ... on GeoLocationAssociation {{
                        geoLocation {{
                            country
                            countryCode
                            city
                            cityCode
                            latitude
                            longitude
                        }}
                    }}
                }}
            """

        association_fields = build_association_fields(relationship_depth)

        return f"""
        query {{
            entities(entityIds: {json.dumps([entity_id])}, first: {limit}) {{
                nodes {{
                    entityId
                    primaryDisplayName
                    secondaryDisplayName
                    type
                    {risk_fields}
                    {association_fields}
                }}
            }}
        }}
        """

    def _build_risk_assessment_query(
        self, entity_ids: list[str], include_risk_factors: bool
    ) -> str:
        """Build GraphQL query for risk assessment."""
        entity_ids_json = json.dumps(entity_ids)

        risk_fields = """
            riskScore
            riskScoreSeverity
        """

        if include_risk_factors:
            risk_fields += """
                riskFactors {
                    type
                    severity
                }
            """

        return f"""
        query {{
            entities(entityIds: {entity_ids_json}, first: 50) {{
                nodes {{
                    entityId
                    primaryDisplayName
                    {risk_fields}
                }}
            }}
        }}
        """

    def _resolve_entities(self, identifiers: dict[str, Any]) -> list[str] | dict[str, Any]:
        """Resolve entity IDs from various identifier types using unified AND-based query.

        All provided identifiers are combined using AND logic in a single GraphQL query.
        For example: entity_names="Administrator" + domain_names=["XDRHOLDINGS.COM"]
        will find entities that match BOTH criteria.

        Returns:
            List[str]: List of resolved entity IDs on success
            Dict[str, Any]: Error response on failure
        """
        resolved_ids = []

        # Direct entity IDs - no resolution needed
        entity_ids = identifiers.get("entity_ids")
        if entity_ids and isinstance(entity_ids, list):
            resolved_ids.extend(entity_ids)

        # Check if we have conflicting entity types (USER vs ENDPOINT)
        email_addresses = identifiers.get("email_addresses")
        ip_addresses = identifiers.get("ip_addresses")
        has_user_criteria = bool(email_addresses)
        has_endpoint_criteria = bool(ip_addresses)

        # If we have both USER and ENDPOINT criteria, we need separate queries
        if has_user_criteria and has_endpoint_criteria:
            # This is a conflict - cannot search for both USER and ENDPOINT in same query
            # For now, prioritize USER entities (emails) over ENDPOINT entities (IPs)
            logger.warning(
                "Cannot combine email addresses (USER) and IP addresses (ENDPOINT) in single query. Prioritizing USER entities."
            )
            ip_addresses = None

        # Build unified GraphQL query with AND logic
        query_filters: list[str] = []
        query_fields: list[str] = []

        # Add entity names filter
        self._add_entity_filters(identifiers, query_fields, query_filters)
        # Add email addresses filter (USER entities)
        self._add_email_filter(email_addresses, query_fields, query_filters)
        # Add IP addresses filter (ENDPOINT entities) - only if no USER criteria
        self._add_ip_filter(has_user_criteria, ip_addresses, query_fields, query_filters)
        # Add domain names filter
        domain_names = self._add_domain_filter(identifiers, query_fields, query_filters)

        # If we have filters to apply, execute unified query
        if query_filters:
            # Remove duplicates from fields
            query_fields = list(set(query_fields))
            fields_string = "\n".join(query_fields)

            # Add account information for domain context
            if domain_names:
                fields_string += """
                    accounts {
                        ... on ActiveDirectoryAccountDescriptor {
                            domain
                            samAccountName
                        }
                    }"""

            filters_string = ", ".join(query_filters)
            limit = identifiers.get("limit", 50)

            query = f"""
            query {{
                entities({filters_string}, first: {limit}) {{
                    nodes {{
                        entityId
                        {fields_string}
                    }}
                }}
            }}
            """

            result = self._base_query_api_call(
                operation="api_preempt_proxy_post_graphql",
                body_params={"query": query},
                error_message="Failed to resolve entities with combined filters",
                default_result=None,
            )
            if self._is_error(result):
                return result

            # Extract entities from GraphQL response structure
            data = result.get("data", {})
            entities = data.get("entities", {}).get("nodes", [])
            resolved_ids.extend([entity["entityId"] for entity in entities])

        # Remove duplicates and return
        return list(set(resolved_ids))

    def _add_domain_filter(
        self,
        identifiers,
        query_fields,
        query_filters,
    ):
        domain_names = identifiers.get("domain_names")
        if domain_names and isinstance(domain_names, list):
            sanitized_domains = [sanitize_input(domain) for domain in domain_names]
            domains_json = json.dumps(sanitized_domains)
            query_filters.append(f"domains: {domains_json}")
            query_fields.extend(["primaryDisplayName", "secondaryDisplayName"])
        return domain_names

    def _add_ip_filter(
        self,
        has_user_criteria,
        ip_addresses,
        query_fields,
        query_filters,
    ):
        if ip_addresses and isinstance(ip_addresses, list) and not has_user_criteria:
            sanitized_ips = [sanitize_input(ip) for ip in ip_addresses]
            ips_json = json.dumps(sanitized_ips)
            query_filters.append(f"primaryDisplayNames: {ips_json}")
            query_filters.append("types: [ENDPOINT]")
            query_fields.append("primaryDisplayName")

    def _add_email_filter(
        self,
        email_addresses,
        query_fields,
        query_filters,
    ):
        if email_addresses and isinstance(email_addresses, str):
            sanitized_email = sanitize_input(email_addresses)
            query_filters.append(f"secondaryDisplayNamePattern: {json.dumps(sanitized_email)}")
            query_filters.append("types: [USER]")
            query_fields.extend(["primaryDisplayName", "secondaryDisplayName"])

    def _add_entity_filters(
        self,
        identifiers,
        query_fields,
        query_filters,
    ):
        entity_names = identifiers.get("entity_names")
        if entity_names and isinstance(entity_names, str):
            sanitized_name = sanitize_input(entity_names)
            query_filters.append(f"primaryDisplayNamePattern: {json.dumps(sanitized_name)}")
            query_fields.append("primaryDisplayName")

    def _get_entity_details_batch(
        self,
        entity_ids: list[str],
        options: dict[str, Any],
    ) -> dict[str, Any]:
        """Get detailed entity information for multiple entities."""
        graphql_query = self._build_entity_details_query(
            entity_ids=entity_ids,
            include_risk_factors=True,
            include_associations=options.get("include_associations", True),
            include_incidents=options.get("include_incidents", True),
            include_accounts=options.get("include_accounts", True),
        )

        result = self._base_query_api_call(
            operation="api_preempt_proxy_post_graphql",
            body_params={"query": graphql_query},
            error_message="Failed to get entity details",
            default_result=None,
        )
        if self._is_error(result):
            return result

        # Extract entities from GraphQL response structure
        data = result.get("data", {})
        entities = data.get("entities", {}).get("nodes", [])
        return {"entities": entities, "entity_count": len(entities)}

    def _get_entity_timelines_batch(
        self, entity_ids: list[str], options: dict[str, Any]
    ) -> dict[str, Any]:
        """Get timeline analysis for multiple entities."""
        timeline_results = []

        for entity_id in entity_ids:
            graphql_query = self._build_timeline_query(
                entity_id=entity_id,
                start_time=options.get("start_time"),
                end_time=options.get("end_time"),
                event_types=options.get("event_types"),
                limit=options.get("limit", 50),
            )

            result = self._base_query_api_call(
                operation="api_preempt_proxy_post_graphql",
                body_params={"query": graphql_query},
                error_message=f"Failed to get timeline for entity '{entity_id}'",
                default_result=None,
            )
            if self._is_error(result):
                return result

            # Extract timeline from GraphQL response structure
            data = result.get("data", {})
            timeline_data = data.get("timeline", {})
            timeline_results.append(
                {
                    "entity_id": entity_id,
                    "timeline": timeline_data.get("nodes", []),
                    "page_info": timeline_data.get("pageInfo", {}),
                }
            )

        return {"timelines": timeline_results, "entity_count": len(entity_ids)}

    def _analyze_relationships_batch(
        self,
        entity_ids: list[str],
        options: dict[str, Any],
    ) -> dict[str, Any]:
        """Analyze relationships for multiple entities."""
        relationship_results = []

        for entity_id in entity_ids:
            relationship_depth = unwrap_field_default(options.get("relationship_depth", 2))

            graphql_query = self._build_relationship_analysis_query(
                entity_id=entity_id,
                relationship_depth=relationship_depth,
                include_risk_context=options.get("include_risk_context", True),
                limit=options.get("limit", 50),
            )

            result = self._base_query_api_call(
                operation="api_preempt_proxy_post_graphql",
                body_params={"query": graphql_query},
                error_message=f"Failed to analyze relationships for entity '{entity_id}'",
                default_result=None,
            )
            if self._is_error(result):
                return result

            # Extract entities from GraphQL response structure
            data = result.get("data", {})
            entities = data.get("entities", {}).get("nodes", [])
            if entities:
                entity_data = entities[0]
                relationship_results.append(
                    {
                        "entity_id": entity_id,
                        "associations": entity_data.get("associations", []),
                        "relationship_count": len(entity_data.get("associations", [])),
                    }
                )
            else:
                relationship_results.append(
                    {
                        "entity_id": entity_id,
                        "associations": [],
                        "relationship_count": 0,
                    }
                )

        return {"relationships": relationship_results, "entity_count": len(entity_ids)}

    def _assess_risks_batch(
        self,
        entity_ids: list[str],
        options: dict[str, Any],
    ) -> dict[str, Any]:
        """Perform risk assessment for multiple entities."""
        graphql_query = self._build_risk_assessment_query(
            entity_ids=entity_ids,
            include_risk_factors=options.get("include_risk_factors", True),
        )

        result = self._base_query_api_call(
            operation="api_preempt_proxy_post_graphql",
            body_params={"query": graphql_query},
            error_message="Failed to assess risks",
            default_result=None,
        )
        if self._is_error(result):
            return result

        # Extract entities from GraphQL response structure
        data = result.get("data", {})
        entities = data.get("entities", {}).get("nodes", [])
        risk_assessments = []

        for entity in entities:
            risk_assessments.append(
                {
                    "entityId": entity.get("entityId"),
                    "primaryDisplayName": entity.get("primaryDisplayName"),
                    "riskScore": entity.get("riskScore", 0),
                    "riskScoreSeverity": entity.get("riskScoreSeverity", "LOW"),
                    "riskFactors": entity.get("riskFactors", []),
                }
            )

        return {
            "risk_assessments": risk_assessments,
            "entity_count": len(risk_assessments),
        }

    def _synthesize_investigation_response(
        self,
        entity_ids: list[str],
        investigation_results: dict[str, Any],
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        """Synthesize comprehensive investigation response from multiple API results."""

        # Build investigation summary
        investigation_summary = {
            "entity_count": len(entity_ids),
            "resolved_entity_ids": entity_ids,
            "investigation_types": metadata.get("investigation_types", []),
            "timestamp": datetime.utcnow().isoformat(),
            "status": "completed",
        }

        # Add search criteria to summary
        search_criteria = metadata.get("search_criteria", {})
        if any(search_criteria.values()):
            investigation_summary["search_criteria"] = search_criteria

        # Start building comprehensive response
        response = {
            "investigation_summary": investigation_summary,
            "entities": entity_ids,
        }

        # Add investigation results based on what was requested
        for investigation_type, results in investigation_results.items():
            response[investigation_type] = results

        # Generate cross-investigation insights
        insights = self._generate_investigation_insights(investigation_results, entity_ids)
        if insights:
            response["cross_investigation_insights"] = insights

        return response

    def _generate_investigation_insights(
        self,
        investigation_results: dict[str, Any],
        entity_ids: list[str],
    ) -> dict[str, Any]:
        """Generate insights by analyzing results across different investigation types."""
        insights = {}

        # Timeline and relationship correlation
        if (
            "timeline_analysis" in investigation_results
            and "relationship_analysis" in investigation_results
        ):
            insights["activity_relationship_correlation"] = self._analyze_activity_relationships(
                investigation_results["timeline_analysis"],
                investigation_results["relationship_analysis"],
            )

        # Multi-entity patterns (if investigating multiple entities)
        if len(entity_ids) > 1:
            insights["multi_entity_patterns"] = self._analyze_multi_entity_patterns(
                investigation_results, entity_ids
            )

        return insights

    def _analyze_activity_relationships(
        self,
        timeline_analysis: dict[str, Any],
        relationship_analysis: dict[str, Any],
    ) -> dict[str, Any]:
        """Analyze correlation between timeline activities and entity relationships."""
        correlation: dict[str, Any] = {"related_entity_activities": [], "suspicious_patterns": []}

        # This would involve complex analysis of timeline events and relationships
        # For now, provide basic structure
        timelines = timeline_analysis.get("timelines", [])
        relationships = relationship_analysis.get("relationships", [])

        correlation["timeline_count"] = len(timelines)
        correlation["relationship_count"] = len(relationships)

        return correlation

    def _analyze_multi_entity_patterns(
        self,
        investigation_results: dict[str, Any],
        entity_ids: list[str],
    ) -> dict[str, Any]:
        """Analyze patterns across multiple entities being investigated."""
        patterns: dict[str, Any] = {
            "common_risk_factors": [],
            "shared_relationships": [],
            "coordinated_activities": [],
        }

        # Analyze common risk factors across entities
        if "risk_assessment" in investigation_results:
            risk_assessments = investigation_results["risk_assessment"].get("risk_assessments", [])
            risk_factor_counts: dict[str, int] = {}

            for assessment in risk_assessments:
                for risk_factor in assessment.get("riskFactors", []):
                    risk_type = risk_factor.get("type")
                    if risk_type in risk_factor_counts:
                        risk_factor_counts[risk_type] += 1
                    else:
                        risk_factor_counts[risk_type] = 1

            # Find common risk factors (present in multiple entities)
            for risk_type, count in risk_factor_counts.items():
                if count > 1:
                    patterns["common_risk_factors"].append(
                        {
                            "risk_type": risk_type,
                            "entity_count": count,
                            "percentage": round((count / len(entity_ids)) * 100, 1),
                        }
                    )

        return patterns
