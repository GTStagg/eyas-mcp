"""
Browser module for Falcon MCP Server

This module provides tools for Falcon Seraphic Enterprise Browser: search the browser
agents running in users' browsers, read the browser policy rules, destination groups and
sensitive data profiles, check a browser extension's risk analysis and read the tenant's
Seraphic settings; activate or deactivate agents; queue response tasks on an agent, such
as closing every window or removing browsing data; manage destination groups and
sensitive data profiles; and change a rule's status or its extension list.
"""

import ipaddress
import re
from datetime import datetime
from typing import Any, Literal

from mcp.server import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from falcon_mcp.common.errors import _format_error_response, handle_api_response
from falcon_mcp.common.logging import get_logger
from falcon_mcp.modules.base import BaseModule

logger = get_logger(__name__)

MAX_LIMIT = 1000
MAX_IDS = 100
# Bounds for a time window given only one side
EARLIEST = "1970-01-01T00:00:00Z"
LATEST = "2100-01-01T00:00:00Z"

UUID_PATTERN = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
RULE_ID_PATTERN = re.compile(r"[0-9]{1,18}")
HOST_ID_PATTERN = re.compile(r"[0-9a-fA-F]{64}")
# Store extension IDs: 32 letters for Chromium stores, an email-like or {GUID} ID for Mozilla
EXTENSION_ID_PATTERN = re.compile(r"[A-Za-z0-9@._{}\-]{1,256}")
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

AgentStatus = Literal["active", "inactive", "disabled"]
ProtectionType = Literal["Extension", "Seraphic Workspace"]
AgentSortField = Literal["last_seen", "first_seen", "hostname", "username", "application_name", "os_name"]
RuleCategory = Literal[
    "general",
    "protection",
    "sessions_and_credentials",
    "content_governance",
    "dlp",
    "privacy",
    "it_hygiene",
    "telemetry",
    "proxy",
    "extensions",
    "applications",
]
ExtensionStore = Literal["google", "mozilla", "microsoft", "apple", "opera"]
AgentTask = Literal["close_all_windows", "refresh_all_tabs", "remove_browsing_data"]
PolicySortField = Literal["name", "description", "created_at", "created_by", "linked_rules"]
RuleStatus = Literal["active", "inactive"]

MAX_LIST_ITEMS = 1000
MAX_REGEXES = 100
# Domains, wildcards and URL patterns such as https://example.com/path*
DOMAIN_PATTERN = re.compile(r"[^\s\x00-\x1f\x7f]{1,2048}")
COUNTRY_PATTERN = re.compile(r"[A-Za-z]{2}")
# Destination group list fields: tool parameter suffix -> API field
_GROUP_LISTS = {
    "domains": "domains",
    "single_ips": "singleIps",
    "countries": "countries",
    "classifications": "classification",
}
# Rule extension changes: tool parameter -> API field. The API applies each field
# separately and not transactionally, so each one goes in its own call.
_EXTENSION_CHANGES = {
    "add_extension_ids": "addExtensionIds",
    "remove_extension_ids": "removeExtensionIds",
    "add_extension_names": "addExtensionNames",
    "remove_extension_names": "removeExtensionNames",
}

# Extension analysis fields kept as they are; the rest of a record (code scans, every
# URL and function name found in the code) runs to several megabytes.
_EXTENSION_FIELDS = (
    "id",
    "name",
    "store",
    "version",
    "category",
    "rating",
    "reviewsCount",
    "usersCount",
    "last_updated",
    "website",
    "size",
    "establishedPublisher",
    "featuredBadge",
    "privacyPolicy",
    "risk_score",
    "reputation",
    "privacy_policy",
    "classification",
    "permissions",
    "optional_permissions",
    "content_security_policy",
    "oauth2",
)
_SECRET_KINDS = (
    "apiKeys",
    "githubTokens",
    "firebaseConfig",
    "jwt",
    "databaseConnection",
    "encryptionKey",
    "bearerToken",
    "sslKey",
    "bitcoins",
)
_LIST_CAP = 50
_HISTORY_CAP = 20


def _error(message: str, operation: str) -> dict[str, Any]:
    return _format_error_response(message, operation=operation)


def _clean(values: list[str] | None, pattern: re.Pattern[str], label: str) -> tuple[list[str], str | None]:
    """Strip, validate and de-duplicate IDs, keeping order."""
    out: list[str] = []
    for raw in values or []:
        value = raw.strip() if isinstance(raw, str) else ""
        if not pattern.fullmatch(value):
            return [], f"Invalid {label} {raw!r}."
        if value.lower() not in (v.lower() for v in out):
            out.append(value)
    if len(out) > MAX_IDS:
        return [], f"Too many {label}s: {len(out)}. At most {MAX_IDS} per call."
    return out, None


def _timestamp(value: str | None, label: str) -> tuple[str | None, str | None]:
    """Check an ISO 8601 timestamp, which the API would otherwise accept and ignore."""
    if value is None or not value.strip():
        return None, None
    text = value.strip()
    problem = f"{label} must be an ISO 8601 timestamp such as 2026-11-01T00:00:00Z, not {value!r}."
    if "T" not in text:
        return None, problem
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None, problem
    return text, None


def _resources(response: dict[str, Any]) -> list[Any]:
    resources = (response.get("body") or {}).get("resources")
    return resources if isinstance(resources, list) else []


def _total(response: dict[str, Any]) -> int | None:
    pagination = ((response.get("body") or {}).get("meta") or {}).get("pagination") or {}
    total = pagination.get("total")
    return total if isinstance(total, int) else None


def _clean_items(
    values: list[str] | None, label: str, kind: str
) -> tuple[list[str], str | None]:
    """Validate destination group entries of one kind, de-duplicated and in order."""
    out: list[str] = []
    for raw in values or []:
        value = raw.strip() if isinstance(raw, str) else ""
        if kind == "domains":
            ok = bool(DOMAIN_PATTERN.fullmatch(value)) and "." in value
        elif kind == "single_ips":
            try:
                ipaddress.ip_network(value, strict=False)
                ok = True
            except ValueError:
                ok = False
        elif kind == "countries":
            ok = bool(COUNTRY_PATTERN.fullmatch(value))
            value = value.upper()
        else:
            ok = 0 < len(value) <= 100 and not CONTROL_CHARS.search(value)
        if not ok:
            return [], f"Invalid entry in {label}: {raw!r}."
        if value not in out:
            out.append(value)
    if len(out) > MAX_LIST_ITEMS:
        return [], f"At most {MAX_LIST_ITEMS} entries in {label}."
    return out, None


def _clean_regexes(values: list[dict[str, Any]] | None) -> tuple[list[dict[str, Any]], str | None]:
    """Validate custom regex entries: a name, a pattern that compiles, and a threshold."""
    out: list[dict[str, Any]] = []
    for entry in values or []:
        if not isinstance(entry, dict):
            return [], "Each custom_regex entry must be an object with name, regex and threshold."
        name = entry.get("name")
        regex = entry.get("regex")
        threshold = entry.get("threshold", 1)
        if not isinstance(name, str) or not 0 < len(name.strip()) <= 100 or CONTROL_CHARS.search(name):
            return [], f"Invalid custom regex name {name!r}."
        if not isinstance(regex, str) or not 0 < len(regex) <= 2000 or CONTROL_CHARS.search(regex):
            return [], f"Invalid regex for {name!r}: give 1-2000 characters with no control characters."
        try:
            re.compile(regex)
        except re.error as exc:
            return [], f"The regex for {name!r} doesn't compile: {exc}."
        if isinstance(threshold, bool) or not isinstance(threshold, int) or not 1 <= threshold <= 1000:
            return [], f"threshold for {name!r} must be a whole number from 1 to 1000."
        out = [r for r in out if r["name"] != name.strip()]
        out.append({"name": name.strip(), "regex": regex, "threshold": threshold})
    if len(out) > MAX_REGEXES:
        return [], f"At most {MAX_REGEXES} custom regexes per profile."
    return out, None


def _flatten_profile(record: dict[str, Any]) -> dict[str, Any]:
    """Profiles come back as {sensitive_data_profile, related_rules}; return one record."""
    inner = record.get("sensitive_data_profile")
    if not isinstance(inner, dict):
        return record
    return {**inner, "related_rules": record.get("related_rules") or []}


def _trim_extension(record: dict[str, Any]) -> dict[str, Any]:
    """Keep the verdict and the findings an analyst reads from an extension analysis."""
    out: dict[str, Any] = {k: record[k] for k in _EXTENSION_FIELDS if k in record}
    description = record.get("description")
    if isinstance(description, str):
        out["description"] = description[:500]

    manifest = record.get("manifest") or {}
    if isinstance(manifest, dict):
        matches: list[str] = []
        for script in manifest.get("content_scripts") or []:
            for match in (script or {}).get("matches") or []:
                if match not in matches:
                    matches.append(match)
        out["manifest"] = {
            "manifest_version": manifest.get("manifest_version"),
            "host_permissions": (manifest.get("host_permissions") or [])[:_LIST_CAP],
            "content_script_matches": matches[:_LIST_CAP],
        }

    summary = record.get("analysisSummary") or {}
    if isinstance(summary, dict):
        data = summary.get("data") or {}
        out["code_analysis"] = {
            "contains_obfuscated_code": summary.get("containsObfuscatedCode"),
            "invoked_native_apis": (summary.get("invokedNativeAPIs") or [])[:_LIST_CAP],
            "vulnerabilities": (summary.get("vulnerabilities") or [])[:_LIST_CAP],
            "indicator_counts": {
                key: len(data.get(key) or []) for key in ("urls", "emails", "ips", "bitcoinAddresses")
            },
        }

    results = record.get("analysisResults") or {}
    if isinstance(results, dict):
        secrets = {kind: 0 for kind in _SECRET_KINDS}
        for entry in results.get("intel") or []:
            found = (entry or {}).get("results") or {}
            for kind in _SECRET_KINDS:
                if found.get(kind):
                    secrets[kind] += 1
        obfuscation: set[str] = set()
        obfuscated_files = 0
        for entry in results.get("code") or []:
            kinds = ((entry or {}).get("results") or {}).get("obfuscationTypes") or []
            if kinds:
                obfuscated_files += 1
                obfuscation.update(str(k) for k in kinds)
        domains = []
        for item in (results.get("suspicious_domains") or [])[:_LIST_CAP]:
            if isinstance(item, dict):
                domains.append(
                    {
                        "domain": item.get("domain"),
                        "classifications": item.get("classifications"),
                        "is_malicious": item.get("isMalicious"),
                        "is_trusted": item.get("isTrusted"),
                        "is_typosquatting": (item.get("typosquatting") or {}).get("isTyposquatting"),
                        "source": item.get("source"),
                    }
                )
        out["findings"] = {
            "known_vulnerable_libraries": (results.get("retireJS") or [])[:_LIST_CAP],
            "files_with_secrets": {kind: n for kind, n in secrets.items() if n},
            "obfuscated_files": obfuscated_files,
            "obfuscation_types": sorted(obfuscation),
            "suspicious_domains": domains,
        }

    scripts = record.get("scripts_analysis") or {}
    if isinstance(scripts, dict):
        out["script_counts"] = {
            "background": scripts.get("background_scripts_count"),
            "content": scripts.get("content_scripts_count"),
        }
    history = record.get("history") or []
    if isinstance(history, list):
        out["risk_history"] = [
            {"version": h.get("version"), "risk_score": h.get("risk_score")}
            for h in history[-_HISTORY_CAP:]
            if isinstance(h, dict)
        ]
    return out


class BrowserModule(BaseModule):
    """Module for Falcon Seraphic Enterprise Browser."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(server=server, method=self.search_browser_agents, name="search_browser_agents")
        self._add_tool(server=server, method=self.get_browser_agents, name="get_browser_agents")
        self._add_tool(server=server, method=self.search_browser_rules, name="search_browser_rules")
        self._add_tool(server=server, method=self.get_browser_rules, name="get_browser_rules")
        self._add_tool(
            server=server,
            method=self.get_browser_extension_analysis,
            name="get_browser_extension_analysis",
        )
        self._add_tool(
            server=server, method=self.get_browser_tenant_settings, name="get_browser_tenant_settings"
        )
        self._add_tool(
            server=server,
            method=self.activate_browser_agents,
            name="activate_browser_agents",
            annotations=ToolAnnotations(
                readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
            ),
        )
        self._add_tool(
            server=server,
            method=self.deactivate_browser_agents,
            name="deactivate_browser_agents",
            annotations=ToolAnnotations(
                readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
            ),
        )
        self._add_tool(
            server=server,
            method=self.run_browser_agent_tasks,
            name="run_browser_agent_tasks",
            annotations=ToolAnnotations(
                readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
            ),
        )
        # Policy objects
        self._add_tool(
            server=server,
            method=self.search_browser_destination_groups,
            name="search_browser_destination_groups",
        )
        self._add_tool(
            server=server,
            method=self.get_browser_destination_groups,
            name="get_browser_destination_groups",
        )
        self._add_tool(
            server=server, method=self.search_browser_data_profiles, name="search_browser_data_profiles"
        )
        self._add_tool(
            server=server, method=self.get_browser_data_profiles, name="get_browser_data_profiles"
        )
        self._add_tool(
            server=server,
            method=self.create_browser_destination_group,
            name="create_browser_destination_group",
            annotations=ToolAnnotations(
                readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
            ),
        )
        self._add_tool(
            server=server,
            method=self.update_browser_destination_group,
            name="update_browser_destination_group",
            annotations=ToolAnnotations(
                readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True
            ),
        )
        self._add_tool(
            server=server,
            method=self.delete_browser_destination_group,
            name="delete_browser_destination_group",
            annotations=ToolAnnotations(
                readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True
            ),
        )
        self._add_tool(
            server=server,
            method=self.create_browser_data_profile,
            name="create_browser_data_profile",
            annotations=ToolAnnotations(
                readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
            ),
        )
        self._add_tool(
            server=server,
            method=self.update_browser_data_profile,
            name="update_browser_data_profile",
            annotations=ToolAnnotations(
                readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True
            ),
        )
        self._add_tool(
            server=server,
            method=self.delete_browser_data_profile,
            name="delete_browser_data_profile",
            annotations=ToolAnnotations(
                readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True
            ),
        )
        self._add_tool(
            server=server,
            method=self.set_browser_rule_status,
            name="set_browser_rule_status",
            annotations=ToolAnnotations(
                readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True
            ),
        )
        self._add_tool(
            server=server,
            method=self.update_browser_rule_extensions,
            name="update_browser_rule_extensions",
            annotations=ToolAnnotations(
                readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True
            ),
        )

    # ------------------------------------------------------------------ #
    # Shared helpers
    # ------------------------------------------------------------------ #

    def _query_then_get(
        self,
        query_operation: str,
        query_body: dict[str, Any],
        get_operation: str,
        error_message: str,
        query_parameters: dict[str, Any] | None = None,
        unwrap: Any = None,
    ) -> tuple[list[dict[str, Any]], int | None] | dict[str, Any]:
        """Query IDs, fetch their records in batches and return them in the query's order.

        `unwrap` turns each fetched record into the shape returned, before reordering.
        """
        kwargs: dict[str, Any] = {"body": query_body}
        if query_parameters:
            kwargs["parameters"] = query_parameters
        response = self.client.command(query_operation, **kwargs)
        if (response.get("status_code") or 0) >= 300:
            error: dict[str, Any] = handle_api_response(
                response, operation=query_operation, error_message=error_message
            )
            return error
        # The destination group query has been seen returning a null among its IDs
        ids = [str(i) for i in _resources(response) if i is not None]
        total = _total(response)
        records: list[dict[str, Any]] = []
        for start in range(0, len(ids), MAX_IDS):
            batch = self.client.command(get_operation, parameters={"ids": ids[start : start + MAX_IDS]})
            if (batch.get("status_code") or 0) >= 300:
                batch_error: dict[str, Any] = handle_api_response(
                    batch, operation=get_operation, error_message=error_message
                )
                return batch_error
            records.extend(r for r in _resources(batch) if isinstance(r, dict))
        if unwrap is not None:
            records = [unwrap(r) for r in records]
        return self._reorder_by_ids(ids, records, id_field="id"), total

    def _get_by_ids(
        self, operation: str, ids: list[str], error_message: str, unwrap: Any = None
    ) -> dict[str, Any]:
        """Fetch records by ID and split the IDs that matched nothing into `not_found`."""
        response = self.client.command(operation, parameters={"ids": ids})
        if (response.get("status_code") or 0) >= 300:
            error: dict[str, Any] = handle_api_response(
                response, operation=operation, error_message=error_message
            )
            return error
        found = [r for r in _resources(response) if isinstance(r, dict)]
        if unwrap is not None:
            found = [unwrap(r) for r in found]
        seen = {str(r.get("id", "")).lower() for r in found}
        return {"found": found, "not_found": [i for i in ids if i.lower() not in seen]}

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #

    def search_browser_agents(
        self,
        hostname: str | None = Field(
            default=None, description="Part of a hostname, matched without regard to case."
        ),
        username: str | None = Field(
            default=None, description="An exact, case-sensitive username signed in to the browser."
        ),
        email: str | None = Field(default=None, description="An exact user email address."),
        host_id: str | None = Field(
            default=None,
            description=(
                "Seraphic's 64-character host ID from an agent record. It is not a Falcon "
                "sensor AID; to link an agent to a Falcon host, match on hostname."
            ),
        ),
        browser: str | None = Field(
            default=None,
            description="Exact browser name as agents report it, e.g. chrome, firefox, microsoft edge, brave.",
        ),
        status: AgentStatus | None = Field(default=None, description="Agent status."),
        protection_type: ProtectionType | None = Field(
            default=None,
            description="Extension (an extension in a standard browser) or Seraphic Workspace.",
        ),
        os_name: str | None = Field(default=None, description="Operating system name, e.g. Windows."),
        last_seen_after: str | None = Field(
            default=None, description="ISO 8601 timestamp, e.g. 2026-11-01T00:00:00Z."
        ),
        last_seen_before: str | None = Field(default=None, description="ISO 8601 timestamp."),
        first_seen_after: str | None = Field(default=None, description="ISO 8601 timestamp."),
        first_seen_before: str | None = Field(default=None, description="ISO 8601 timestamp."),
        search: str | None = Field(
            default=None, description="Free text matched against hostnames and usernames."
        ),
        sort_by: AgentSortField = Field(default="last_seen", description="Field to sort by."),
        sort_order: Literal["asc", "desc"] = Field(default="desc", description="asc or desc."),
        limit: int = Field(default=50, ge=1, le=MAX_LIMIT, description=f"[1-{MAX_LIMIT}]"),
        offset: int = Field(default=0, ge=0, description="The number of agents to skip."),
    ) -> dict[str, Any]:
        """Search Seraphic Enterprise Browser agents: which users and hosts run a protected browser, and their state.

        Each agent is one browser on one host. Records carry `id`, `hostname`,
        `username`, `application_name` (the browser), `status`, `artifact_type`,
        the extension or workspace version, OS, IP addresses, first and last seen,
        whether the agent has the latest policy, and `self_info` (install type and
        whether it can be disabled). Filters combine with AND.
        """
        operation = "CombinedQueryAgents"
        filters: dict[str, Any] = {}
        for key, value in (
            ("hostname", hostname),
            ("username", username),
            ("email", email),
            ("application_name", browser),
            ("status", status),
            ("protection_type", protection_type),
            ("os_name", os_name),
        ):
            if isinstance(value, str) and value.strip():
                if CONTROL_CHARS.search(value):
                    return _error(f"{key} can't contain control characters.", operation)
                filters[key] = [value.strip()]
        if host_id is not None and host_id.strip():
            if not HOST_ID_PATTERN.fullmatch(host_id.strip()):
                return _error("host_id must be Seraphic's 64-character hexadecimal host ID.", operation)
            filters["host_id"] = [host_id.strip().lower()]
        for key, after, before in (
            ("last_seen", last_seen_after, last_seen_before),
            ("first_seen", first_seen_after, first_seen_before),
        ):
            start, problem = _timestamp(after, f"{key}_after")
            end, problem2 = _timestamp(before, f"{key}_before")
            if problem or problem2:
                return _error(str(problem or problem2), operation)
            if start or end:
                # The API ignores a window unless it has both bounds, so fill the open one
                filters[key] = {"start": start or EARLIEST, "end": end or LATEST}

        body: dict[str, Any] = {
            "limit": limit,
            "skip": offset,
            "sort": [{"field": sort_by, "order": sort_order.upper()}],
        }
        if filters:
            body["filter"] = filters
        if search is not None and search.strip():
            body["search"] = search.strip()

        if protection_type:
            # The one-call search ignores protection_type; the ID query honours it.
            result = self._query_then_get(
                "QueryAgents", body, "GetAgents", "Failed to search browser agents"
            )
            if isinstance(result, dict):
                return result
            agents, total = result
        else:
            response = self.client.command(operation, body=body)
            if (response.get("status_code") or 0) >= 300:
                error: dict[str, Any] = handle_api_response(
                    response, operation=operation, error_message="Failed to search browser agents"
                )
                return error
            page = next((r for r in _resources(response) if isinstance(r, dict)), {})
            agents = [a for a in page.get("items") or [] if isinstance(a, dict)]
            total = _total(response)
            if total is None and isinstance(page.get("total"), int):
                total = page["total"]

        return self._build_pagination_envelope(agents, {"total": total, "offset": offset, "limit": limit})

    def get_browser_agents(
        self,
        ids: list[str] = Field(description=f"Agent IDs (UUIDs), at most {MAX_IDS}."),
    ) -> dict[str, Any]:
        """Get Seraphic Enterprise Browser agents by ID, with the IDs that matched no agent in `not_found`."""
        operation = "GetAgents"
        agent_ids, problem = _clean(ids, UUID_PATTERN, "agent ID")
        if problem or not agent_ids:
            return _error(problem or "Give at least one agent ID.", operation)
        return self._get_by_ids(operation, agent_ids, "Failed to get browser agents")

    def search_browser_rules(
        self,
        category: RuleCategory = Field(
            description=(
                "Rule category: general, protection, sessions_and_credentials, "
                "content_governance, dlp, privacy, it_hygiene, telemetry, proxy, "
                "extensions or applications."
            ),
        ),
        search: str | None = Field(default=None, description="Free text matched against rule names."),
        limit: int = Field(default=100, ge=1, le=MAX_LIMIT, description=f"[1-{MAX_LIMIT}]"),
    ) -> dict[str, Any]:
        """List Seraphic Enterprise Browser policy rules in one category, with their settings and scope.

        Each rule has `id`, `name`, `displayName`, `description`, `status` (active or
        inactive), `enabled`, `severity`, `priority`, `input_type`, its options in
        `childrens`, the users or groups it applies to in `targets` (an empty list
        with `anyTarget` true means everyone), the destination groups in
        `destinations`, and the message users see when it triggers.
        """
        body: dict[str, Any] = {"limit": limit}
        if search is not None and search.strip():
            if CONTROL_CHARS.search(search):
                return _error("search can't contain control characters.", "QueryRulesMixin0")
            body["search"] = search.strip()
        result = self._query_then_get(
            "QueryRulesMixin0",
            body,
            "GetRules",
            "Failed to search browser rules",
            query_parameters={"category": category},
        )
        if isinstance(result, dict):
            return result
        rules, total = result
        return self._build_pagination_envelope(rules, {"total": total, "limit": limit})

    def get_browser_rules(
        self,
        ids: list[str] = Field(description=f"Numeric rule IDs, at most {MAX_IDS}."),
    ) -> dict[str, Any]:
        """Get Seraphic Enterprise Browser policy rules by ID, with the IDs that matched no rule in `not_found`."""
        operation = "GetRules"
        rule_ids, problem = _clean([str(i) for i in ids or []], RULE_ID_PATTERN, "rule ID")
        if problem or not rule_ids:
            return _error(problem or "Give at least one rule ID.", operation)
        return self._get_by_ids(operation, rule_ids, "Failed to get browser rules")

    def get_browser_extension_analysis(
        self,
        store: ExtensionStore = Field(
            description="The extension's store: google, mozilla, microsoft, apple or opera."
        ),
        extension_id: str = Field(
            description=(
                "The extension's store ID, e.g. the 32-letter Chrome Web Store ID or a "
                "Mozilla add-on ID such as name@publisher."
            ),
        ),
    ) -> dict[str, Any]:
        """Get Seraphic's risk analysis of a browser extension: risk score, reputation, permissions and code findings.

        The result has the store listing (publisher badges, users, rating), a
        `risk_score` with its reasoning, `reputation`, `privacy_policy`,
        `classification`, the permissions and sites the extension can reach, code
        analysis (obfuscation, native APIs, vulnerable libraries, files containing
        secrets, suspicious domains) and the risk score of earlier versions. The
        first request for an extension starts the analysis; ask again a minute or
        two later for the result.
        """
        operation = "GetExtensionAnalysis"
        ext_id = (extension_id or "").strip()
        if not EXTENSION_ID_PATTERN.fullmatch(ext_id):
            return _error(f"Invalid extension_id {extension_id!r}.", operation)
        response = self.client.command(operation, parameters={"store": store, "id": ext_id})
        if (response.get("status_code") or 0) >= 300:
            error: dict[str, Any] = handle_api_response(
                response, operation=operation, error_message="Failed to get the extension analysis"
            )
            return error
        record = next((r for r in _resources(response) if isinstance(r, dict)), {})
        if "runningAt" in record or (record.get("status") and "analysisSummary" not in record):
            return {
                "id": ext_id,
                "store": store,
                "analysis_status": record.get("status"),
                "message": record.get("message"),
                "started_at": record.get("runningAt"),
                "hint": "The analysis isn't ready yet. Call this tool again in a minute or two.",
            }
        if record.get("failureReason"):
            return {"id": ext_id, "store": store, "failure_reason": record.get("failureReason")}
        return _trim_extension(record)

    def get_browser_tenant_settings(self) -> dict[str, Any]:
        """Get the tenant's Seraphic Enterprise Browser settings: browser sign-in, session and 2FA timeouts, report recipients and branding."""
        operation = "GetTenantSettings"
        response = self.client.command(operation)
        if (response.get("status_code") or 0) >= 300:
            error: dict[str, Any] = handle_api_response(
                response, operation=operation, error_message="Failed to get browser tenant settings"
            )
            return error
        settings = dict(next((r for r in _resources(response) if isinstance(r, dict)), {}))
        for logo in ("logo", "small_logo"):
            if logo in settings:
                # Logos can be inline images; say whether one is set instead of returning it
                settings[logo] = bool(settings[logo])
        return settings

    # ------------------------------------------------------------------ #
    # Writes
    # ------------------------------------------------------------------ #

    def _set_activation(self, operation: str, ids: list[str], error_message: str) -> dict[str, Any] | list[Any]:
        agent_ids, problem = _clean(ids, UUID_PATTERN, "agent ID")
        if problem or not agent_ids:
            return _error(problem or "Give at least one agent ID.", operation)
        response = self.client.command(operation, body={"ids": agent_ids})
        result: dict[str, Any] | list[Any] = handle_api_response(
            response, operation=operation, error_message=error_message
        )
        return result

    def activate_browser_agents(
        self,
        ids: list[str] = Field(description=f"Agent IDs (UUIDs) to activate, at most {MAX_IDS}."),
    ) -> dict[str, Any] | list[Any]:
        """Activate Seraphic Enterprise Browser agents by ID, reversing falcon_deactivate_browser_agents."""
        return self._set_activation("ActivateAgents", ids, "Failed to activate the browser agents")

    def deactivate_browser_agents(
        self,
        ids: list[str] = Field(description=f"Agent IDs (UUIDs) to deactivate, at most {MAX_IDS}."),
    ) -> dict[str, Any] | list[Any]:
        """Deactivate Seraphic Enterprise Browser agents by ID. Reverse it with falcon_activate_browser_agents.

        Only the IDs given are changed; this tool never acts on a filter.
        """
        return self._set_activation("DeactivateAgents", ids, "Failed to deactivate the browser agents")

    def run_browser_agent_tasks(
        self,
        agent_id: str = Field(description="The agent ID (UUID) to send the tasks to."),
        actions: list[AgentTask] = Field(
            description=(
                "Tasks to queue, run in the order given: close_all_windows, refresh_all_tabs "
                "or remove_browsing_data."
            ),
        ),
        ttl_hours: int = Field(
            default=72,
            ge=1,
            le=168,
            description="Hours the tasks wait for the agent to come online before expiring, 1-168. Default 72.",
        ),
    ) -> dict[str, Any] | list[Any]:
        """Queue response tasks on a Seraphic browser agent: close every window, refresh every tab or remove browsing data.

        Use it to respond to a compromised browser session, for example removing
        browsing data after credential theft. Closing windows can lose a user's
        unsaved work, and removing browsing data deletes it. The agent runs the
        tasks when it next checks in.
        """
        operation = "ApplyAgentTasks"
        agent_ids, problem = _clean([agent_id] if isinstance(agent_id, str) else [], UUID_PATTERN, "agent ID")
        if problem or not agent_ids:
            return _error(problem or "Give the agent ID.", operation)
        chosen: list[str] = []
        for action in actions or []:
            if action not in ("close_all_windows", "refresh_all_tabs", "remove_browsing_data"):
                return _error(f"Unsupported task {action!r}.", operation)
            if action not in chosen:
                chosen.append(action)
        if not chosen:
            return _error("Give at least one task.", operation)
        body = {"actions": [{"action": a, "args": []} for a in chosen], "ttlHours": ttl_hours}
        logger.debug("Queueing %d browser task(s) on one agent", len(chosen))
        response = self.client.command(operation, parameters={"agent_id": agent_ids[0]}, body=body)
        result: dict[str, Any] | list[Any] = handle_api_response(
            response, operation=operation, error_message="Failed to queue the browser agent tasks"
        )
        return result

    # ------------------------------------------------------------------ #
    # Destination groups and sensitive data profiles: reads
    # ------------------------------------------------------------------ #

    def _search_policy_objects(
        self,
        query_operation: str,
        get_operation: str,
        name: str | None,
        description: str | None,
        created_by: str | None,
        search: str | None,
        sort_by: str,
        sort_order: str,
        limit: int,
        offset: int,
        error_message: str,
        unwrap: Any = None,
    ) -> dict[str, Any]:
        filters: dict[str, Any] = {}
        for key, value in (("name", name), ("description", description), ("created_by", created_by)):
            if isinstance(value, str) and value.strip():
                if CONTROL_CHARS.search(value):
                    return _error(f"{key} can't contain control characters.", query_operation)
                filters[key] = [value.strip()]
        body: dict[str, Any] = {
            "limit": limit,
            "skip": offset,
            "sort": [{"field": sort_by, "order": sort_order.upper()}],
        }
        if filters:
            body["filter"] = filters
        if search is not None and search.strip():
            if CONTROL_CHARS.search(search):
                return _error("search can't contain control characters.", query_operation)
            body["search"] = search.strip()
        result = self._query_then_get(query_operation, body, get_operation, error_message, unwrap=unwrap)
        if isinstance(result, dict):
            return result
        records, total = result
        return self._build_pagination_envelope(records, {"total": total, "offset": offset, "limit": limit})

    def search_browser_destination_groups(
        self,
        name: str | None = Field(
            default=None, description="An exact group name; use search to match part of one."
        ),
        description: str | None = Field(default=None, description="An exact group description."),
        created_by: str | None = Field(
            default=None, description="Who created the group; Seraphic for the built-in groups."
        ),
        search: str | None = Field(default=None, description="Free text matched against group names."),
        sort_by: PolicySortField = Field(default="name", description="Field to sort by."),
        sort_order: Literal["asc", "desc"] = Field(default="asc", description="asc or desc."),
        limit: int = Field(default=100, ge=1, le=MAX_LIMIT, description=f"[1-{MAX_LIMIT}]"),
        offset: int = Field(default=0, ge=0, description="The number of groups to skip."),
    ) -> dict[str, Any]:
        """Search Seraphic Enterprise Browser destination groups: the named sets of sites the browser allows or blocks.

        Each group has `id`, `name`, `description`, `domains` (wildcards such as
        *.example.com allowed), `singleIps` (addresses or CIDR ranges), `ipsRange`,
        `countries`, `classification` (site categories such as Gambling or AI
        Related), `default` (true for Seraphic's built-in groups) and a usage count.
        The tenant's own groups come first and Seraphic's built-in ones after them,
        each part sorted by `sort_by`.
        """
        return self._search_policy_objects(
            "QueryDestinationGroups", "GetDestinationGroups", name, description, created_by, search,
            sort_by, sort_order, limit, offset, "Failed to search browser destination groups",
        )

    def get_browser_destination_groups(
        self,
        ids: list[str] = Field(description=f"Destination group IDs (UUIDs), at most {MAX_IDS}."),
    ) -> dict[str, Any]:
        """Get Seraphic Enterprise Browser destination groups by ID, with the IDs that matched no group in `not_found`."""
        operation = "GetDestinationGroups"
        group_ids, problem = _clean(ids, UUID_PATTERN, "destination group ID")
        if problem or not group_ids:
            return _error(problem or "Give at least one destination group ID.", operation)
        return self._get_by_ids(operation, group_ids, "Failed to get browser destination groups")

    def search_browser_data_profiles(
        self,
        name: str | None = Field(
            default=None, description="An exact profile name; use search to match part of one."
        ),
        description: str | None = Field(default=None, description="An exact profile description."),
        created_by: str | None = Field(default=None, description="Who created the profile."),
        search: str | None = Field(default=None, description="Free text matched against profile names."),
        sort_by: PolicySortField = Field(default="name", description="Field to sort by."),
        sort_order: Literal["asc", "desc"] = Field(default="asc", description="asc or desc."),
        limit: int = Field(default=100, ge=1, le=MAX_LIMIT, description=f"[1-{MAX_LIMIT}]"),
        offset: int = Field(default=0, ge=0, description="The number of profiles to skip."),
    ) -> dict[str, Any]:
        """Search Seraphic Enterprise Browser sensitive data profiles: the patterns browser DLP looks for.

        Each profile has `id`, `name`, `description`, `custom_regex` (name, regex
        and threshold), `predefined_piis` (CrowdStrike's built-in detectors),
        `apply_exact_match`, who created it, and what uses it.
        """
        return self._search_policy_objects(
            "QuerySensitiveDataProfiles", "GetSensitiveDataProfiles", name, description, created_by,
            search, sort_by, sort_order, limit, offset, "Failed to search browser sensitive data profiles",
            unwrap=_flatten_profile,
        )

    def get_browser_data_profiles(
        self,
        ids: list[str] = Field(description=f"Sensitive data profile IDs (UUIDs), at most {MAX_IDS}."),
    ) -> dict[str, Any]:
        """Get Seraphic Enterprise Browser sensitive data profiles by ID, with what uses each and IDs that matched nothing in `not_found`."""
        operation = "GetSensitiveDataProfiles"
        profile_ids, problem = _clean(ids, UUID_PATTERN, "sensitive data profile ID")
        if problem or not profile_ids:
            return _error(problem or "Give at least one sensitive data profile ID.", operation)
        return self._get_by_ids(
            operation, profile_ids, "Failed to get browser sensitive data profiles", unwrap=_flatten_profile
        )

    # ------------------------------------------------------------------ #
    # Destination groups and sensitive data profiles: writes
    # ------------------------------------------------------------------ #

    def _fetch_one(
        self, operation: str, record_id: str, label: str, unwrap: Any = None
    ) -> dict[str, Any] | str:
        """Fetch one record before changing it. Returns the record, or a problem string."""
        found = self._get_by_ids(operation, [record_id], f"Failed to read the {label}", unwrap=unwrap)
        if "error" in found:
            return str(found["error"])
        records = found.get("found") or []
        if not records:
            return f"No {label} has ID {record_id}."
        record: dict[str, Any] = records[0]
        return record

    def _send(
        self, operation: str, error_message: str, **kwargs: Any
    ) -> dict[str, Any] | list[Any]:
        response = self.client.command(operation, **kwargs)
        result: dict[str, Any] | list[Any] = handle_api_response(
            response, operation=operation, error_message=error_message
        )
        return result

    def create_browser_destination_group(
        self,
        name: str = Field(description="Name for the new destination group."),
        description: str | None = Field(default=None, description="What the group is for."),
        domains: list[str] | None = Field(
            default=None,
            description="Domains or URL patterns, e.g. example.com, *.example.com or https://example.com/path*.",
        ),
        single_ips: list[str] | None = Field(
            default=None, description="IP addresses or CIDR ranges, e.g. 203.0.113.7 or 198.51.100.0/24."
        ),
        countries: list[str] | None = Field(
            default=None, description="Two-letter country codes, e.g. CN."
        ),
        classifications: list[str] | None = Field(
            default=None,
            description="Site categories as Seraphic names them, e.g. Gambling, File Sharing, AI Related.",
        ),
    ) -> dict[str, Any] | list[Any]:
        """Create a Seraphic Enterprise Browser destination group, a named set of sites for browser rules to allow or block.

        Give at least one of domains, single_ips, countries or classifications. The
        group does nothing until it is attached in the console.
        """
        operation = "CreateDestinationGroup"
        clean_name = (name or "").strip()
        if not 0 < len(clean_name) <= 200 or CONTROL_CHARS.search(clean_name):
            return _error("name must be 1-200 characters with no control characters.", operation)
        body: dict[str, Any] = {"name": clean_name}
        if description is not None and description.strip():
            if len(description) > 1000 or CONTROL_CHARS.search(description):
                return _error("description must be at most 1000 characters with no control characters.", operation)
            body["description"] = description.strip()
        for param, values in (
            ("domains", domains),
            ("single_ips", single_ips),
            ("countries", countries),
            ("classifications", classifications),
        ):
            items, problem = _clean_items(values, param, param)
            if problem:
                return _error(problem, operation)
            if items:
                body[_GROUP_LISTS[param]] = items
        if len(body) == 1 + ("description" in body):
            return _error("Give at least one of domains, single_ips, countries or classifications.", operation)
        return self._send(operation, "Failed to create the destination group", body=body)

    def update_browser_destination_group(
        self,
        id: str = Field(description="The destination group ID (UUID)."),
        name: str | None = Field(default=None, description="A new name."),
        description: str | None = Field(default=None, description="A new description."),
        add_domains: list[str] | None = Field(default=None, description="Domains to add."),
        remove_domains: list[str] | None = Field(default=None, description="Domains to remove."),
        add_single_ips: list[str] | None = Field(default=None, description="IP addresses or CIDR ranges to add."),
        remove_single_ips: list[str] | None = Field(default=None, description="IP addresses or CIDR ranges to remove."),
        add_countries: list[str] | None = Field(default=None, description="Two-letter country codes to add."),
        remove_countries: list[str] | None = Field(default=None, description="Two-letter country codes to remove."),
        add_classifications: list[str] | None = Field(default=None, description="Site categories to add."),
        remove_classifications: list[str] | None = Field(default=None, description="Site categories to remove."),
    ) -> dict[str, Any] | list[Any]:
        """Add or remove sites in a Seraphic Enterprise Browser destination group, or rename it.

        The tool reads the group, applies the additions and removals, and sends the
        resulting lists, so entries not named stay as they are. The change applies
        wherever the group is used. Seraphic's built-in groups can't be changed here.
        """
        operation = "UpdateDestinationGroup"
        group_ids, problem = _clean([id] if isinstance(id, str) else [], UUID_PATTERN, "destination group ID")
        if problem or not group_ids:
            return _error(problem or "Give the destination group ID.", operation)
        changes: dict[str, tuple[list[str], list[str]]] = {}
        for param, adds, removes in (
            ("domains", add_domains, remove_domains),
            ("single_ips", add_single_ips, remove_single_ips),
            ("countries", add_countries, remove_countries),
            ("classifications", add_classifications, remove_classifications),
        ):
            add_items, problem = _clean_items(adds, f"add_{param}", param)
            remove_items, problem2 = _clean_items(removes, f"remove_{param}", param)
            if problem or problem2:
                return _error(str(problem or problem2), operation)
            if add_items or remove_items:
                changes[param] = (add_items, remove_items)
        body: dict[str, Any] = {}
        if name is not None and name.strip():
            if len(name.strip()) > 200 or CONTROL_CHARS.search(name):
                return _error("name must be 1-200 characters with no control characters.", operation)
            body["name"] = name.strip()
        if description is not None and description.strip():
            if len(description) > 1000 or CONTROL_CHARS.search(description):
                return _error("description must be at most 1000 characters with no control characters.", operation)
            body["description"] = description.strip()
        if not changes and not body:
            return _error("Give a new name or description, or entries to add or remove.", operation)

        group = self._fetch_one("GetDestinationGroups", group_ids[0], "destination group")
        if isinstance(group, str):
            return _error(group, operation)
        if group.get("default"):
            return _error("This is one of Seraphic's built-in destination groups, which this tool doesn't change.", operation)
        for param, (add_items, remove_items) in changes.items():
            field = _GROUP_LISTS[param]
            current = [str(v) for v in group.get(field) or []]
            removing = {v.lower() for v in remove_items}
            updated = [v for v in current if v.lower() not in removing]
            updated += [v for v in add_items if v.lower() not in {u.lower() for u in updated}]
            if len(updated) > MAX_LIST_ITEMS:
                return _error(f"The group would hold more than {MAX_LIST_ITEMS} {param}.", operation)
            if updated != current:
                body[field] = updated
        if not body:
            return {"id": group_ids[0], "changed": False, "message": "The group already matches; nothing was sent."}
        logger.debug("Updating destination group fields: %s", sorted(body))
        return self._send(
            operation, "Failed to update the destination group", parameters={"id": group_ids[0]}, body=body
        )

    def delete_browser_destination_group(
        self,
        id: str = Field(description="The destination group ID (UUID) to delete."),
    ) -> dict[str, Any] | list[Any]:
        """Delete a Seraphic Enterprise Browser destination group. This cannot be undone.

        Refuses Seraphic's built-in groups and groups still in use; detach the
        group first.
        """
        operation = "DeleteDestinationGroup"
        group_ids, problem = _clean([id] if isinstance(id, str) else [], UUID_PATTERN, "destination group ID")
        if problem or not group_ids:
            return _error(problem or "Give the destination group ID.", operation)
        group = self._fetch_one("GetDestinationGroups", group_ids[0], "destination group")
        if isinstance(group, str):
            return _error(group, operation)
        if group.get("default"):
            return _error("This is one of Seraphic's built-in destination groups, which this tool doesn't delete.", operation)
        linked = group.get("linked_rules")
        if isinstance(linked, int) and linked > 0:
            return _error(f"{linked} rule(s) still use this group. Remove it from them before deleting it.", operation)
        return self._send(operation, "Failed to delete the destination group", parameters={"id": group_ids[0]})

    def create_browser_data_profile(
        self,
        name: str = Field(description="Name for the new profile, at least 2 characters."),
        custom_regex: list[dict[str, Any]] = Field(
            description=(
                "Patterns to detect, each {name, regex, threshold}: threshold is the number "
                "of matches that count as a hit, 1 by default. At most 100."
            ),
        ),
        description: str | None = Field(default=None, description="What the profile detects."),
        apply_exact_match: bool | None = Field(
            default=None, description="True to report only exact regex matches; false for all matches."
        ),
    ) -> dict[str, Any] | list[Any]:
        """Create a Seraphic Enterprise Browser sensitive data profile from custom regexes, for browser DLP rules to detect.

        The profile does nothing until it is attached in the console. CrowdStrike's
        predefined PII detectors aren't offered here, because their names aren't
        documented.
        """
        operation = "CreateSensitiveDataProfile"
        clean_name = (name or "").strip()
        if not 2 <= len(clean_name) <= 200 or CONTROL_CHARS.search(clean_name):
            return _error("name must be 2-200 characters with no control characters.", operation)
        regexes, problem = _clean_regexes(custom_regex)
        if problem:
            return _error(problem, operation)
        if not regexes:
            return _error("Give at least one custom_regex entry.", operation)
        body: dict[str, Any] = {"name": clean_name, "custom_regex": regexes}
        if description is not None and description.strip():
            if len(description) > 1000 or CONTROL_CHARS.search(description):
                return _error("description must be at most 1000 characters with no control characters.", operation)
            body["description"] = description.strip()
        if apply_exact_match is not None:
            body["apply_exact_match"] = apply_exact_match
        return self._send(operation, "Failed to create the sensitive data profile", body=body)

    def update_browser_data_profile(
        self,
        id: str = Field(description="The sensitive data profile ID (UUID)."),
        name: str | None = Field(default=None, description="A new name."),
        description: str | None = Field(default=None, description="A new description."),
        add_custom_regex: list[dict[str, Any]] | None = Field(
            default=None,
            description="Patterns to add, each {name, regex, threshold}; one with an existing name replaces it.",
        ),
        remove_custom_regex: list[str] | None = Field(
            default=None, description="Names of custom regexes to remove."
        ),
        apply_exact_match: bool | None = Field(
            default=None, description="True to report only exact regex matches; false for all matches."
        ),
    ) -> dict[str, Any] | list[Any]:
        """Add, replace or remove the regexes in a Seraphic Enterprise Browser sensitive data profile, or rename it.

        The tool reads the profile, applies the changes and sends the resulting regex
        list, so regexes not named stay as they are. The change applies wherever
        the profile is used.
        """
        operation = "UpdateSensitiveDataProfile"
        profile_ids, problem = _clean([id] if isinstance(id, str) else [], UUID_PATTERN, "sensitive data profile ID")
        if problem or not profile_ids:
            return _error(problem or "Give the sensitive data profile ID.", operation)
        adds, problem = _clean_regexes(add_custom_regex)
        if problem:
            return _error(problem, operation)
        removes = [r.strip() for r in remove_custom_regex or [] if isinstance(r, str) and r.strip()]
        body: dict[str, Any] = {}
        if name is not None and name.strip():
            if not 2 <= len(name.strip()) <= 200 or CONTROL_CHARS.search(name):
                return _error("name must be 2-200 characters with no control characters.", operation)
            body["name"] = name.strip()
        if description is not None and description.strip():
            if len(description) > 1000 or CONTROL_CHARS.search(description):
                return _error("description must be at most 1000 characters with no control characters.", operation)
            body["description"] = description.strip()
        if apply_exact_match is not None:
            body["apply_exact_match"] = apply_exact_match
        if not body and not adds and not removes:
            return _error("Give a new name, description or apply_exact_match, or regexes to add or remove.", operation)

        if adds or removes:
            profile = self._fetch_one(
                "GetSensitiveDataProfiles", profile_ids[0], "sensitive data profile", unwrap=_flatten_profile
            )
            if isinstance(profile, str):
                return _error(profile, operation)
            current = [r for r in profile.get("custom_regex") or [] if isinstance(r, dict)]
            names = {str(r.get("name")) for r in current}
            missing = [n for n in removes if n not in names]
            if missing:
                return _error(f"The profile has no custom regex named {missing[:5]}.", operation)
            replaced = {r["name"] for r in adds}
            updated = [
                {"name": r.get("name"), "regex": r.get("regex"), "threshold": r.get("threshold")}
                for r in current
                if r.get("name") not in removes and r.get("name") not in replaced
            ] + adds
            if not updated and not profile.get("predefined_piis"):
                return _error("That would leave the profile with nothing to detect. Delete it instead.", operation)
            if len(updated) > MAX_REGEXES:
                return _error(f"The profile would hold more than {MAX_REGEXES} custom regexes.", operation)
            body["custom_regex"] = updated
        return self._send(
            operation, "Failed to update the sensitive data profile", parameters={"id": profile_ids[0]}, body=body
        )

    def delete_browser_data_profile(
        self,
        id: str = Field(description="The sensitive data profile ID (UUID) to delete."),
    ) -> dict[str, Any] | list[Any]:
        """Delete a Seraphic Enterprise Browser sensitive data profile. This cannot be undone.

        Refuses a profile still in use; detach it first.
        """
        operation = "DeleteSensitiveDataProfile"
        profile_ids, problem = _clean([id] if isinstance(id, str) else [], UUID_PATTERN, "sensitive data profile ID")
        if problem or not profile_ids:
            return _error(problem or "Give the sensitive data profile ID.", operation)
        profile = self._fetch_one(
            "GetSensitiveDataProfiles", profile_ids[0], "sensitive data profile", unwrap=_flatten_profile
        )
        if isinstance(profile, str):
            return _error(profile, operation)
        rules = profile.get("related_rules") or []
        if rules:
            names = [str(r.get("displayName") or r.get("name")) for r in rules if isinstance(r, dict)][:5]
            return _error(f"{len(rules)} rule(s) still use this profile ({', '.join(names)}). Remove it from them first.", operation)
        return self._send(
            operation, "Failed to delete the sensitive data profile", parameters={"id": profile_ids[0]}
        )

    # ------------------------------------------------------------------ #
    # Rule writes
    # ------------------------------------------------------------------ #

    def set_browser_rule_status(
        self,
        id: str = Field(description="The numeric rule ID."),
        status: RuleStatus = Field(description="active to enforce the rule, inactive to stop enforcing it."),
    ) -> dict[str, Any] | list[Any]:
        """Turn a Seraphic Enterprise Browser policy rule on or off by setting its status to active or inactive.

        Setting a protection or DLP rule inactive stops the browser enforcing it for
        everyone it targets. Read the rule with falcon_get_browser_rules first.
        """
        operation = "UpdateRuleMixin0"
        rule_ids, problem = _clean([str(id)] if id is not None else [], RULE_ID_PATTERN, "rule ID")
        if problem or not rule_ids:
            return _error(problem or "Give the rule ID.", operation)
        rule = self._fetch_one("GetRules", rule_ids[0], "rule")
        if isinstance(rule, str):
            return _error(rule, operation)
        if rule.get("status") == status:
            return {"id": rule_ids[0], "changed": False, "message": f"The rule is already {status}; nothing was sent."}
        return self._send(
            operation, "Failed to change the rule's status", parameters={"id": rule_ids[0]}, body={"status": status}
        )

    def update_browser_rule_extensions(
        self,
        id: str = Field(description="The numeric ID of a rule in the extensions category."),
        add_extension_ids: list[str] | None = Field(default=None, description="Store extension IDs to add."),
        remove_extension_ids: list[str] | None = Field(default=None, description="Store extension IDs to remove."),
        add_extension_names: list[str] | None = Field(default=None, description="Extension names to add."),
        remove_extension_names: list[str] | None = Field(default=None, description="Extension names to remove."),
    ) -> dict[str, Any] | list[Any]:
        """Add or remove browser extensions on a Seraphic Enterprise Browser extension rule's list.

        Whether the listed extensions are blocked or allowed depends on the rule, so
        read it with falcon_get_browser_rules first. Check an extension with
        falcon_get_browser_extension_analysis before allowing it. The API applies each
        kind of change separately, so the tool sends one call per kind and stops at
        the first failure; `applied` lists what went through.
        """
        operation = "UpdateRuleMixin0"
        rule_ids, problem = _clean([str(id)] if id is not None else [], RULE_ID_PATTERN, "rule ID")
        if problem or not rule_ids:
            return _error(problem or "Give the rule ID.", operation)
        changes: list[tuple[str, list[str]]] = []
        for param, values in (
            ("add_extension_ids", add_extension_ids),
            ("remove_extension_ids", remove_extension_ids),
            ("add_extension_names", add_extension_names),
            ("remove_extension_names", remove_extension_names),
        ):
            pattern = EXTENSION_ID_PATTERN if param.endswith("_ids") else None
            items: list[str] = []
            for raw in values or []:
                value = raw.strip() if isinstance(raw, str) else ""
                valid = bool(pattern.fullmatch(value)) if pattern else 0 < len(value) <= 200 and not CONTROL_CHARS.search(value)
                if not valid:
                    return _error(f"Invalid entry in {param}: {raw!r}.", operation)
                if value not in items:
                    items.append(value)
            if len(items) > MAX_IDS:
                return _error(f"At most {MAX_IDS} entries in {param}.", operation)
            if items:
                changes.append((param, items))
        if not changes:
            return _error("Give extension IDs or names to add or remove.", operation)
        rule = self._fetch_one("GetRules", rule_ids[0], "rule")
        if isinstance(rule, str):
            return _error(rule, operation)
        if rule.get("category") != "extensions":
            return _error(
                f"Rule {rule_ids[0]} is in the {rule.get('category')!r} category; extension lists belong to "
                "rules in the extensions category.",
                operation,
            )
        applied: list[str] = []
        for param, items in changes:
            result = self._send(
                operation,
                f"Failed to apply {param}",
                parameters={"id": rule_ids[0]},
                body={_EXTENSION_CHANGES[param]: items},
            )
            if isinstance(result, dict) and "error" in result:
                return {**result, "applied": applied, "not_applied": [p for p, _ in changes if p not in applied]}
            applied.append(param)
        return {"id": rule_ids[0], "applied": applied}
