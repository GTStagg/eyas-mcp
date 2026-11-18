"""
Browser module for Falcon MCP Server

This module provides tools for Falcon Seraphic Enterprise Browser: search the browser
agents running in users' browsers, read the browser policy rules, check a browser
extension's risk analysis and read the tenant's Seraphic settings; activate or deactivate
agents; and queue response tasks on an agent, such as closing every window or removing
browsing data.
"""

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
    ) -> tuple[list[dict[str, Any]], int | None] | dict[str, Any]:
        """Query IDs, fetch their records in batches and return them in the query's order."""
        kwargs: dict[str, Any] = {"body": query_body}
        if query_parameters:
            kwargs["parameters"] = query_parameters
        response = self.client.command(query_operation, **kwargs)
        if (response.get("status_code") or 0) >= 300:
            error: dict[str, Any] = handle_api_response(
                response, operation=query_operation, error_message=error_message
            )
            return error
        ids = [str(i) for i in _resources(response)]
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
        return self._reorder_by_ids(ids, records, id_field="id"), total

    def _get_by_ids(
        self, operation: str, ids: list[str], error_message: str
    ) -> dict[str, Any]:
        """Fetch records by ID and split the IDs that matched nothing into `not_found`."""
        response = self.client.command(operation, parameters={"ids": ids})
        if (response.get("status_code") or 0) >= 300:
            error: dict[str, Any] = handle_api_response(
                response, operation=operation, error_message=error_message
            )
            return error
        found = [r for r in _resources(response) if isinstance(r, dict)]
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
