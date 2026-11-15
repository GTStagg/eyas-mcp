"""
Intel module for Falcon MCP Server

This module provides tools for accessing and analyzing CrowdStrike Falcon intelligence data.
"""

import json
from typing import Any, Literal

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from pydantic import AnyUrl, Field

from falcon_mcp.common.logging import get_logger
from falcon_mcp.common.truncate import clip_long_strings
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.intel import (
    QUERY_ACTOR_ENTITIES_FQL_DOCUMENTATION,
    QUERY_INDICATOR_ENTITIES_FQL_DOCUMENTATION,
    QUERY_REPORT_ENTITIES_FQL_DOCUMENTATION,
    QUERY_VULNERABILITIES_FQL_DOCUMENTATION,
)

logger = get_logger(__name__)

# Finished intelligence is the point of the full-content tools, so the default is
# generous, but one long report must not crowd out the rest of the context.
_DEFAULT_FULL_TEXT_CHARS = 20000
_MAX_FULL_TEXT_CHARS = 200000
_RICH_TEXT_PREFIX = "rich_text_"

# CVE records list every affected product and linked report; a few CVEs list hundreds
_MAX_AFFECTED_PRODUCTS = 25
_MAX_RELATED_REPORTS = 20
_MAX_SEARCH = 100
_MAX_MALWARE_NAMES = 20
_MAX_MALWARE_REPORTS = 10
# Characters that would end or extend a quoted FQL value
_FQL_SPECIAL = frozenset("'\"\\")

def _trim_cve(record: dict[str, Any]) -> dict[str, Any]:
    """Cap the long lists on a CVE record and say how many were left out."""
    trimmed = dict(record)
    for key, cap in (("affected_products", _MAX_AFFECTED_PRODUCTS), ("related_reports", _MAX_RELATED_REPORTS)):
        values = record.get(key)
        if isinstance(values, list) and len(values) > cap:
            trimmed[key] = values[:cap]
            trimmed[f"{key}_total"] = len(values)
    return trimmed


def _trim_malware(record: dict[str, Any], max_text_chars: int) -> dict[str, Any]:
    """Shrink a malware family profile: cap its report list and flatten its ATT&CK mapping.

    A well-known family's profile runs to tens of kilobytes, almost all of it the
    list of related reports and the reports nested inside each ATT&CK technique.
    """
    trimmed = _drop_rich_text_duplicates(record)
    reports = record.get("reports")
    if isinstance(reports, list) and len(reports) > _MAX_MALWARE_REPORTS:
        trimmed["reports"] = reports[:_MAX_MALWARE_REPORTS]
        trimmed["reports_total"] = len(reports)
    techniques: dict[str, dict[str, Any]] = {}
    for entry in record.get("mitre") or []:
        if isinstance(entry, dict):
            key = str(entry.get("attack_id") or entry.get("technique_id"))
            techniques.setdefault(
                key,
                {
                    "technique_id": entry.get("technique_id"),
                    "technique_name": entry.get("technique_name"),
                    "tactic_id": entry.get("tactic_id"),
                    "tactic_name": entry.get("tactic_name"),
                },
            )
    if "mitre" in record:
        trimmed["mitre"] = list(techniques.values())
    clipped: dict[str, Any] = clip_long_strings(trimmed, max_text_chars)
    return clipped


def _drop_rich_text_duplicates(record: dict[str, Any]) -> dict[str, Any]:
    """Drop `rich_text_<field>` keys whose plain `<field>` counterpart has text.

    Intel entities carry some narrative fields twice, once as plain text and once
    as HTML under a `rich_text_` prefix. The HTML copy doubles the size and adds
    nothing a reader needs, so keep it only when the plain field is empty.
    """
    return {
        key: value
        for key, value in record.items()
        if not (key.startswith(_RICH_TEXT_PREFIX) and record.get(key[len(_RICH_TEXT_PREFIX) :]))
    }


class IntelModule(BaseModule):
    """Module for accessing and analyzing CrowdStrike Falcon intelligence data."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        # Register tools
        self._add_tool(
            server=server,
            method=self.query_actor_entities,
            name="search_actors",
        )

        self._add_tool(
            server=server,
            method=self.query_indicator_entities,
            name="search_indicators",
        )

        self._add_tool(
            server=server,
            method=self.query_report_entities,
            name="search_reports",
        )

        self._add_tool(
            server=server,
            method=self.get_mitre_report,
            name="get_mitre_report",
        )

        self._add_tool(
            server=server,
            method=self.get_intel_reports,
            name="get_intel_reports",
        )

        self._add_tool(
            server=server,
            method=self.get_intel_actors,
            name="get_intel_actors",
        )
        self._add_tool(
            server=server,
            method=self.search_intel_vulnerabilities,
            name="search_intel_vulnerabilities",
        )
        self._add_tool(
            server=server,
            method=self.search_malware_families,
            name="search_malware_families",
        )
        self._add_tool(
            server=server,
            method=self.search_intel_rules,
            name="search_intel_rules",
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP server.

        Args:
            server: MCP server instance
        """
        search_actors_fql_resource = TextResource(
            uri=AnyUrl("falcon://intel/actors/fql-guide"),
            name="falcon_search_actors_fql_guide",
            description=(
                "Contains the guide for the `filter` param of the "
                "`falcon_search_actors` tool."
            ),
            text=QUERY_ACTOR_ENTITIES_FQL_DOCUMENTATION,
        )

        search_indicators_fql_resource = TextResource(
            uri=AnyUrl("falcon://intel/indicators/fql-guide"),
            name="falcon_search_indicators_fql_guide",
            description=(
                "Contains the guide for the `filter` param of the "
                "`falcon_search_indicators` tool."
            ),
            text=QUERY_INDICATOR_ENTITIES_FQL_DOCUMENTATION,
        )

        search_reports_fql_resource = TextResource(
            uri=AnyUrl("falcon://intel/reports/fql-guide"),
            name="falcon_search_reports_fql_guide",
            description=(
                "Contains the guide for the `filter` param of the "
                "`falcon_search_reports` tool."
            ),
            text=QUERY_REPORT_ENTITIES_FQL_DOCUMENTATION,
        )

        self._add_resource(
            server,
            search_actors_fql_resource,
        )
        self._add_resource(
            server,
            search_indicators_fql_resource,
        )
        self._add_resource(
            server,
            search_reports_fql_resource,
        )
        self._add_resource(
            server,
            TextResource(
                uri=AnyUrl("falcon://intel/vulnerabilities/fql-guide"),
                name="falcon_search_intel_vulnerabilities_fql_guide",
                description=(
                    "Contains the guide for the `filter` param of the "
                    "`falcon_search_intel_vulnerabilities` tool."
                ),
                text=QUERY_VULNERABILITIES_FQL_DOCUMENTATION,
            ),
        )

    def query_actor_entities(
        self,
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter expression. See `falcon://intel/actors/fql-guide` for syntax."
            ),
        ),
        limit: int = Field(
            default=10,
            ge=1,
            le=5000,
            description="Maximum number of records to return. Max 5000",
            examples=[10, 20, 100],
        ),
        offset: int | None = Field(
            default=None,
            description="Starting index of overall result set from which to return ids.",
            examples=[0, 10],
        ),
        sort: str | None = Field(
            default=None,
            description=(
                "The field and direction to sort results on. The format is "
                "{field}.{asc/desc}. Valid values include: name, target_countries, "
                "target_industries, type, created_date, last_activity_date and "
                "last_modified_date. Prefer the dot separator, supported on every "
                "Falcon sort endpoint. Ex: created_date.desc"
            ),
            examples=["created_date.desc"],
        ),
        q: str | None = Field(
            default=None,
            description="Free text search across all indexed fields.",
            examples=["BEAR"],
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Research threat actors and adversary groups tracked by CrowdStrike intelligence.

        Use this to search actors by name, target countries/industries, or activity dates.
        Consult falcon://intel/actors/fql-guide before constructing filter expressions.
        Returns full actor profiles including aliases, motivations, and targeting details.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        api_response, pagination = self._base_search_with_meta(
            operation="QueryIntelActorEntities",
            search_params={
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
                "q": q,
            },
            error_message="Failed to search actors",
        )

        if self._is_error(api_response):
            return self._format_fql_error_response(
                [api_response], filter, QUERY_ACTOR_ENTITIES_FQL_DOCUMENTATION
            )

        return self._build_pagination_envelope(api_response or [], pagination, filter)

    def query_indicator_entities(
        self,
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter expression. See `falcon://intel/indicators/fql-guide` "
                "for syntax."
            ),
        ),
        limit: int = Field(
            default=10,
            ge=1,
            le=5000,
            description="Maximum number of records to return. (Max: 5000)",
        ),
        offset: int | None = Field(
            default=None,
            description="Starting index of overall result set from which to return ids.",
        ),
        sort: str | None = Field(
            default=None,
            description=(
                "The field and direction to sort results on. The format is "
                "{field}.{asc/desc}. Valid values are: id, indicator, type, "
                "published_date, last_updated, and _marker. Prefer the dot "
                "separator, supported on every Falcon sort endpoint. Ex: "
                "published_date.desc"
            ),
            examples=["published_date.desc"],
        ),
        q: str | None = Field(
            default=None,
            description="Free text search across all indexed fields.",
        ),
        include_deleted: bool = Field(
            default=False,
            description=(
                "Flag indicating if both published and deleted indicators "
                "should be returned."
            ),
        ),
        include_relations: bool = Field(
            default=False,
            description=(
                "Flag indicating if related indicators should be returned."
            ),
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search for threat indicators and IOCs from CrowdStrike intelligence.

        Use this to find indicators by type, publish date, malware family, or threat actor
        association. Consult falcon://intel/indicators/fql-guide before constructing filter
        expressions. Returns full indicator details including labels, relations, and kill
        chain stage.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        api_response, pagination = self._base_search_with_meta(
            operation="QueryIntelIndicatorEntities",
            search_params={
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
                "q": q,
                "include_deleted": include_deleted,
                "include_relations": include_relations,
            },
            error_message="Failed to search indicators",
        )

        if self._is_error(api_response):
            return self._format_fql_error_response(
                [api_response], filter, QUERY_INDICATOR_ENTITIES_FQL_DOCUMENTATION
            )

        return self._build_pagination_envelope(api_response or [], pagination, filter)

    def query_report_entities(
        self,
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter expression. See `falcon://intel/reports/fql-guide` for syntax."
            ),
        ),
        limit: int = Field(
            default=10,
            ge=1,
            le=5000,
            description="Maximum number of records to return. (Max: 5000)",
        ),
        offset: int | None = Field(
            default=None,
            description="Starting index of overall result set from which to return ids.",
        ),
        sort: str | None = Field(
            default=None,
            description=(
                "The field and direction to sort results on in the format of: "
                "{field}.{asc}or {field}.{desc}. Valid values include: name, "
                "target_countries, target_industries, type, created_date, "
                "last_modified_date. Ex: created_date.desc"
            ),
            examples=["created_date.desc"],
        ),
        q: str | None = Field(
            default=None,
            description="Free text search across all indexed fields.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search CrowdStrike intelligence publications and threat reports.

        Use this to find reports by name, target industry, threat type, or publication date.
        Consult falcon://intel/reports/fql-guide before constructing filter expressions.
        Returns full report metadata including title, description, and target details.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        api_response, pagination = self._base_search_with_meta(
            operation="QueryIntelReportEntities",
            search_params={
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
                "q": q,
            },
            error_message="Failed to search reports",
        )

        if self._is_error(api_response):
            return self._format_fql_error_response(
                [api_response], filter, QUERY_REPORT_ENTITIES_FQL_DOCUMENTATION
            )

        return self._build_pagination_envelope(api_response or [], pagination, filter)

    def get_mitre_report(
        self,
        actor: str = Field(
            ...,
            description="Threat actor name or ID",
            examples=["WARP PANDA", "234987", "revenant spider"],
        ),
        format: str = Field(
            default="json",
            description="Report format. Accepted options: 'csv' or 'json'.",
            examples=["json", "csv"],
        ),
    ) -> list[dict[str, Any]] | str:
        """Generate a MITRE ATT&CK report for a given threat actor.

        Accepts an actor name (e.g., 'WARP PANDA') or numeric ID. Returns MITRE ATT&CK
        tactics, techniques, and procedures (TTPs) for the actor. JSON format returns a
        parsed list of dicts; CSV format returns raw CSV text.
        """

        # Check if the actor parameter looks like an ID (numeric) or a name
        actor_id = actor.strip()

        # If it's not a numeric ID, search for the actor first
        if not actor_id.isdigit():
            if "'" in actor or "\\" in actor:
                return [{
                    "error": "Invalid actor name",
                    "message": "An actor name can't contain quotes or backslashes.",
                }]
            logger.debug("Searching for actor: %s", actor)

            # Search for actors using the provided name with FQL filter
            search_results = self._base_search_api_call(
                operation="QueryIntelActorEntities",
                search_params={
                    "filter": f"name:'{actor}'",
                    "limit": 1,
                },
                error_message="Failed to search for actor by name",
            )

            # Check if search returned an error
            if self._is_error(search_results):
                return [search_results]

            # Check if we got any results - must be a list at this point
            if not search_results or not isinstance(search_results, list):
                return [{
                    "error": "Actor not found",
                    "message": f"No actor found with name: {actor}",
                }]

            # Get the first (and should be only) result
            selected_actor = search_results[0]

            # Extract the numeric ID
            actor_id = str(selected_actor.get('id', ''))
            if not actor_id or actor_id == 'None':
                return [{
                    "error": "Invalid actor data",
                    "message": (
                        f"Found actor '{selected_actor.get('name', 'Unknown')}'"
                        " but missing ID field"
                    ),
                    "actor_data": selected_actor
                }]

            logger.debug("Resolved actor '%s' to ID: %s", actor, actor_id)

        # Use the base GET API call method with binary decoding
        api_response = self._base_get_api_call(
            operation="GetMitreReport",
            api_params={
                "actor_id": actor_id,
                "format": format,
            },
            error_message="Failed to get MITRE report",
        )

        # If it's an error, wrap in list for consistency
        if self._is_error(api_response):
            logger.debug("API response is an error, wrapping in list")
            return [api_response]

        # Parse JSON format into Python objects; keep CSV as raw string
        if format.lower() == "json" and isinstance(api_response, str):
            stripped = api_response.strip()
            if not stripped or stripped == "null":
                return []
            try:
                return json.loads(stripped)
            except json.JSONDecodeError as e:
                return [{"error": "JSON parse failure", "message": str(e)}]

        return api_response

    def _get_full_entities(
        self,
        operation: str,
        ids: list[str],
        max_text_chars: int,
        include_rich_text: bool,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Fetch intel entities by ID with every field, then bound their size.

        The entity endpoints return the `__basic__` field set unless asked for
        more; `fields=__full__` is what brings back the analytic text.

        Args:
            operation: GetIntelReportEntities or GetIntelActorEntities
            ids: Entity IDs
            max_text_chars: The longest string kept whole in each record
            include_rich_text: Keep HTML `rich_text_` copies of plain fields

        Returns:
            The clipped records, or an error dict
        """
        details = self._base_get_by_ids(
            operation=operation,
            ids=ids,
            use_params=True,
            fields=["__full__"],
        )
        if isinstance(details, dict):
            return details

        records = [
            record if include_rich_text else _drop_rich_text_duplicates(record)
            for record in details
            if isinstance(record, dict)
        ]
        clipped: list[dict[str, Any]] = clip_long_strings(records, max_text_chars)
        return clipped

    def get_intel_reports(
        self,
        ids: list[str] = Field(
            min_length=1,
            max_length=20,
            description=(
                "Report IDs, from the `id` field of falcon_search_reports results. Up to 20."
            ),
        ),
        max_text_chars: int = Field(
            default=_DEFAULT_FULL_TEXT_CHARS,
            ge=1000,
            le=_MAX_FULL_TEXT_CHARS,
            description=(
                "Longest text field kept whole in each report. Longer fields are cut "
                "and end with a [truncated: N more characters] marker."
            ),
        ),
        include_rich_text: bool = Field(
            default=False,
            description=(
                "Keep the HTML `rich_text_` copies of text fields. Off by default, "
                "since they repeat the plain text."
            ),
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Read the full content of CrowdStrike intelligence reports by ID.

        Use this after falcon_search_reports to read what a report actually says: the
        search returns report metadata, and this returns every field, including the
        analytic write-up, along with actors, targeting, malware and MITRE ATT&CK
        mappings. This is the right tool when asked to go deeper on a campaign or
        report than its one-line summary. Long text is clipped to `max_text_chars`;
        some long-form reports keep extra depth in an attached PDF that this does not
        return.
        """
        return self._get_full_entities(
            operation="GetIntelReportEntities",
            ids=ids,
            max_text_chars=max_text_chars,
            include_rich_text=include_rich_text,
        )

    def get_intel_actors(
        self,
        ids: list[str] = Field(
            min_length=1,
            max_length=20,
            description=(
                "Actor IDs, from the `id` field of falcon_search_actors results. Up to 20."
            ),
        ),
        max_text_chars: int = Field(
            default=_DEFAULT_FULL_TEXT_CHARS,
            ge=1000,
            le=_MAX_FULL_TEXT_CHARS,
            description=(
                "Longest text field kept whole in each profile. Longer fields are cut "
                "and end with a [truncated: N more characters] marker."
            ),
        ),
        include_rich_text: bool = Field(
            default=False,
            description=(
                "Keep the HTML `rich_text_` copies of text fields. Off by default, "
                "since they repeat the plain text."
            ),
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Read full CrowdStrike threat actor profiles by ID.

        Use this after falcon_search_actors identifies an adversary, when you need the
        complete profile rather than the search summary: the full description, aliases,
        first and last activity, targeted industries, countries and regions, origins,
        motivations, capabilities and objectives. For the actor's ATT&CK techniques, use
        falcon_get_mitre_report. Long text is clipped to `max_text_chars`.
        """
        return self._get_full_entities(
            operation="GetIntelActorEntities",
            ids=ids,
            max_text_chars=max_text_chars,
            include_rich_text=include_rich_text,
        )

    def search_intel_vulnerabilities(
        self,
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter, e.g. exploit_status:'ActivelyUsed'+severity:'CRITICAL' or "
                "cve:'CVE-2021-44228'. See `falcon://intel/vulnerabilities/fql-guide`."
            ),
        ),
        q: str | None = Field(
            default=None,
            description="Free-text search across all fields, e.g. 'log4j'.",
        ),
        limit: int = Field(default=10, ge=1, le=_MAX_SEARCH, description=f"[1-{_MAX_SEARCH}]"),
        offset: int | None = Field(default=None, description="The offset to start from."),
        sort: str | None = Field(
            default="publish_date|desc", description="e.g. publish_date|desc or cve|asc."
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Look up CrowdStrike's intelligence on CVEs: whether they're exploited in the wild, severity, CVSS and linked adversaries.

        Use this to judge how urgent a CVE is: `exploit_status` (e.g. ActivelyUsed),
        `severity`, `cvss_v3_base`, `description`, `affected_products`, and the
        `related_actors`, `related_threats` and `related_reports` CrowdStrike links to
        it. Long lists are capped, with `<list>_total` giving the full count. For
        which of this tenant's hosts are exposed, use falcon_search_vulnerabilities.
        Responses include `pagination.total`.
        """
        cve_ids, pagination = self._base_search_with_meta(
            operation="QueryVulnerabilities",
            search_params={"filter": filter, "q": q, "limit": limit, "offset": offset, "sort": sort},
            error_message="Failed to search CVE intelligence",
        )
        if self._is_error(cve_ids):
            return self._format_fql_error_response(
                [cve_ids], filter, QUERY_VULNERABILITIES_FQL_DOCUMENTATION
            )
        if not cve_ids:
            return self._build_pagination_envelope([], pagination, filter)
        records = self._base_get_by_ids(operation="GetVulnerabilities", ids=cve_ids)
        if self._is_error(records):
            return [records]
        records = self._reorder_by_ids(cve_ids, records, id_field="cve")
        return self._build_pagination_envelope([_trim_cve(r) for r in records], pagination, filter)

    def search_malware_families(
        self,
        q: str | None = Field(
            default=None,
            description="Free-text search, e.g. 'emotet' or 'ransomware'. Give q or names.",
        ),
        names: list[str] | None = Field(
            default=None,
            description=(
                f"Exact malware family names, at most {_MAX_MALWARE_NAMES}, e.g. ['Emotet', "
                "'CobaltStrike']. Use q when unsure of the exact name."
            ),
        ),
        limit: int = Field(default=10, ge=1, le=_MAX_SEARCH, description=f"[1-{_MAX_SEARCH}]"),
        offset: int | None = Field(default=None, description="The offset to start from."),
        max_text_chars: int = Field(
            default=5000,
            ge=500,
            le=_MAX_FULL_TEXT_CHARS,
            description="Longest text field kept whole; longer ones end with a truncation marker.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Look up CrowdStrike's malware family profiles: what a family does, who uses it, its ATT&CK techniques, and whether it has been seen in this tenant.

        Each profile has `name`, `slug`, `description`, `capabilities`, `motivation`,
        `used_by`, `developed_by` and `associated_actors`, `mitre` (technique and tactic
        IDs and names), `plugins`, `all_systems`, indicator and report counts, the
        latest `reports` (capped, with `reports_total`), and `seen_in_environment`
        (counts of related vulnerabilities, detections and sandbox results here).
        Search with `q`, or fetch known families by exact `names`.
        """
        if names:
            wanted = list(dict.fromkeys(n.strip() for n in names if isinstance(n, str) and n.strip()))
            if not wanted or len(wanted) > _MAX_MALWARE_NAMES:
                return [{"error": f"Pass between 1 and {_MAX_MALWARE_NAMES} malware family names."}]
            bad = [n for n in wanted if set(n) & _FQL_SPECIAL]
            if bad:
                return [{"error": f"Malware family names can't contain quotes or backslashes: {bad}"}]
            records, _ = self._base_search_with_meta(
                operation="QueryMalwareEntities",
                search_params={
                    "filter": ",".join(f"name:'{n}'" for n in wanted),
                    "limit": len(wanted),
                },
                error_message="Failed to get malware families",
            )
            if self._is_error(records):
                return [records]
            found_names = {str(r.get("name", "")).lower() for r in records}
            not_found = [n for n in wanted if n.lower() not in found_names]
            envelope: dict[str, Any] = {
                "results": [_trim_malware(r, max_text_chars) for r in records],
                "not_found": not_found,
            }
            if not_found:
                # CrowdStrike's spelling can differ from the common one ("CobaltStrike")
                envelope["hint"] = "Names must match exactly. Search with q to find the right name."
            return envelope

        if not q or not q.strip():
            return [{"error": "Give q (a search phrase) or names."}]
        records, pagination = self._base_search_with_meta(
            operation="QueryMalwareEntities",
            search_params={"q": q.strip(), "limit": limit, "offset": offset},
            error_message="Failed to search malware families",
        )
        if self._is_error(records):
            return [records]
        return self._build_pagination_envelope(
            [_trim_malware(r, max_text_chars) for r in records], pagination
        )

    def search_intel_rules(
        self,
        rule_type: Literal[
            "yara-master",
            "yara-update",
            "snort-suricata-master",
            "snort-suricata-update",
            "common-event-format",
            "netwitness",
        ] = Field(
            description=(
                "Rule set type: yara-master or snort-suricata-master (complete sets), "
                "yara-update or snort-suricata-update (recent changes), "
                "common-event-format, netwitness."
            ),
        ),
        q: str | None = Field(default=None, description="Free-text search, e.g. 'ransomware'."),
        tags: list[str] | None = Field(default=None, description="Rule set tags to match."),
        limit: int = Field(default=10, ge=1, le=_MAX_SEARCH, description=f"[1-{_MAX_SEARCH}]"),
        offset: int | None = Field(default=None, description="The offset to start from."),
        sort: str | None = Field(
            default="created_date|desc", description="created_date|desc or last_modified_date|desc."
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search CrowdStrike's published YARA and Snort/Suricata rule sets and read what each covers.

        Each rule set has `id`, `name`, `type`, `created_date`, `last_modified_date`,
        `short_description`, `description` and `tags`. Rule files themselves download
        only as zip or gzip archives and are not returned here.
        Responses include `pagination.total`.
        """
        rule_ids, pagination = self._base_search_with_meta(
            operation="QueryIntelRuleIds",
            search_params={
                "type": rule_type,
                "q": q,
                "tags": tags or None,
                "limit": limit,
                "offset": offset,
                "sort": sort,
            },
            error_message="Failed to search intel rule sets",
        )
        if self._is_error(rule_ids):
            return [rule_ids]
        if not rule_ids:
            return self._build_pagination_envelope([], pagination)
        rules = self._base_get_by_ids(operation="GetIntelRuleEntities", ids=rule_ids, use_params=True)
        if self._is_error(rules):
            return [rules]
        rules = self._reorder_by_ids(rule_ids, rules, id_field="id")
        return self._build_pagination_envelope(
            [_drop_rich_text_duplicates(r) for r in rules], pagination
        )
