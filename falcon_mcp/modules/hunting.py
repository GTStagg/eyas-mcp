"""
Hunting module for Falcon MCP Server

This module provides tools for searching and reading CrowdStrike's published
hunting content: hunting guides (narrative investigation runbooks) and hunting
queries (runnable detection and hunting logic, which the API calls intelligence
queries).

Required API scopes:
    - CAO Hunting: read
"""

from typing import Any, Literal

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from pydantic import AnyUrl, Field

from falcon_mcp.common.logging import get_logger
from falcon_mcp.common.truncate import clip_long_strings
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.hunting import (
    SEARCH_HUNTING_GUIDES_FQL_DOCUMENTATION,
    SEARCH_HUNTING_QUERIES_FQL_DOCUMENTATION,
)

logger = get_logger(__name__)

# Guides are long Markdown documents; queries are short logic plus a description.
_DEFAULT_GUIDE_TEXT_CHARS = 10000
_DEFAULT_QUERY_TEXT_CHARS = 10000
_MAX_TEXT_CHARS = 100000

TranslatedContent = Literal["SPL", "__all__"]


class HuntingModule(BaseModule):
    """Module for CrowdStrike's published hunting guides and hunting queries."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(
            server=server,
            method=self.search_hunting_guides,
            name="search_hunting_guides",
        )

        self._add_tool(
            server=server,
            method=self.get_hunting_guides,
            name="get_hunting_guides",
        )

        self._add_tool(
            server=server,
            method=self.search_hunting_queries,
            name="search_hunting_queries",
        )

        self._add_tool(
            server=server,
            method=self.get_hunting_queries,
            name="get_hunting_queries",
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_resource(
            server,
            TextResource(
                uri=AnyUrl("falcon://hunting/guides/fql-guide"),
                name="falcon_search_hunting_guides_fql_guide",
                description=(
                    "Contains the guide for the `filter` param of the "
                    "`falcon_search_hunting_guides` tool."
                ),
                text=SEARCH_HUNTING_GUIDES_FQL_DOCUMENTATION,
            ),
        )
        self._add_resource(
            server,
            TextResource(
                uri=AnyUrl("falcon://hunting/queries/fql-guide"),
                name="falcon_search_hunting_queries_fql_guide",
                description=(
                    "Contains the guide for the `filter` param of the "
                    "`falcon_search_hunting_queries` tool."
                ),
                text=SEARCH_HUNTING_QUERIES_FQL_DOCUMENTATION,
            ),
        )

    @staticmethod
    def _is_filter_error(error: dict[str, Any], filter_used: str | None) -> bool:
        """Report whether the FQL guide is the right answer to an API error.

        Only a 400 suggests bad syntax, and the guide only helps a caller who
        sent a filter. A 400 without one points at `sort` or `q` instead.

        Args:
            error: An error dict from a search helper
            filter_used: The FQL filter the caller supplied, if any

        Returns:
            True when the FQL guide should be returned inline
        """
        details = error.get("details") or {}
        return details.get("status_code") == 400 and bool(filter_used)

    def _search_and_hydrate(
        self,
        search_operation: str,
        get_operation: str,
        search_params: dict[str, Any],
        get_params: dict[str, Any],
        max_text_chars: int,
        fql_documentation: str,
        error_message: str,
    ) -> dict[str, Any]:
        """Search for content IDs, then fetch and clip the full records.

        Args:
            search_operation: The ID search operation
            get_operation: The get-by-IDs operation
            search_params: Query parameters for the search, including `filter`
            get_params: Extra query parameters for the get-by-IDs call
            max_text_chars: The longest string kept whole in each record
            fql_documentation: The FQL guide returned on a filter error
            error_message: Prefix for a failed search

        Returns:
            The standard pagination envelope, or an error dict
        """
        filter_used = search_params.get("filter")
        ids, pagination = self._base_search_with_meta(
            operation=search_operation,
            search_params=search_params,
            error_message=error_message,
        )

        if isinstance(ids, dict):
            if self._is_filter_error(ids, filter_used):
                return self._format_fql_error_response([ids], filter_used, fql_documentation)
            return ids

        if not ids:
            return self._build_pagination_envelope([], pagination, filter_used)

        details = self._base_get_by_ids(
            operation=get_operation,
            ids=ids,
            use_params=True,
            **get_params,
        )

        if isinstance(details, dict):
            return details

        ordered = self._reorder_by_ids(ids, details, id_field="id")
        return self._build_pagination_envelope(
            clip_long_strings(ordered, max_text_chars), pagination, filter_used
        )

    def search_hunting_guides(
        self,
        q: str | None = Field(
            default=None,
            description=(
                "Free-text phrase-prefix search across every indexed text field. The "
                "easiest way in: a technique, tool, behavior or actor name."
            ),
            examples=["mimikatz", "T1003", "lateral movement"],
        ),
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter expression. See `falcon://hunting/guides/fql-guide`. The "
                "API does not publish its filterable fields, so prefer `q`."
            ),
        ),
        limit: int = Field(
            default=5,
            ge=1,
            le=50,
            description="Maximum guides to return. Guides are long documents. [1-50]",
        ),
        offset: int | None = Field(
            default=None,
            ge=0,
            description="Starting index of the result set, for paging.",
        ),
        sort: str | None = Field(
            default=None,
            description="Sort on a field from the returned records, with a dot separator: 'name.asc'.",
        ),
        max_text_chars: int = Field(
            default=_DEFAULT_GUIDE_TEXT_CHARS,
            ge=500,
            le=_MAX_TEXT_CHARS,
            description=(
                "Longest text field kept whole in each guide. Longer fields are cut "
                "and end with a [truncated: N more characters] marker."
            ),
        ),
    ) -> dict[str, Any]:
        """Search CrowdStrike's published hunting guides and return their content.

        Use this when planning a threat hunt or investigating a behavior, technique or
        adversary, to find the runbook CrowdStrike researchers already wrote for it:
        why the activity matters, what to look at, and what to check next. Pair it with
        falcon_search_hunting_queries for the runnable logic. Start with `q`; consult
        falcon://hunting/guides/fql-guide before building a `filter`. Returns full guide
        records, with long text clipped to `max_text_chars`.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        return self._search_and_hydrate(
            search_operation="SearchHuntingGuides",
            get_operation="GetHuntingGuides",
            search_params={
                "q": q,
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
            },
            get_params={},
            max_text_chars=max_text_chars,
            fql_documentation=SEARCH_HUNTING_GUIDES_FQL_DOCUMENTATION,
            error_message="Failed to search hunting guides",
        )

    def get_hunting_guides(
        self,
        ids: list[str] = Field(
            min_length=1,
            max_length=50,
            description="Hunting guide IDs, from falcon_search_hunting_guides. Up to 50.",
        ),
        max_text_chars: int = Field(
            default=_DEFAULT_GUIDE_TEXT_CHARS,
            ge=500,
            le=_MAX_TEXT_CHARS,
            description=(
                "Longest text field kept whole in each guide. Longer fields are cut "
                "and end with a [truncated: N more characters] marker."
            ),
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Read CrowdStrike hunting guides by ID.

        Use this when you already hold guide IDs, for example to reread a guide with a
        larger `max_text_chars` after a search clipped it. To find guides by topic, use
        falcon_search_hunting_guides. Returns full guide records.
        """
        details = self._base_get_by_ids(
            operation="GetHuntingGuides",
            ids=ids,
            use_params=True,
        )
        if self._is_error(details):
            return details
        return clip_long_strings(details, max_text_chars)

    def search_hunting_queries(
        self,
        q: str | None = Field(
            default=None,
            description=(
                "Free-text phrase-prefix search across every indexed text field. The "
                "easiest way in: a technique, binary, tool or behavior."
            ),
            examples=["rundll32", "T1218", "Cobalt Strike"],
        ),
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter expression. See `falcon://hunting/queries/fql-guide`. The "
                "API does not publish its filterable fields, so prefer `q`."
            ),
        ),
        limit: int = Field(
            default=10,
            ge=1,
            le=100,
            description="Maximum queries to return. [1-100]",
        ),
        offset: int | None = Field(
            default=None,
            ge=0,
            description="Starting index of the result set, for paging.",
        ),
        sort: str | None = Field(
            default=None,
            description="Sort on a field from the returned records, with a dot separator: 'name.asc'.",
        ),
        include_translated_content: TranslatedContent | None = Field(
            default=None,
            description=(
                "Also return an AI-translated version of each query where one exists. "
                "'SPL' for Splunk, or '__all__' for every available translation."
            ),
        ),
        max_text_chars: int = Field(
            default=_DEFAULT_QUERY_TEXT_CHARS,
            ge=500,
            le=_MAX_TEXT_CHARS,
            description=(
                "Longest text field kept whole in each query. Longer fields are cut "
                "and end with a [truncated: N more characters] marker."
            ),
        ),
    ) -> dict[str, Any]:
        """Search CrowdStrike's published hunting queries and return them in full.

        Use this before writing a hunting or detection query from scratch: CrowdStrike
        researchers publish ready-made queries, most in CQL for Next-Gen SIEM, for many
        techniques and tools. Adapt a published query rather than inventing one. Start
        with `q`; consult falcon://hunting/queries/fql-guide before building a `filter`.
        Returns full query records including the query text, with long text clipped to
        `max_text_chars`.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        return self._search_and_hydrate(
            search_operation="SearchIntelligenceQueries",
            get_operation="GetIntelligenceQueries",
            search_params={
                "q": q,
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
            },
            get_params={"include_translated_content": include_translated_content},
            max_text_chars=max_text_chars,
            fql_documentation=SEARCH_HUNTING_QUERIES_FQL_DOCUMENTATION,
            error_message="Failed to search hunting queries",
        )

    def get_hunting_queries(
        self,
        ids: list[str] = Field(
            min_length=1,
            max_length=100,
            description="Hunting query IDs, from falcon_search_hunting_queries. Up to 100.",
        ),
        include_translated_content: TranslatedContent | None = Field(
            default=None,
            description=(
                "Also return an AI-translated version of each query where one exists. "
                "'SPL' for Splunk, or '__all__' for every available translation."
            ),
        ),
        max_text_chars: int = Field(
            default=_DEFAULT_QUERY_TEXT_CHARS,
            ge=500,
            le=_MAX_TEXT_CHARS,
            description=(
                "Longest text field kept whole in each query. Longer fields are cut "
                "and end with a [truncated: N more characters] marker."
            ),
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Read CrowdStrike hunting queries by ID.

        Use this when you already hold query IDs, for example to fetch an SPL
        translation of a query found earlier. To find queries by topic, use
        falcon_search_hunting_queries. Returns full query records including the query
        text.
        """
        details = self._base_get_by_ids(
            operation="GetIntelligenceQueries",
            ids=ids,
            use_params=True,
            include_translated_content=include_translated_content,
        )
        if self._is_error(details):
            return details
        return clip_long_strings(details, max_text_chars)
