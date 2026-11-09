"""
Discover module for Falcon MCP Server

This module provides tools for accessing and managing CrowdStrike Falcon Discover applications, managed assets, unmanaged assets, and accounts.
"""

import re
from collections.abc import Callable
from textwrap import dedent
from typing import Any, Literal

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from pydantic import AnyUrl, Field

from falcon_mcp.common.errors import handle_api_response
from falcon_mcp.common.utils import prepare_api_parameters
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.discover import (
    SEARCH_ACCOUNTS_FQL_DOCUMENTATION,
    SEARCH_APPLICATIONS_FQL_DOCUMENTATION,
    SEARCH_MANAGED_ASSETS_FQL_DOCUMENTATION,
    SEARCH_UNMANAGED_ASSETS_FQL_DOCUMENTATION,
)

# Discover query endpoints return at most 100 IDs per call and refuse
# offset + limit above 10,000. Their entities endpoints take at most 100 IDs.
DISCOVER_PAGE_SIZE = 100
MAX_DISCOVER_QUERY_WINDOW = 10_000

# Asset entity types seen in Discover. Any others are counted as `other`.
KNOWN_ENTITY_TYPES = ("managed", "unmanaged", "unsupported")
# entity_type is written into a quoted FQL value, so allow only a plain name.
ENTITY_TYPE_PATTERN = re.compile(r"[A-Za-z_]{1,32}")

COMPACT_APPLICATION_FIELDS = (
    "id",
    "name",
    "vendor",
    "version",
    "software_type",
    "is_suspicious",
    "installation_paths",
    "last_used_timestamp",
)


def _compact_application(app: dict[str, Any]) -> dict[str, Any]:
    """Reduce an application record to the fields a list view needs."""
    row = {key: app.get(key) for key in COMPACT_APPLICATION_FIELDS}
    host = app.get("host")
    if not isinstance(host, dict):
        host = {}
    row["host"] = {"id": host.get("id"), "hostname": host.get("hostname")}
    return row


class DiscoverModule(BaseModule):
    """Module for accessing and managing CrowdStrike Falcon Discover applications, managed assets, unmanaged assets, and accounts."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        # Register tools
        self._add_tool(
            server=server,
            method=self.search_applications,
            name="search_applications",
        )

        self._add_tool(
            server=server,
            method=self.search_unmanaged_assets,
            name="search_unmanaged_assets",
        )

        self._add_tool(
            server=server,
            method=self.search_managed_assets,
            name="search_managed_assets",
        )

        self._add_tool(
            server=server,
            method=self.search_accounts,
            name="search_accounts",
        )

        self._add_tool(
            server=server,
            method=self.search_assets,
            name="search_assets",
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP server.

        Args:
            server: MCP server instance
        """
        search_applications_fql_resource = TextResource(
            uri=AnyUrl("falcon://discover/applications/fql-guide"),
            name="falcon_search_applications_fql_guide",
            description="Contains the guide for the `filter` param of the `falcon_search_applications` tool.",
            text=SEARCH_APPLICATIONS_FQL_DOCUMENTATION,
        )

        search_unmanaged_assets_fql_resource = TextResource(
            uri=AnyUrl("falcon://discover/hosts/fql-guide"),
            name="falcon_search_unmanaged_assets_fql_guide",
            description="Contains the guide for the `filter` param of the `falcon_search_unmanaged_assets` tool.",
            text=SEARCH_UNMANAGED_ASSETS_FQL_DOCUMENTATION,
        )

        search_managed_assets_fql_resource = TextResource(
            uri=AnyUrl("falcon://discover/managed-assets/fql-guide"),
            name="falcon_search_managed_assets_fql_guide",
            description="Contains the guide for the `filter` param of the `falcon_search_managed_assets` tool.",
            text=SEARCH_MANAGED_ASSETS_FQL_DOCUMENTATION,
        )

        self._add_resource(
            server,
            search_applications_fql_resource,
        )

        self._add_resource(
            server,
            search_unmanaged_assets_fql_resource,
        )

        search_accounts_fql_resource = TextResource(
            uri=AnyUrl("falcon://discover/accounts/fql-guide"),
            name="falcon_search_accounts_fql_guide",
            description="Contains the guide for the `filter` param of the `falcon_search_accounts` tool.",
            text=SEARCH_ACCOUNTS_FQL_DOCUMENTATION,
        )

        self._add_resource(
            server,
            search_managed_assets_fql_resource,
        )

        self._add_resource(
            server,
            search_accounts_fql_resource,
        )

    def search_applications(
        self,
        filter: str | None = Field(
            default=None,
            description=dedent("""
                FQL filter expression. See `falcon://discover/applications/fql-guide` for syntax.
                Omit it to list every application. There is no reliable match-all filter:
                name:'*' silently returns nothing, and a range filter such as
                last_used_timestamp:>'1970-01-01T00:00:00Z' drops applications whose
                timestamp is empty.
            """).strip(),
            examples={"name:'Chrome'", "vendor:'Microsoft Corporation'"},
        ),
        facet: str | None = Field(
            default=None,
            description=dedent("""
                Type of data to be returned for each application entity. The facet filter allows you to limit the response to just the information you want.

                Possible values:
                • browser_extension
                • host_info
                • install_usage

                Note: Requests that do not include the host_info or browser_extension facets still return host.ID, browser_extension.ID, and browser_extension.enabled in the response.

                Applies only with a filter. Without one, facet is ignored, and each row
                already carries the full host block, including host.hostname, and
                last_used_timestamp.
            """).strip(),
            examples={"browser_extension", "host_info", "install_usage"},
        ),
        limit: int = Field(
            default=100,
            ge=1,
            le=1000,
            description="Maximum number of items to return: 1-1000. Default is 100.",
        ),
        sort: str | None = Field(
            default=None,
            description="Property used to sort the results. All properties can be used to sort unless otherwise noted in their property descriptions.",
            examples={"name.asc", "vendor.desc", "last_used_timestamp.desc"},
        ),
        offset: int | None = Field(
            default=None,
            ge=0,
            description=(
                "Starting index, used only without a filter. offset + limit can't exceed "
                f"{MAX_DISCOVER_QUERY_WINDOW}; to go further, add a filter and page with `after`."
            ),
        ),
        after: str | None = Field(
            default=None,
            description="Next-page token from a previous filtered call's pagination.next. Used only with a filter.",
        ),
        fields: Literal["full", "compact"] = Field(
            default="full",
            description=(
                "'compact' returns only id, name, vendor, version, software_type, is_suspicious, "
                "installation_paths, last_used_timestamp and host (id, hostname). A full row is "
                "about 3 KB, so use compact for large pages."
            ),
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search for applications discovered in your CrowdStrike environment.

        Use this to find applications by name, vendor, or installation details. Consult
        falcon://discover/applications/fql-guide before constructing filter expressions.
        Without a filter it lists every application, for example the most recently used
        with sort='last_used_timestamp.desc'. Use fields='compact' for large pages.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        if not filter:
            return self._list_all_applications(limit, sort, offset or 0, fields)

        applications, pagination = self._base_search_with_meta(
            operation="combined_applications",
            search_params={
                "filter": filter,
                "facet": facet,
                "limit": limit,
                "sort": sort,
                "after": after,
            },
            error_message="Failed to search applications",
        )

        if self._is_error(applications):
            return [applications]

        if fields == "compact" and isinstance(applications, list):
            applications = [_compact_application(app) for app in applications]

        return self._build_pagination_envelope(applications, pagination, filter)

    def _list_all_applications(
        self,
        limit: int,
        sort: str | None,
        offset: int,
        fields: str,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """List applications with no filter, through the query and entities endpoints.

        The combined endpoint requires a filter, and no filter matches every
        application, so this path is the only way to count and list them all.
        """
        return self._list_via_query(
            query_operation="query_applications",
            get_operation="get_applications",
            what="applications",
            limit=limit,
            sort=sort,
            offset=offset,
            transform=_compact_application if fields == "compact" else None,
        )

    def _list_via_query(
        self,
        query_operation: str,
        get_operation: str,
        what: str,
        limit: int,
        sort: str | None,
        offset: int,
        transform: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Page a Discover query endpoint, then fetch the records 100 IDs at a time.

        Discover query endpoints return at most 100 IDs per call and refuse
        offset + limit above 10,000. Their entities endpoints take at most 100 IDs.
        """
        if offset + limit > MAX_DISCOVER_QUERY_WINDOW:
            return [
                {
                    "error": (
                        f"offset + limit must be {MAX_DISCOVER_QUERY_WINDOW} or less without "
                        "a filter. Add a filter and page with `after` to go further."
                    )
                }
            ]

        ids: list[str] = []
        total: Any = None
        while len(ids) < limit:
            page_limit = min(DISCOVER_PAGE_SIZE, limit - len(ids))
            response = self.client.command(
                query_operation,
                parameters=prepare_api_parameters(
                    {"limit": page_limit, "offset": offset + len(ids), "sort": sort}
                ),
            )
            page = handle_api_response(
                response,
                operation=query_operation,
                error_message=f"Failed to search {what}",
                default_result=[],
            )
            if self._is_error(page):
                return [page]
            if total is None:
                total = (self._extract_pagination(response) or {}).get("total")
            if not isinstance(page, list) or not page:
                break
            ids.extend(page)
            if len(page) < page_limit:
                break

        records: list[dict[str, Any]] = []
        for start in range(0, len(ids), DISCOVER_PAGE_SIZE):
            batch = self._base_get_by_ids(
                operation=get_operation,
                ids=ids[start : start + DISCOVER_PAGE_SIZE],
                use_params=True,
            )
            if isinstance(batch, dict):
                return [batch]
            records.extend(batch)

        records = self._reorder_by_ids(ids, records, id_field="id")
        if transform is not None:
            records = [transform(record) for record in records]

        envelope = self._build_pagination_envelope(
            records, {"total": total, "offset": offset, "limit": limit}
        )
        next_offset = offset + len(ids)
        more = isinstance(total, int) and next_offset < total
        envelope["pagination"]["next_offset"] = (
            next_offset if more and next_offset < MAX_DISCOVER_QUERY_WINDOW else None
        )
        return envelope

    def search_assets(
        self,
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter expression. See `falcon://discover/managed-assets/fql-guide` for "
                "fields. Omit it, and entity_type, to list every asset of every type."
            ),
            examples={"platform_name:'Windows'", "criticality:'Critical'"},
        ),
        entity_type: str | None = Field(
            default=None,
            description=(
                "Limit results to one entity type, for example 'managed', 'unmanaged' or "
                "'unsupported'. Omit it to include every type."
            ),
            examples={"managed", "unmanaged", "unsupported"},
        ),
        limit: int = Field(
            default=100,
            ge=1,
            le=1000,
            description="Maximum number of assets to return: 1-1000. Default is 100.",
        ),
        offset: int | None = Field(
            default=None,
            ge=0,
            description=(
                "Starting index, used only without a filter or entity_type. offset + limit "
                f"can't exceed {MAX_DISCOVER_QUERY_WINDOW}; to go further, add a filter and "
                "page with `after`."
            ),
        ),
        after: str | None = Field(
            default=None,
            description="Next-page token from a previous filtered call's pagination.next.",
        ),
        sort: str | None = Field(
            default=None,
            description="Sort field and direction, for example 'hostname.asc' or 'last_seen_timestamp.desc'.",
            examples={"hostname.asc", "last_seen_timestamp.desc"},
        ),
        include_type_totals: bool = Field(
            default=False,
            description=(
                "Also return `totals_by_entity_type`: the asset count for each known entity "
                "type, plus `other` for any assets the known types don't cover."
            ),
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search Discover assets of every entity type: managed, unmanaged and unsupported.

        Unlike falcon_search_managed_assets and falcon_search_unmanaged_assets, this
        tool doesn't pin an entity type, so it also reaches unsupported assets. Without
        a filter it lists every asset and `pagination.total` counts them all. Set
        include_type_totals to get a count per entity type in the same call.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        if entity_type is not None and not ENTITY_TYPE_PATTERN.fullmatch(entity_type):
            return [
                {
                    "error": (
                        f"Invalid entity_type {entity_type!r}: use a plain type name such as "
                        "'managed', 'unmanaged' or 'unsupported'."
                    )
                }
            ]

        parts = [f"entity_type:'{entity_type}'"] if entity_type else []
        if filter:
            parts.append(filter)
        combined_filter = "+".join(parts)

        if combined_filter:
            assets, pagination = self._base_search_with_meta(
                operation="combined_hosts",
                search_params={
                    "filter": combined_filter,
                    "limit": limit,
                    "sort": sort,
                    "after": after,
                },
                error_message="Failed to search assets",
            )
            if self._is_error(assets):
                return self._format_fql_error_response(
                    [assets], combined_filter, SEARCH_MANAGED_ASSETS_FQL_DOCUMENTATION
                )
            result = self._build_pagination_envelope(assets, pagination, combined_filter)
        else:
            listed = self._list_via_query(
                query_operation="query_hosts",
                get_operation="get_hosts",
                what="assets",
                limit=limit,
                sort=sort,
                offset=offset or 0,
            )
            if not isinstance(listed, dict):
                return listed
            result = listed

        if include_type_totals:
            totals = self._asset_type_totals()
            if self._is_error(totals):
                return [totals]
            result["totals_by_entity_type"] = totals
        return result

    def _asset_type_totals(self) -> dict[str, Any]:
        """Count assets per known entity type, and the remainder as `other`."""
        counts: dict[str, Any] = {}
        for label, query_filter in [("all", None), *((t, f"entity_type:'{t}'") for t in KNOWN_ENTITY_TYPES)]:
            response = self.client.command(
                "query_hosts",
                parameters=prepare_api_parameters({"limit": 1, "filter": query_filter}),
            )
            ids = handle_api_response(
                response,
                operation="query_hosts",
                error_message="Failed to count assets",
                default_result=[],
            )
            if self._is_error(ids):
                return ids
            counts[label] = (self._extract_pagination(response) or {}).get("total")

        total = counts.pop("all")
        known = [counts[t] for t in KNOWN_ENTITY_TYPES]
        if isinstance(total, int) and all(isinstance(n, int) for n in known):
            # Assets are discovered continuously, so the separate counts can drift by a
            # few between calls. Never report a negative remainder.
            counts["other"] = max(total - sum(known), 0)
        else:
            counts["other"] = None
        counts["total"] = total
        return counts

    def search_unmanaged_assets(
        self,
        filter: str | None = Field(
            default=None,
            description="FQL filter expression. See `falcon://discover/hosts/fql-guide` for syntax. Note: entity_type:'unmanaged' is automatically applied.",
            examples={"platform_name:'Windows'", "criticality:'Critical'"},
        ),
        limit: int = Field(
            default=100,
            ge=1,
            le=5000,
            description="Maximum number of items to return: 1-5000. Default is 100.",
        ),
        offset: int | None = Field(
            default=None,
            description="Starting index of overall result set from which to return results.",
        ),
        sort: str | None = Field(
            default=None,
            description=dedent("""
                Sort unmanaged assets using these options:

                hostname: Host name/computer name
                last_seen_timestamp: Timestamp when the asset was last seen
                first_seen_timestamp: Timestamp when the asset was first seen
                platform_name: Operating system platform
                os_version: Operating system version
                external_ip: External IP address
                country: Country location
                criticality: Criticality level

                Sort either asc (ascending) or desc (descending). Use the dot
                separator ('hostname.desc'), which is supported on every Falcon
                sort endpoint. The pipe form ('hostname|desc') is accepted here
                but rejected by some endpoints, so prefer the dot form.

                Examples: 'hostname.asc', 'last_seen_timestamp.desc', 'criticality.desc'
            """).strip(),
            examples={"hostname.asc", "last_seen_timestamp.desc", "criticality.desc"},
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search for unmanaged assets (hosts without Falcon sensor) in your environment.

        Finds systems discovered by Falcon-managed hosts that lack a sensor themselves.
        Consult falcon://discover/hosts/fql-guide before constructing filter expressions.
        The tool automatically adds entity_type:'unmanaged' to all queries. Returns full
        asset details including platform, network, and criticality information.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        # Always enforce entity_type:'unmanaged' filter
        base_filter = "entity_type:'unmanaged'"

        # Combine with user filter if provided
        if filter:
            combined_filter = f"{base_filter}+{filter}"
        else:
            combined_filter = base_filter

        assets, pagination = self._base_search_with_meta(
            operation="combined_hosts",
            search_params={
                "filter": combined_filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
            },
            error_message="Failed to search unmanaged assets",
        )

        if self._is_error(assets):
            return [assets]

        return self._build_pagination_envelope(assets, pagination, filter)

    def search_managed_assets(
        self,
        filter: str | None = Field(
            default=None,
            description="FQL filter expression. See `falcon://discover/managed-assets/fql-guide` for syntax. Note: entity_type:'managed' is automatically applied.",
            examples={"encryption_status:'Unencrypted'", "os_security.credential_guard_status:false"},
        ),
        limit: int = Field(
            default=100,
            ge=1,
            le=5000,
            description="Maximum number of items to return: 1-5000. Default is 100.",
        ),
        offset: int | None = Field(
            default=None,
            description="Starting index of overall result set from which to return results.",
        ),
        sort: str | None = Field(
            default=None,
            description=dedent("""
                Sort managed assets using these options:

                hostname: Host name/computer name
                last_seen_timestamp: Timestamp when the asset was last seen
                first_seen_timestamp: Timestamp when the asset was first seen
                platform_name: Operating system platform
                os_version: Operating system version
                external_ip: External IP address
                country: Country location
                criticality: Criticality level

                Sort either asc (ascending) or desc (descending). Use the dot
                separator ('hostname.desc'), which is supported on every Falcon
                sort endpoint. The pipe form ('hostname|desc') is accepted here
                but rejected by some endpoints, so prefer the dot form.

                Examples: 'hostname.asc', 'last_seen_timestamp.desc', 'criticality.desc'
            """).strip(),
            examples={"hostname.asc", "last_seen_timestamp.desc", "criticality.desc"},
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search hosts by asset and configuration posture: drive encryption status, encrypted/unencrypted drives, OS security settings (Secure Boot, Credential Guard, IOMMU), disk/memory/CPU usage, asset criticality, and internet exposure.

        Use this when the question is about a device's storage, hardware, or security
        configuration rather than its sensor state. For containment status, sensor version,
        or policy assignment, use `falcon_search_hosts`. See
        `falcon://discover/managed-assets/fql-guide` for filters; returns full asset details.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        # Always enforce entity_type:'managed' filter
        base_filter = "entity_type:'managed'"

        # Combine with user filter if provided
        if filter:
            combined_filter = f"{base_filter}+{filter}"
        else:
            combined_filter = base_filter

        assets, pagination = self._base_search_with_meta(
            operation="combined_hosts",
            search_params={
                "filter": combined_filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
            },
            error_message="Failed to search managed assets",
        )

        if self._is_error(assets):
            # combined_hosts validates filter fields loudly (HTTP 400 on an unknown
            # field or wrong type), so surface the FQL guide to help correct the query
            # rather than returning a bare error.
            return self._format_fql_error_response(
                [assets], filter, SEARCH_MANAGED_ASSETS_FQL_DOCUMENTATION
            )

        return self._build_pagination_envelope(assets, pagination, filter)

    def search_accounts(
        self,
        filter: str | None = Field(
            default=None,
            description="FQL filter expression. See `falcon://discover/accounts/fql-guide` for syntax.",
            examples={"admin_privileges:'Yes'", "account_type:'Local'"},
        ),
        limit: int = Field(
            default=100,
            ge=1,
            le=100,
            description="Maximum number of accounts to return: 1-100. Default is 100.",
        ),
        offset: int | None = Field(
            default=None,
            ge=0,
            description="Starting index of overall result set from which to return results.",
        ),
        sort: str | None = Field(
            default=None,
            description=dedent("""
                Sort accounts by a single property, ascending or descending, for example:

                username: Username of the account
                account_name: Name of the account
                first_seen_timestamp: When the account was first seen
                last_successful_login_timestamp: Most recent successful login
                last_failed_login_timestamp: Most recent failed login
                password_last_set_timestamp: When the password was last set

                Examples: 'username|asc', 'last_successful_login_timestamp|desc'
            """).strip(),
            examples={"username|asc", "last_successful_login_timestamp|desc"},
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search local and Active Directory accounts inventoried by Falcon Discover.

        Use this to find accounts by privilege level, account type, password age, or
        recent successful and failed logins, for example local admin accounts or
        accounts whose passwords have not changed in a year. Consult
        `falcon://discover/accounts/fql-guide` before constructing filter expressions.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        query_response = self.client.command(
            "query_accounts",
            parameters=prepare_api_parameters(
                {
                    "filter": filter,
                    "limit": limit,
                    "offset": offset,
                    "sort": sort,
                }
            ),
        )
        account_ids = handle_api_response(
            query_response,
            operation="query_accounts",
            error_message="Failed to search accounts",
            default_result=[],
        )

        if self._is_error(account_ids):
            return self._format_fql_error_response(
                [account_ids], filter, SEARCH_ACCOUNTS_FQL_DOCUMENTATION
            )

        pagination = self._extract_pagination(query_response)

        if not account_ids:
            return self._build_pagination_envelope([], pagination, filter)

        accounts = self._base_get_by_ids(
            operation="get_accounts",
            ids=account_ids,
            use_params=True,
        )

        if self._is_error(accounts):
            return [accounts]

        accounts = self._reorder_by_ids(account_ids, accounts, id_field="id")
        return self._build_pagination_envelope(accounts, pagination, filter)
