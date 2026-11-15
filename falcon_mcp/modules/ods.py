"""
ODS module for Falcon MCP Server

This module provides tools for Falcon on-demand scans (ODS): search scans, their
per-host results, the malicious files they found and scheduled scans; start a scan
on hosts or host groups; cancel scans; and delete scheduled scans.
"""

import re
from typing import Any

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from mcp.types import ToolAnnotations
from pydantic import AnyUrl, Field

from falcon_mcp.common.errors import _format_error_response, handle_api_response
from falcon_mcp.common.logging import get_logger
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.ods import ODS_FQL_DOCUMENTATION

logger = get_logger(__name__)

FQL_GUIDE = "`falcon://ods/search/fql-guide`"
MAX_SEARCH_LIMIT = 500
MAX_SCAN_HOSTS = 500
MAX_HOST_GROUPS = 100
MAX_PATHS = 50
MAX_IDS = 100

ID_PATTERN = re.compile(r"[0-9a-fA-F]{32}")
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

# Fields that make a scan record long without helping an agent read it
_NOISY_SCAN_FIELDS = ("policy_setting", "mac_policy_setting")


def _error(message: str, operation: str) -> dict[str, Any]:
    return _format_error_response(message, operation=operation)


def _clean_ids(values: list[str] | None, limit: int, label: str) -> tuple[list[str], str | None]:
    """Normalize 32-hex IDs (host AIDs, host group IDs, scan IDs), keeping order."""
    out: list[str] = []
    for raw in values or []:
        value = raw.strip().lower() if isinstance(raw, str) else ""
        if not ID_PATTERN.fullmatch(value):
            return [], f"Invalid {label} {raw!r}: expected 32 hexadecimal characters."
        if value not in out:
            out.append(value)
    if len(out) > limit:
        return [], f"Too many {label}s: {len(out)}. At most {limit} per call."
    return out, None


def _clean_paths(values: list[str] | None, label: str) -> tuple[list[str], str | None]:
    out = [v.strip() for v in values or [] if isinstance(v, str) and v.strip()]
    if len(out) > MAX_PATHS:
        return [], f"At most {MAX_PATHS} {label} per scan."
    bad = [p for p in out if CONTROL_CHARS.search(p) or len(p) > 1024]
    if bad:
        return [], f"Invalid {label}: {bad[:3]}. Paths can't contain control characters."
    return out, None


class OdsModule(BaseModule):
    """Module for Falcon on-demand scans."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(server=server, method=self.search_ods_scans, name="search_ods_scans")
        self._add_tool(server=server, method=self.search_ods_scan_hosts, name="search_ods_scan_hosts")
        self._add_tool(
            server=server, method=self.search_ods_malicious_files, name="search_ods_malicious_files"
        )
        self._add_tool(
            server=server, method=self.search_ods_scheduled_scans, name="search_ods_scheduled_scans"
        )
        self._add_tool(
            server=server,
            method=self.start_ods_scan,
            name="start_ods_scan",
            annotations=ToolAnnotations(
                readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
            ),
        )
        self._add_tool(
            server=server,
            method=self.cancel_ods_scans,
            name="cancel_ods_scans",
            annotations=ToolAnnotations(
                readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
            ),
        )
        self._add_tool(
            server=server,
            method=self.delete_ods_scheduled_scans,
            name="delete_ods_scheduled_scans",
            annotations=ToolAnnotations(
                readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True
            ),
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_resource(
            server,
            TextResource(
                uri=AnyUrl("falcon://ods/search/fql-guide"),
                name="falcon_ods_fql_guide",
                description="Contains the guide for the `filter` param of the on-demand scan search tools.",
                text=ODS_FQL_DOCUMENTATION,
            ),
        )

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #

    def _search(
        self,
        query_operation: str,
        get_operation: str,
        filter: str | None,
        limit: int,
        offset: int | None,
        sort: str | None,
        error_message: str,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Query IDs, fetch the records and return them in the query's order."""
        ids, pagination = self._base_search_with_meta(
            operation=query_operation,
            search_params={"filter": filter, "limit": limit, "offset": offset, "sort": sort},
            error_message=error_message,
        )
        if self._is_error(ids):
            return self._format_fql_error_response([ids], filter, ODS_FQL_DOCUMENTATION)
        if not ids:
            return self._build_pagination_envelope([], pagination, filter)
        records = self._base_get_by_ids(operation=get_operation, ids=ids, use_params=True)
        if self._is_error(records):
            return [records]
        records = self._reorder_by_ids(ids, records, id_field="id")
        for record in records:
            for noisy in _NOISY_SCAN_FIELDS:
                record.pop(noisy, None)
        return self._build_pagination_envelope(records, pagination, filter)

    def search_ods_scans(
        self,
        filter: str | None = Field(
            default=None,
            description=f"FQL filter on scans, e.g. status:'completed'+filecount.malicious:>0. See {FQL_GUIDE}.",
        ),
        limit: int = Field(default=20, ge=1, le=MAX_SEARCH_LIMIT, description=f"[1-{MAX_SEARCH_LIMIT}]"),
        offset: int | None = Field(default=None, description="The offset to start from."),
        sort: str | None = Field(
            default="created_on|desc", description="field|asc or field|desc, e.g. created_on|desc."
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search on-demand malware scans: status, hosts targeted, files scanned and malicious files found.

        Each scan has `id`, `status` (pending, running, completed, incomplete,
        canceled), `initiated_from`, `description`, `hosts`, `targeted_platforms`,
        `filecount` (scanned, malicious, quarantined, skipped), host counts by state,
        the scan settings, and when it started and was created. For per-host results
        use falcon_search_ods_scan_hosts; for what was found,
        falcon_search_ods_malicious_files.
        """
        return self._search(
            "query_scans", "get_scans_by_scan_ids_v2", filter, limit, offset, sort,
            "Failed to search on-demand scans",
        )

    def search_ods_scan_hosts(
        self,
        filter: str | None = Field(
            default=None,
            description=f"FQL filter on per-host results, e.g. scan_id:'<scan id>'. See {FQL_GUIDE}.",
        ),
        limit: int = Field(default=50, ge=1, le=MAX_SEARCH_LIMIT, description=f"[1-{MAX_SEARCH_LIMIT}]"),
        offset: int | None = Field(default=None, description="The offset to start from."),
        sort: str | None = Field(default=None, description="field|asc or field|desc."),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Get each host's result in on-demand scans: status, files scanned, malicious and quarantined.

        Each record has `scan_id`, `host_id`, `platform_name`, `status`, `filecount`
        and when the host started and finished. Filter on scan_id to see how one scan
        went on every host.
        """
        return self._search(
            "query_scan_host_metadata", "get_scan_host_metadata_by_ids", filter, limit, offset,
            sort, "Failed to search on-demand scan hosts",
        )

    def search_ods_malicious_files(
        self,
        filter: str | None = Field(
            default=None,
            description=f"FQL filter on found files, e.g. scan_id:'<scan id>'. See {FQL_GUIDE}.",
        ),
        limit: int = Field(default=50, ge=1, le=MAX_SEARCH_LIMIT, description=f"[1-{MAX_SEARCH_LIMIT}]"),
        offset: int | None = Field(default=None, description="The offset to start from."),
        sort: str | None = Field(default=None, description="field|asc or field|desc."),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """List the malicious files on-demand scans found: path, hash, severity and whether they were quarantined.

        Each record carries `scan_id`, `host_id`, `filepath`, `filename`, `hash`,
        `severity` and `quarantined`. Check a hash further with
        falcon_search_sandbox_reports.
        """
        return self._search(
            "query_malicious_files", "get_malicious_files_by_ids", filter, limit, offset, sort,
            "Failed to search on-demand scan findings",
        )

    def search_ods_scheduled_scans(
        self,
        filter: str | None = Field(
            default=None, description=f"FQL filter on scheduled scans. See {FQL_GUIDE}."
        ),
        limit: int = Field(default=20, ge=1, le=MAX_SEARCH_LIMIT, description=f"[1-{MAX_SEARCH_LIMIT}]"),
        offset: int | None = Field(default=None, description="The offset to start from."),
        sort: str | None = Field(default=None, description="field|asc or field|desc."),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """List recurring on-demand scans set up in the console: their schedule, targets and settings."""
        return self._search(
            "query_scheduled_scans", "get_scheduled_scans_by_scan_ids", filter, limit, offset,
            sort, "Failed to search scheduled scans",
        )

    # ------------------------------------------------------------------ #
    # Writes
    # ------------------------------------------------------------------ #

    def start_ods_scan(
        self,
        hosts: list[str] | None = Field(
            default=None,
            description=f"Host AIDs to scan, at most {MAX_SCAN_HOSTS}. Give hosts, host_groups or both.",
        ),
        host_groups: list[str] | None = Field(
            default=None,
            description=f"Host group IDs to scan, at most {MAX_HOST_GROUPS}.",
        ),
        file_paths: list[str] | None = Field(
            default=None,
            description=(
                "Windows and Linux paths or globs to scan, e.g. C:\\\\Users\\\\** or /tmp/**. "
                "Give file_paths, mac_file_paths or both."
            ),
        ),
        mac_file_paths: list[str] | None = Field(
            default=None,
            description="macOS paths or globs to scan, e.g. /Users/** or /Applications/**.",
        ),
        exclusions: list[str] | None = Field(
            default=None, description="Windows and Linux path globs to skip."
        ),
        mac_exclusions: list[str] | None = Field(
            default=None, description="macOS path globs to skip."
        ),
        quarantine: bool = Field(
            default=False,
            description=(
                "Quarantine malicious files the scan finds. False (default) only reports them."
            ),
        ),
        ml_level: int = Field(
            default=2,
            ge=0,
            le=4,
            description=(
                "Machine-learning sensitivity for both the sensor and the cloud, detection "
                "and prevention: 0 (off) to 4 (most aggressive). Default 2."
            ),
        ),
        cpu_priority: int = Field(
            default=1,
            ge=1,
            le=5,
            description="CPU the scan may use on each host, 1 (least) to 5 (most). Default 1.",
        ),
        endpoint_notification: bool = Field(
            default=True,
            description="Show the user on each host that a scan is running.",
        ),
        description: str | None = Field(default=None, description="A note identifying the scan."),
    ) -> dict[str, Any] | list[Any]:
        """Start an on-demand malware scan of chosen paths on hosts or host groups.

        The scan runs on each host as soon as it is online and uses its CPU; with
        `quarantine` it also quarantines what it finds. Use it to sweep hosts for a
        known threat or after an incident. Follow it with falcon_search_ods_scans,
        falcon_search_ods_scan_hosts and falcon_search_ods_malicious_files. Returns the
        API's response for the new scan.
        """
        operation = "create_scan"
        host_ids, problem = _clean_ids(hosts, MAX_SCAN_HOSTS, "host AID")
        if problem:
            return _error(problem, operation)
        group_ids, problem = _clean_ids(host_groups, MAX_HOST_GROUPS, "host group ID")
        if problem:
            return _error(problem, operation)
        if not host_ids and not group_ids:
            return _error("Give hosts, host_groups or both.", operation)

        paths, problem = _clean_paths(file_paths, "file_paths")
        mac_paths, problem2 = _clean_paths(mac_file_paths, "mac_file_paths")
        skip, problem3 = _clean_paths(exclusions, "exclusions")
        mac_skip, problem4 = _clean_paths(mac_exclusions, "mac_exclusions")
        problem = problem or problem2 or problem3 or problem4
        if problem:
            return _error(problem, operation)
        if not paths and not mac_paths:
            return _error("Give file_paths, mac_file_paths or both.", operation)
        if description is not None and len(description) > 1000:
            return _error("description must be at most 1000 characters.", operation)

        body: dict[str, Any] = {
            "quarantine": quarantine,
            "cpu_priority": cpu_priority,
            "endpoint_notification": endpoint_notification,
            "sensor_ml_level_detection": ml_level,
            "sensor_ml_level_prevention": ml_level,
            "cloud_ml_level_detection": ml_level,
            "cloud_ml_level_prevention": ml_level,
        }
        if host_ids:
            body["hosts"] = host_ids
        if group_ids:
            body["host_groups"] = group_ids
        if paths:
            body["file_paths"] = paths
        if skip:
            body["scan_exclusions"] = skip
        if mac_paths:
            body["mac_scan_inclusions"] = mac_paths
            body["mac_sensor_ml_level_detection"] = ml_level
            body["mac_sensor_ml_level_prevention"] = ml_level
            body["mac_cloud_ml_level_detection"] = ml_level
            body["mac_cloud_ml_level_prevention"] = ml_level
        if mac_skip:
            body["mac_scan_exclusions"] = mac_skip
        if description and description.strip():
            body["description"] = description.strip()

        logger.debug("Starting an on-demand scan on %d host(s), %d group(s)", len(host_ids), len(group_ids))
        response = self.client.command(operation, body=body)
        result: dict[str, Any] | list[Any] = handle_api_response(
            response, operation=operation, error_message="Failed to start the on-demand scan"
        )
        return result

    def cancel_ods_scans(
        self,
        ids: list[str] = Field(description=f"Scan IDs to cancel, at most {MAX_IDS}."),
    ) -> dict[str, Any] | list[Any]:
        """Cancel running on-demand scans. Files already quarantined stay quarantined."""
        operation = "cancel_scans"
        scan_ids, problem = _clean_ids(ids, MAX_IDS, "scan ID")
        if problem or not scan_ids:
            return _error(problem or "Give at least one scan ID.", operation)
        response = self.client.command(operation, body={"ids": scan_ids})
        result: dict[str, Any] | list[Any] = handle_api_response(
            response, operation=operation, error_message="Failed to cancel the scans"
        )
        return result

    def delete_ods_scheduled_scans(
        self,
        ids: list[str] = Field(description=f"Scheduled scan IDs to delete, at most {MAX_IDS}."),
    ) -> dict[str, Any] | list[Any]:
        """Delete scheduled on-demand scans so they stop recurring. This cannot be undone.

        Only the IDs given are deleted; this tool never deletes by filter.
        """
        operation = "delete_scheduled_scans"
        scan_ids, problem = _clean_ids(ids, MAX_IDS, "scheduled scan ID")
        if problem or not scan_ids:
            return _error(problem or "Give at least one scheduled scan ID.", operation)
        response = self.client.command(operation, parameters={"ids": scan_ids})
        result: dict[str, Any] | list[Any] = handle_api_response(
            response, operation=operation, error_message="Failed to delete the scheduled scans"
        )
        return result
