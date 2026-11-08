"""
MalQuery module for Falcon MCP Server

This module provides tools for searching CrowdStrike's MalQuery malware corpus and checking quota usage.
"""

import re
from typing import Any, Literal

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from pydantic import AnyUrl, Field

from falcon_mcp.common.errors import _format_error_response, handle_api_response
from falcon_mcp.common.logging import get_logger
from falcon_mcp.common.utils import prepare_api_parameters
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.malquery import MALQUERY_EXACT_SEARCH_GUIDE

logger = get_logger(__name__)

# MD5 (32), SHA-1 (40) or SHA-256 (64) hex digests.
HASH_PATTERN = re.compile(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")
# MalQuery request IDs are UUIDs.
REQUEST_ID_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
HEX_PATTERN = re.compile(r"(?:[0-9a-fA-F]{2}){2,}")
DATE_PATTERN = re.compile(r"\d{4}/\d{2}/\d{2}")
SIZE_PATTERN = re.compile(r"\d+(?:KB|MB|GB)?", re.IGNORECASE)
FILETYPE_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")

VALID_PATTERN_TYPES = {"ascii", "wide", "hex"}
VALID_FILTER_META = {"sha256", "md5", "type", "size", "first_seen", "label", "family"}
MAX_HASHES = 100
MIN_TEXT_PATTERN_LENGTH = 4
MAX_TEXT_PATTERN_LENGTH = 200
MAX_HEX_PATTERN_LENGTH = 400


class MalQueryModule(BaseModule):
    """Module for searching CrowdStrike's MalQuery malware corpus."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(
            server=server,
            method=self.get_malquery_quotas,
            name="get_malquery_quotas",
        )
        self._add_tool(
            server=server,
            method=self.get_malquery_file_metadata,
            name="get_malquery_file_metadata",
        )
        self._add_tool(
            server=server,
            method=self.start_malquery_exact_search,
            name="start_malquery_exact_search",
        )
        self._add_tool(
            server=server,
            method=self.get_malquery_request,
            name="get_malquery_request",
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP server.

        Args:
            server: MCP server instance
        """
        exact_search_guide = TextResource(
            uri=AnyUrl("falcon://malquery/exact-search/pattern-guide"),
            name="falcon_malquery_exact_search_guide",
            description=(
                "Pattern types, options and workflow for the `falcon_start_malquery_exact_search` "
                "and `falcon_get_malquery_request` tools."
            ),
            text=MALQUERY_EXACT_SEARCH_GUIDE,
        )
        self._add_resource(server, exact_search_guide)

    def get_malquery_quotas(self) -> dict[str, Any]:
        """Get MalQuery quota usage.

        Use this before a large hunt to check how many MalQuery searches and downloads
        the tenant has used and has left. Returns the quota counters and limits.
        """
        operation = "GetMalQueryQuotasV1"
        response = self.client.command(operation)

        result = handle_api_response(
            response,
            operation=operation,
            error_message="Failed to get MalQuery quotas",
            default_result=[],
        )
        if self._is_error(result):
            return result

        # The quota counters are returned in meta, not resources.
        meta = dict(response.get("body", {}).get("meta") or {})
        meta.pop("trace_id", None)
        meta.pop("powered_by", None)
        return {"quotas": meta}

    def get_malquery_file_metadata(
        self,
        hashes: list[str] = Field(
            description=(
                "File hashes to look up (1-100). MalQuery indexes files by SHA-256; MD5 and SHA-1 "
                "are accepted but may not match."
            ),
            min_length=1,
            max_length=MAX_HASHES,
            examples=[["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]],
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Get MalQuery metadata for file hashes.

        Use this when you have a file hash and want to know what CrowdStrike's malware
        corpus knows about it: file type, size, first-seen date, verdict label and malware
        family. The family and label are often good patterns for
        `falcon_start_malquery_exact_search`. Returns one record per hash MalQuery knows.
        """
        if not hashes:
            return _format_error_response(
                "Provide at least one hash.", operation="GetMalQueryMetadataV1"
            )
        if len(hashes) > MAX_HASHES:
            return _format_error_response(
                f"Provide at most {MAX_HASHES} hashes per call.", operation="GetMalQueryMetadataV1"
            )

        clean: list[str] = []
        for value in hashes:
            if not isinstance(value, str) or not HASH_PATTERN.fullmatch(value.strip()):
                return _format_error_response(
                    f"Invalid hash {value!r}. Use a hex MD5, SHA-1 or SHA-256 digest.",
                    operation="GetMalQueryMetadataV1",
                )
            normalized = value.strip().lower()
            if normalized not in clean:
                clean.append(normalized)

        return self._base_get_by_ids(
            operation="GetMalQueryMetadataV1",
            ids=clean,
            use_params=True,
        )

    def start_malquery_exact_search(
        self,
        pattern: str = Field(
            description=(
                "The exact string or byte sequence to find. For `hex`, write an even number of "
                "hex characters with no spaces or 0x prefix."
            ),
            examples=["evil-c2.example.com", "4d5a90000300"],
        ),
        pattern_type: Literal["ascii", "wide", "hex"] = Field(
            default="ascii",
            description=(
                "How to match `pattern`: `ascii` (single-byte string), `wide` (UTF-16LE string) "
                "or `hex` (byte sequence). Try `wide` if an `ascii` search finds nothing."
            ),
        ),
        limit: int = Field(
            default=100,
            ge=1,
            le=1000,
            description="Maximum number of matching samples to return.",
        ),
        filter_filetypes: list[str] | None = Field(
            default=None,
            description="Only match these file types, such as `pe32`, `pe64`, `elf64` or `pdf`.",
            examples=[["pe32", "pe64"]],
        ),
        filter_meta: list[str] | None = Field(
            default=None,
            description=(
                "Metadata fields to return for each match: sha256, md5, type, size, first_seen, "
                "label, family."
            ),
            examples=[["sha256", "family", "first_seen"]],
        ),
        min_date: str | None = Field(
            default=None,
            description="Only match samples first seen on or after this date, written YYYY/MM/DD.",
            examples=["2024/01/01"],
        ),
        max_date: str | None = Field(
            default=None,
            description="Only match samples first seen on or before this date, written YYYY/MM/DD.",
            examples=["2024/12/31"],
        ),
        min_size: str | None = Field(
            default=None,
            description="Minimum file size, in bytes or with a KB, MB or GB suffix.",
            examples=["10KB"],
        ),
        max_size: str | None = Field(
            default=None,
            description="Maximum file size, in bytes or with a KB, MB or GB suffix.",
            examples=["5MB"],
        ),
    ) -> dict[str, Any]:
        """Start a MalQuery exact search.

        Use this to find samples in CrowdStrike's malware corpus that contain a distinctive
        string or byte sequence, such as a C2 domain, PDB path or mutex name. It searches
        CrowdStrike's corpus, not your hosts, and doesn't change tenant state, but each search
        counts against the tenant's MalQuery quota. The search runs asynchronously: this
        returns a `request_id` to pass to `falcon_get_malquery_request`. See
        falcon://malquery/exact-search/pattern-guide for pattern types and options.
        """
        operation = "PostMalQueryExactSearchV1"

        def invalid(message: str) -> dict[str, Any]:
            return _format_error_response(message, operation=operation)

        if not isinstance(pattern, str) or not pattern.strip():
            return invalid("pattern must be a non-empty string.")
        value = pattern.strip()

        if pattern_type not in VALID_PATTERN_TYPES:
            return invalid(
                f"pattern_type must be one of: {', '.join(sorted(VALID_PATTERN_TYPES))}."
            )

        if pattern_type == "hex":
            if not HEX_PATTERN.fullmatch(value) or len(value) > MAX_HEX_PATTERN_LENGTH:
                return invalid(
                    "A hex pattern must be an even number of hex characters (at least 4, at most "
                    f"{MAX_HEX_PATTERN_LENGTH}) with no spaces or 0x prefix."
                )
            value = value.lower()
        else:
            if not MIN_TEXT_PATTERN_LENGTH <= len(value) <= MAX_TEXT_PATTERN_LENGTH:
                return invalid(
                    f"An {pattern_type} pattern must be {MIN_TEXT_PATTERN_LENGTH}-"
                    f"{MAX_TEXT_PATTERN_LENGTH} characters."
                )
            if pattern_type == "ascii" and not value.isascii():
                return invalid(
                    "An ascii pattern must contain only ASCII characters. Use `wide` for other text."
                )
            if not value.isprintable():
                return invalid(
                    "The pattern must not contain control characters. Use `hex` for raw bytes."
                )

        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            return invalid("limit must be between 1 and 1000.")

        if filter_filetypes is not None:
            bad = [
                t
                for t in filter_filetypes
                if not isinstance(t, str) or not FILETYPE_PATTERN.fullmatch(t)
            ]
            if bad:
                return invalid(
                    f"Invalid file type(s): {bad!r}. Use lowercase names such as pe32 or elf64."
                )

        if filter_meta is not None:
            bad = [m for m in filter_meta if m not in VALID_FILTER_META]
            if bad:
                return invalid(
                    f"Invalid filter_meta field(s): {bad!r}. Valid fields: {', '.join(sorted(VALID_FILTER_META))}."
                )

        for name, date in (("min_date", min_date), ("max_date", max_date)):
            if date is not None and (not isinstance(date, str) or not DATE_PATTERN.fullmatch(date)):
                return invalid(f"{name} must be written YYYY/MM/DD.")

        for name, size in (("min_size", min_size), ("max_size", max_size)):
            if size is not None and (not isinstance(size, str) or not SIZE_PATTERN.fullmatch(size)):
                return invalid(
                    f"{name} must be a number of bytes, optionally with a KB, MB or GB suffix."
                )

        options = prepare_api_parameters(
            {
                "limit": limit,
                "filter_filetypes": filter_filetypes or None,
                "filter_meta": filter_meta or None,
                "min_date": min_date,
                "max_date": max_date,
                "min_size": min_size.upper() if min_size else None,
                "max_size": max_size.upper() if max_size else None,
            }
        )
        body = {
            "patterns": [{"type": pattern_type, "value": value}],
            "options": options,
        }

        logger.debug("Starting MalQuery exact search (%s pattern)", pattern_type)
        response = self.client.command(operation, body=body)

        result = handle_api_response(
            response,
            operation=operation,
            error_message="Failed to start MalQuery exact search",
            default_result=[],
        )
        if self._is_error(result):
            return result

        meta = response.get("body", {}).get("meta") or {}
        request_id = meta.get("reqid")
        if not request_id:
            return _format_error_response(
                "MalQuery accepted the search but returned no request ID.",
                details=response,
                operation=operation,
            )
        return {
            "request_id": request_id,
            "status": meta.get("status"),
            "next_step": "Poll falcon_get_malquery_request with this request_id until status is done.",
        }

    def get_malquery_request(
        self,
        request_id: str = Field(
            description="The request ID returned by `falcon_start_malquery_exact_search`.",
            examples=["9f1c2e4a-6b7d-4c8e-9a0b-1c2d3e4f5a6b"],
        ),
    ) -> dict[str, Any]:
        """Get the status and results of a MalQuery search.

        Use this to poll a search started with `falcon_start_malquery_exact_search`. When
        `status` is `inprogress`, wait and call again; when it is `done`, `results` holds
        the matching samples.
        """
        operation = "GetMalQueryRequestV1"
        if not isinstance(request_id, str) or not REQUEST_ID_PATTERN.fullmatch(request_id.strip()):
            return _format_error_response(
                "request_id must be the UUID returned by falcon_start_malquery_exact_search.",
                operation=operation,
            )

        response = self.client.command(operation, parameters={"ids": request_id.strip()})

        result = handle_api_response(
            response,
            operation=operation,
            error_message="Failed to get MalQuery request",
            default_result=[],
        )
        if self._is_error(result):
            return result

        meta = response.get("body", {}).get("meta") or {}
        return {
            "request_id": meta.get("reqid") or request_id.strip(),
            "status": meta.get("status"),
            "results": result,
        }
