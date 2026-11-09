"""
NGSIEM module for Falcon MCP Server

This module provides tools for running search queries against CrowdStrike's
Next-Gen SIEM via the asynchronous job-based search API, read-only tools for
inspecting its ingest pipeline (data connections, parsers, and lookup files), a
process-tree reconstruction built on that search API, and an offline lookup of CQL
query functions.
"""

import asyncio
import difflib
import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from importlib import resources
from typing import Any

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from pydantic import AnyUrl, Field

from falcon_mcp.common.cql_lint import lint_cql
from falcon_mcp.common.errors import _format_error_response, handle_api_response
from falcon_mcp.common.logging import get_logger
from falcon_mcp.common.utils import unwrap_field_default
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.ngsiem import SEARCH_NGSIEM_CQL_DOCUMENTATION

logger = get_logger(__name__)

# Hint appended to error/empty responses steering the model to the CQL guide.
_CQL_ERROR_HINT = (
    "Review the CQL guide above and correct your query. CQL is a pipe-based "
    "language (filter | command | command) — not SQL or Splunk SPL. Consult "
    "`falcon://ngsiem/search/cql-guide` for the syntax and working examples."
)
# The API demotes unrecognized CQL words to free-text stages instead of erroring, so
# `job.parsed_query` (its own normalization of what ran) is the only misparse signal.
_CQL_CONFIRMED_ZERO_HINT = (
    "No rows matched, and the job scanned {processed_events:,} events — a real "
    "negative. Report it as such rather than retrying. If you expected rows, check "
    "`job.parsed_query` against the query you sent."
)

# A correct filter over an empty partition and a misparsed query both scan nothing.
_CQL_UNSCANNED_ZERO_HINT = (
    "No rows, and `job.processed_events` does not show a completed scan, so this alone "
    "is not a confirmed negative. Compare `job.parsed_query` to the query you sent: "
    "unrecognized words become free-text stages instead of an error. If it matches your "
    "intent the negative is real; if not, correct the syntax using the guide above."
)

# Configurable polling settings
POLL_INTERVAL_SECONDS = int(os.environ.get("FALCON_MCP_NGSIEM_POLL_INTERVAL", "5"))
TIMEOUT_SECONDS = int(os.environ.get("FALCON_MCP_NGSIEM_TIMEOUT", "300"))

# Bounds for the optional per-call settings on falcon_search_ngsiem.
MAX_HOURS_BACK = 24 * 90
MIN_TIME_BUDGET_SECONDS = 10
MAX_TIME_BUDGET_SECONDS = 290
MAX_ROWS_LIMIT = 10_000

# `repository` is the only caller-supplied value in this server that reaches a URL
# path variable (/humio/api/v1/repositories/{repository}/queryjobs). FalconPy
# interpolates it into the route and `requests` normalizes the path before sending,
# so a separator or a bare dot-segment retargets the request at a route the calling
# operation never selected. A separator is what makes traversal possible, so once
# those are rejected only a whole-value dot-segment can still alter the path —
# `a..b` is inert and stays allowed.
_UNSAFE_REPOSITORY_CHARS = ("/", "\\", "%")
_DOT_SEGMENTS = (".", "..")

# ListParsers accepts only this repository: parsers live in a dedicated repository
# rather than in the searchable views.
_PARSERS_REPOSITORY = "parsers-repository"
_PARSER_TYPES = ("ootb", "custom", "extension")
# Search domains (views or repositories) that ListLookupFiles accepts.
_LOOKUP_FILE_SEARCH_DOMAINS = (
    "all",
    "falcon",
    "third-party",
    "dashboards",
    "parsers-repository",
    "query-audit",
)


def _validate_repository(repository: Any) -> dict[str, Any] | None:
    """Reject a repository value that would change which route is called.

    Returns an error response to hand straight back to the caller, or None when the
    value is safe to interpolate.

    A non-str value is an unresolved Pydantic `Field` default, which happens only when
    the tool method is called directly instead of through FastMCP — the same reason
    `end` is guarded with `isinstance` below. FastMCP validates against the `str`
    annotation before dispatch, and the declared default is safe, so let it through.

    Args:
        repository: The caller-supplied repository or view name

    Returns:
        An error response dict, or None if the value is acceptable
    """
    if not isinstance(repository, str):
        return None

    if not repository.strip():
        return _format_error_response(
            "Invalid repository: must be a non-empty repository or view name, "
            "for example 'search-all'.",
            operation="StartSearchV1",
        )

    if any(char in repository for char in _UNSAFE_REPOSITORY_CHARS) or repository in _DOT_SEGMENTS:
        return _format_error_response(
            f"Invalid repository {repository!r}: must not contain '/', '\\', or '%', "
            "or be '.' or '..'. Pass a plain repository or view name, "
            "for example 'search-all'.",
            operation="StartSearchV1",
        )

    return None


def _iso_to_epoch_ms(iso_timestamp: str) -> int:
    """Convert ISO 8601 timestamp to Unix epoch milliseconds.

    Args:
        iso_timestamp: ISO 8601 formatted timestamp (e.g., "2025-01-01T00:00:00Z")

    Returns:
        Unix epoch time in milliseconds
    """
    dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
    return int(dt.timestamp() * 1000)


def _resolve_search_window(
    start: str | None,
    end: str | None,
    hours_back: float | None,
) -> dict[str, Any]:
    """Turn start/end or hours_back into epoch milliseconds, or an error response."""
    if start is not None and hours_back is not None:
        return _format_error_response(
            "Pass start or hours_back, not both.", operation="StartSearchV1"
        )
    try:
        end_ms = _iso_to_epoch_ms(end) if isinstance(end, str) else None
        if isinstance(start, str):
            start_ms = _iso_to_epoch_ms(start)
        elif hours_back is not None:
            anchor_ms = end_ms if end_ms is not None else int(time.time() * 1000)
            start_ms = anchor_ms - int(float(hours_back) * 3_600_000)
        else:
            return _format_error_response(
                "Pass start (an ISO 8601 timestamp) or hours_back.",
                operation="StartSearchV1",
            )
    except ValueError as exc:
        return _format_error_response(
            f"Invalid timestamp: {exc}. Use ISO 8601, for example 2025-01-01T00:00:00Z.",
            operation="StartSearchV1",
        )
    return {"start_ms": start_ms, "end_ms": end_ms}


def _epoch_ms_to_iso(epoch_ms: Any) -> str | None:
    """Convert Unix epoch milliseconds to an ISO 8601 UTC timestamp.

    Args:
        epoch_ms: Unix epoch time in milliseconds

    Returns:
        ISO 8601 timestamp string, or None if the value is not a usable number
    """
    if isinstance(epoch_ms, bool) or not isinstance(epoch_ms, (int, float)):
        return None
    try:
        return (
            datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except (OSError, OverflowError, ValueError):
        return None


# --- Process tree reconstruction ------------------------------------------------
#
# Every value placed into the CQL below is validated against one of these patterns
# first, so no caller-supplied or event-supplied text can change the query's shape.
_DEVICE_ID_PATTERN = re.compile(r"[0-9a-fA-F]{32}", re.ASCII)
_PROCESS_ID_PATTERN = re.compile(r"[0-9]{1,20}", re.ASCII)
# An image basename such as `powershell.exe`. It is only compared locally, never
# written into a query, but the narrow charset keeps it that way by construction.
_IMAGE_NAME_PATTERN = re.compile(r"[A-Za-z0-9._ -]{1,128}", re.ASCII)
_MAX_PIVOT_TIME_LENGTH = 64

_PROCESS_TREE_REPOSITORY = "search-all"
_PROCESS_TREE_EVENT_LIMIT = 5000
# Window search, anchor probe, re-anchored window search, one parent lookup.
_PROCESS_TREE_MAX_SEARCHES = 4
_ANCHOR_PROBE_LOOKBACK = timedelta(days=7)
_PARENT_LOOKUP_RADIUS = timedelta(minutes=60)
_PARENT_LOOKUP_LIMIT = 5
_COMMAND_LINE_MAX_CHARS = 1000

# ProcessRollup2 fields the tree needs. TargetProcessId and ParentProcessId are the
# sensor's process identifiers that link rows; RawProcessId is the OS pid.
_PROCESS_ROLLUP_FIELDS = (
    "@timestamp",
    "aid",
    "TargetProcessId",
    "ParentProcessId",
    "ContextProcessId",
    "RawProcessId",
    "ImageFileName",
    "FileName",
    "CommandLine",
    "UserName",
    "UserSid",
    "SHA256HashData",
    "ProcessStartTime",
)


def _is_valid_process_id(value: Any) -> bool:
    return isinstance(value, str) and _PROCESS_ID_PATTERN.fullmatch(value) is not None


def _process_rollup_query(device_id: str, limit: int, target_process_id: str | None = None) -> str:
    """Build the ProcessRollup2 CQL query for one host, optionally one process.

    Every interpolated value is re-validated here, so the builder is safe even if a
    caller skips its own checks. Raises ValueError rather than emitting a query that
    contains anything but hex digits, decimal digits and fixed text.

    Args:
        device_id: The host's 32-character hex AID
        limit: Maximum rows to return
        target_process_id: Only return the process with this TargetProcessId

    Returns:
        The CQL query string
    """
    if not isinstance(device_id, str) or not _DEVICE_ID_PATTERN.fullmatch(device_id):
        raise ValueError("device_id must be 32 hexadecimal characters")
    if target_process_id is not None and not _is_valid_process_id(target_process_id):
        raise ValueError("process ids must be 1-20 decimal digits")
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("limit must be an integer")
    if not 1 <= limit <= _PROCESS_TREE_EVENT_LIMIT:
        raise ValueError(f"limit must be between 1 and {_PROCESS_TREE_EVENT_LIMIT}")

    query_filter = f'#event_simpleName=ProcessRollup2 aid="{device_id.lower()}"'
    if target_process_id is not None:
        query_filter += f' TargetProcessId="{target_process_id}"'
    return (
        f"{query_filter}\n"
        f"| select([{', '.join(_PROCESS_ROLLUP_FIELDS)}])\n"
        # sort() keeps only 200 rows unless given an explicit limit.
        f"| sort(@timestamp, order=asc, limit={limit})"
    )


def _parse_pivot_time(value: Any) -> datetime | None:
    """Parse an ISO 8601 timestamp, treating a missing offset as UTC."""
    if not isinstance(value, str) or not 0 < len(value) <= _MAX_PIVOT_TIME_LENGTH:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _to_ms(moment: datetime) -> int:
    return int(moment.timestamp() * 1000)


def _id_string(value: Any) -> str | None:
    """Return a process id from an event as a digit string, or None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        value = str(value)
    if isinstance(value, str):
        value = value.strip()
        if _is_valid_process_id(value):
            return value
    return None


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _process_node(event: dict[str, Any]) -> dict[str, Any]:
    """Shape a ProcessRollup2 event into a tree node.

    Ids stay strings: they can exceed the integers a JSON client represents exactly.
    The private `_start_ms` key orders nodes and is removed before returning them.
    """
    timestamp_ms = _number(event.get("@timestamp"))
    start_seconds = _number(event.get("ProcessStartTime"))
    start_ms = start_seconds * 1000 if start_seconds is not None else timestamp_ms

    command_line = event.get("CommandLine")
    command_line = str(command_line) if command_line is not None else None
    if command_line is not None and len(command_line) > _COMMAND_LINE_MAX_CHARS:
        command_line = command_line[:_COMMAND_LINE_MAX_CHARS] + "..."

    return {
        "process_id": _id_string(event.get("TargetProcessId")),
        "parent_process_id": (
            _id_string(event.get("ParentProcessId")) or _id_string(event.get("ContextProcessId"))
        ),
        "os_pid": _id_string(event.get("RawProcessId")),
        "image": str(event.get("ImageFileName") or event.get("FileName") or "") or None,
        "command_line": command_line,
        "user_name": event.get("UserName") or None,
        "user_sid": event.get("UserSid") or None,
        "sha256": event.get("SHA256HashData") or None,
        "process_start_time": _epoch_ms_to_iso(start_ms) if start_seconds is not None else None,
        "timestamp": _epoch_ms_to_iso(timestamp_ms),
        "_start_ms": start_ms,
    }


def _public_node(node: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in node.items() if not key.startswith("_")}


def _image_basename(image: Any) -> str:
    if not isinstance(image, str) or not image:
        return ""
    return re.split(r"[\\/]", image)[-1].lower()


# --- Delivery-vector heuristic ----------------------------------------------------
#
# A deterministic heuristic over image basenames and command lines in the ancestry.
# It suggests how a process chain started; it is not a detection or a verdict.

_MAIL_CLIENTS = frozenset({"outlook.exe", "olk.exe", "hxoutlook.exe", "thunderbird.exe"})
_OFFICE_APPS = frozenset(
    {
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "msaccess.exe",
        "mspub.exe",
        "visio.exe",
        "onenote.exe",
    }
)
_BROWSERS = frozenset(
    {
        "chrome.exe",
        "msedge.exe",
        "iexplore.exe",
        "firefox.exe",
        "brave.exe",
        "opera.exe",
        "vivaldi.exe",
    }
)
_ARCHIVE_TOOLS = frozenset(
    {"7zfm.exe", "7zg.exe", "winrar.exe", "rar.exe", "bandizip.exe", "peazip.exe"}
)
_SCRIPT_HOSTS = frozenset(
    {
        "cmd.exe",
        "powershell.exe",
        "powershell_ise.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "regsvr32.exe",
        "rundll32.exe",
        "msiexec.exe",
        "installutil.exe",
        "regasm.exe",
        "regsvcs.exe",
        "msbuild.exe",
    }
)
_INTERPRETERS = frozenset(
    {
        "python.exe",
        "pythonw.exe",
        "python3.exe",
        "py.exe",
        "node.exe",
        "ruby.exe",
        "perl.exe",
    }
)
# Command-line shapes typical of a remote-control agent hosted by an interpreter.
_AGENT_COMMAND_LINE = re.compile(
    r"""(
        --server\s+https?://
      | (^|\s)-c2\s
      | --c2-?(server|host|url)\s
      | --listener\s
      | --beacon[=\s]
      | \\(agent|beacon|implant)[\w-]*\.py\b
      | https?://[\w.-]+:\d{4,5}\b
    )""",
    re.IGNORECASE | re.VERBOSE,
)
_REMOTE_EXECUTION_HOSTS = frozenset({"wsmprovhost.exe", "psexesvc.exe", "paexec.exe"})
_TASK_HOSTS = frozenset({"taskhostw.exe", "taskhost.exe", "taskeng.exe"})
_WMI_HOSTS = frozenset({"wmiprvse.exe", "scrcons.exe"})
_MAIL_ATTACHMENT_PATHS = (
    "\\inetcache\\content.outlook\\",
    "\\temporary internet files\\content.outlook",
    "\\appdata\\local\\microsoft\\olk\\",
)
_USER_DROP_PATHS = (
    "\\downloads\\",
    "\\desktop\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
)
_DOCUMENT_PATH = re.compile(
    r"[A-Za-z]:\\[^'\"<>|]+?\.(?:docm?|xlsm?|xlsb|pptm?|ppam|dotm|xlam|rtf|pdf)\b",
    re.IGNORECASE,
)
_WINDOWS_PATH = re.compile(r"[A-Za-z]:\\[^\s'\"<>|]+")
_URL = re.compile(r"https?://[\w.-]+(?::\d+)?(?:/\S*)?")

_DELIVERY_VECTOR_NOTE = (
    "Heuristic suggestion from image names and command lines in the ancestry only. "
    "Confirm against the events before acting on it."
)


def _first_index(images: list[str], names: frozenset[str]) -> int | None:
    return next((i for i, image in enumerate(images) if image in names), None)


def _user_drop_path(chain: list[dict[str, Any]]) -> str | None:
    for node in chain:
        image = node.get("image") or ""
        if any(fragment in image.lower() for fragment in _USER_DROP_PATHS):
            return image
        command_line = node.get("command_line") or ""
        if any(fragment in command_line.lower() for fragment in _USER_DROP_PATHS):
            match = _WINDOWS_PATH.search(command_line)
            return match.group(0) if match else None
    return None


def _classify_delivery_vector(
    chain: list[dict[str, Any]], parent_lookup_widened: bool
) -> dict[str, Any]:
    """Suggest how a process chain started, from its images and command lines.

    Args:
        chain: The pivot first, then its ancestors, nearest first
        parent_lookup_widened: True when a parent was found outside the main window,
            which lowers a high confidence to medium

    Returns:
        `{kind, confidence, rationale, method, note}` plus, when one node explains
        the chain, `anchor_process_id`, `anchor_image` and possibly `artifact`
    """
    images = [_image_basename(node.get("image")) for node in chain]

    def verdict(
        kind: str,
        confidence: str,
        rationale: str,
        anchor: int | None = None,
        artifact: str | None = None,
    ) -> dict[str, Any]:
        if parent_lookup_widened and confidence == "high":
            confidence = "medium"
        result: dict[str, Any] = {
            "kind": kind,
            "confidence": confidence,
            "rationale": rationale,
            "method": "heuristic",
            "note": _DELIVERY_VECTOR_NOTE,
        }
        if anchor is not None:
            result["anchor_process_id"] = chain[anchor].get("process_id")
            result["anchor_image"] = chain[anchor].get("image")
        if artifact:
            result["artifact"] = artifact
        return result

    if not chain:
        return verdict("unknown", "low", "No ancestry is available.")

    office = _first_index(images, _OFFICE_APPS)
    mail = _first_index(images, _MAIL_CLIENTS)
    if office is not None:
        command_line = chain[office].get("command_line") or ""
        match = _DOCUMENT_PATH.search(command_line)
        document = match.group(0) if match else None
        what = document or "a document"
        if mail is not None and mail > office:
            return verdict(
                "phishing_doc",
                "high",
                f"{images[office]} opened {what} under {images[mail]}.",
                anchor=mail,
                artifact=document,
            )
        if any(fragment in command_line.lower() for fragment in _MAIL_ATTACHMENT_PATHS):
            return verdict(
                "phishing_doc",
                "high",
                f"{images[office]} opened {what} from a mail attachment cache path.",
                anchor=office,
                artifact=document,
            )
        return verdict(
            "malicious_document",
            "medium",
            f"{images[office]} opened {what}; no mail client in the ancestry.",
            anchor=office,
            artifact=document,
        )

    if mail is not None:
        return verdict(
            "phishing_email_direct",
            "high",
            f"{images[mail]} started the chain without an Office application in between.",
            anchor=mail,
        )

    browser = _first_index(images, _BROWSERS)
    if browser is not None:
        drop = _user_drop_path(chain)
        if drop:
            return verdict(
                "browser_drive_by",
                "medium",
                f"{images[browser]} is an ancestor and the chain runs from {drop}.",
                anchor=browser,
                artifact=drop,
            )
        return verdict(
            "browser_drive_by",
            "low",
            f"{images[browser]} is an ancestor, but no download or temp path was seen.",
            anchor=browser,
        )

    archive = _first_index(images, _ARCHIVE_TOOLS)
    if archive is not None:
        return verdict(
            "archive_extraction",
            "medium",
            f"{images[archive]} is an ancestor: the chain started from an extracted file.",
            anchor=archive,
        )

    remote = _first_index(images, _REMOTE_EXECUTION_HOSTS)
    if remote is not None:
        if images[remote] == "wsmprovhost.exe":
            return verdict(
                "lateral_winrm",
                "high",
                "wsmprovhost.exe is an ancestor: the chain was started over WinRM remoting.",
                anchor=remote,
            )
        return verdict(
            "lateral_psexec",
            "high",
            f"{images[remote]} is an ancestor: the chain was started by a remote "
            "service-execution tool.",
            anchor=remote,
        )

    task = _first_index(images, _TASK_HOSTS)
    if task is not None and task >= 1:
        return verdict(
            "scheduled_task",
            "medium",
            f"{images[task]} is an ancestor: a scheduled task started the chain.",
            anchor=task,
        )

    wmi = _first_index(images, _WMI_HOSTS)
    if wmi is not None:
        return verdict(
            "wmi_execution",
            "medium",
            f"{images[wmi]} is an ancestor: the chain was started through WMI.",
            anchor=wmi,
        )

    explorer = _first_index(images, frozenset({"explorer.exe"}))
    if explorer is not None:
        drop = _user_drop_path(chain)
        if drop:
            return verdict(
                "user_executed_file",
                "medium",
                f"explorer.exe started the chain from {drop}.",
                anchor=explorer,
                artifact=drop,
            )

    for index, node in enumerate(chain):
        command_line = node.get("command_line") or ""
        if images[index] in _INTERPRETERS and _AGENT_COMMAND_LINE.search(command_line):
            match = _URL.search(command_line)
            url = match.group(0) if match else None
            return verdict(
                "interpreter_agent",
                "high",
                f"{images[index]} runs a script whose command line looks like a "
                "remote-control agent" + (f" pointed at {url}." if url else "."),
                anchor=index,
                artifact=url,
            )

    script_host = _first_index(images, _SCRIPT_HOSTS)
    if script_host is not None and script_host == len(chain) - 1:
        return verdict(
            "script_host_root",
            "low",
            f"The ancestry ends at {images[script_host]} with nothing above it; its "
            "parent may be outside the searched window.",
            anchor=script_host,
        )

    service = _first_index(images, frozenset({"services.exe"}))
    if service is not None and service >= 1:
        return verdict(
            "service",
            "medium",
            "services.exe is an ancestor: the chain runs as a Windows service.",
            anchor=service,
        )

    return verdict(
        "unknown",
        "low",
        "No recognized starting point (mail, browser, Office, archive, remote execution, "
        "scheduled task, WMI or service) in the ancestry.",
    )


# --- CQL function catalog ---------------------------------------------------------

_CQL_CATALOG_FILE = "cql_functions.json"
_CQL_FUNCTION_QUERY_MAX_LENGTH = 128
_CQL_FUNCTION_CANDIDATE_LIMIT = 10


@lru_cache(maxsize=1)
def _load_cql_catalog() -> dict[str, dict[str, Any]]:
    """Load the CQL function catalog shipped in `falcon_mcp.resources`, keyed by name."""
    text = (
        resources.files("falcon_mcp.resources")
        .joinpath(_CQL_CATALOG_FILE)
        .read_text(encoding="utf-8")
    )
    data = json.loads(text)
    return {function["name"]: function for function in data.get("functions", [])}


# Names models reach for that are not CQL functions, with what to use instead.
_CQL_NON_FUNCTIONS = {
    "limit": "Use head(N) to keep the first N rows; to cap sort(), pass limit=N inside it.",
    "where": "Filter by writing the condition as its own pipeline stage, or use test().",
    "dedup": "Use groupBy() on the fields that identify a duplicate, or head() per group.",
    "distinct": "Use groupBy() for distinct values, or count(field, distinct=true).",
    "fields": "Use select() or table() to choose fields.",
}


@dataclass
class _SearchBudget:
    """Searches run so far by one process-tree request, and when it must stop."""

    deadline: float
    searches: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _sorted_nodes(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Turn events into tree nodes ordered by process start."""
    nodes = [_process_node(event) for event in events if isinstance(event, dict)]
    nodes.sort(key=lambda node: (node["_start_ms"] is None, node["_start_ms"] or 0))
    return nodes


def _find_pivot(
    rows: list[dict[str, Any]],
    target_pid: str | None,
    image_name: str | None,
    pivot_ms: float,
) -> dict[str, Any] | None:
    """Find the pivot by process id, or else the named image closest to the pivot time."""
    if target_pid is not None:
        return next((row for row in rows if row["process_id"] == target_pid), None)
    best: tuple[float, dict[str, Any]] | None = None
    for row in rows:
        if _image_basename(row["image"]) != image_name:
            continue
        start = row["_start_ms"]
        delta = abs(start - pivot_ms) if start is not None else float("inf")
        if best is None or delta < best[0]:
            best = (delta, row)
    return best[1] if best else None


def _walk_descendants(
    rows: list[dict[str, Any]], pivot: dict[str, Any], limit: int
) -> tuple[list[dict[str, Any]], bool]:
    """Collect the pivot's descendants breadth first, in start order within a level.

    Returns:
        The descendants with their depth below the pivot, and whether more existed
        than `limit` allowed
    """
    children: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if row["parent_process_id"]:
            children.setdefault(row["parent_process_id"], []).append(row)

    descendants: list[dict[str, Any]] = []
    seen = {pivot["process_id"]}
    queue: list[tuple[str, int]] = [(pivot["process_id"], 1)] if pivot["process_id"] else []
    while queue:
        parent_id, depth = queue.pop(0)
        for child in children.get(parent_id, []):
            child_id = child["process_id"]
            if not child_id or child_id in seen:
                continue
            if len(descendants) >= limit:
                return descendants, True
            seen.add(child_id)
            descendants.append({**child, "depth": depth})
            queue.append((child_id, depth + 1))
    return descendants, False


@dataclass
class _SearchJobOutcome:
    """What one NGSIEM search job produced.

    Exactly one of three shapes: `events` set (completed, possibly empty), `error`
    set (the API refused or failed), or `timed_out` true (stopped before completion).
    """

    events: list[dict[str, Any]] | None = None
    job: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    job_id: str | None = None
    timed_out: bool = False
    stop_status_code: Any = None
    # Rows the last status poll returned before the job was stopped.
    partial_events: list[dict[str, Any]] | None = None


class NGSIEMModule(BaseModule):
    """Module for searching CrowdStrike Next-Gen SIEM and inspecting its ingest pipeline."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(
            server=server,
            method=self.search_ngsiem,
            name="search_ngsiem",
        )

        self._add_tool(
            server=server,
            method=self.list_ngsiem_data_connections,
            name="list_ngsiem_data_connections",
        )

        self._add_tool(
            server=server,
            method=self.get_ngsiem_data_connection_status,
            name="get_ngsiem_data_connection_status",
        )

        self._add_tool(
            server=server,
            method=self.list_ngsiem_parsers,
            name="list_ngsiem_parsers",
        )

        self._add_tool(
            server=server,
            method=self.list_ngsiem_lookup_files,
            name="list_ngsiem_lookup_files",
        )

        self._add_tool(
            server=server,
            method=self.get_process_tree,
            name="get_process_tree",
        )

        self._add_tool(
            server=server,
            method=self.lookup_cql_function,
            name="lookup_cql_function",
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP server.

        Args:
            server: MCP server instance
        """
        search_ngsiem_cql_resource = TextResource(
            uri=AnyUrl("falcon://ngsiem/search/cql-guide"),
            name="falcon_search_ngsiem_cql_guide",
            description="Contains the CQL authoring guide for the `query_string` param of the `falcon_search_ngsiem` tool.",
            text=SEARCH_NGSIEM_CQL_DOCUMENTATION,
        )

        self._add_resource(
            server,
            search_ngsiem_cql_resource,
        )

    def _format_cql_error_response(
        self,
        error_response: dict[str, Any],
        query_string: str,
    ) -> dict[str, Any]:
        """Augment an error response with the CQL guide and a repair hint.

        Reaches the model with the full CQL authoring guide exactly when its query
        failed, so it can correct the syntax and retry. Mirrors
        `_format_fql_error_response` but for CQL (the API returns no CQL parser
        diagnostics, so the guide is the only actionable signal).

        Args:
            error_response: The error dict produced by the shared error handlers
            query_string: The CQL query that was attempted

        Returns:
            The error dict with `cql_guide`, `hint`, and `query_used` added
        """
        error_response["query_used"] = query_string
        error_response["cql_guide"] = SEARCH_NGSIEM_CQL_DOCUMENTATION
        error_response["hint"] = _CQL_ERROR_HINT
        return error_response

    @staticmethod
    def _extract_job_metadata(
        body: dict[str, Any],
        repository: str,
        job_id: str,
    ) -> dict[str, Any]:
        """Map a search-status body onto the `job` block of the response envelope.

        Fields the response omits are reported as None, never defaulted to 0.

        Args:
            body: The `body` of a 200 GetSearchStatusV1 response
            repository: The repository the job ran against
            job_id: The search job ID

        Returns:
            Dict of job metadata suitable for the `job` key of the response envelope
        """
        meta = body.get("metaData") or {}
        filter_query = meta.get("filterQuery") or {}
        # Job-level and query-level warnings are scoped separately; callers want both.
        warnings = [*(body.get("warnings") or []), *(meta.get("warnings") or [])]

        return {
            "job_id": job_id,
            "repository": repository,
            "event_count": meta.get("eventCount"),
            "processed_events": meta.get("processedEvents"),
            "processed_bytes": meta.get("processedBytes"),
            "parsed_query": filter_query.get("queryString"),
            "search_start": _epoch_ms_to_iso(meta.get("queryStart")),
            "search_end": _epoch_ms_to_iso(meta.get("queryEnd")),
            "duration_ms": meta.get("timeMillis"),
            "is_aggregate": meta.get("isAggregate"),
            "cancelled": body.get("cancelled"),
            "warnings": warnings,
        }

    def _build_job_envelope(
        self,
        events: list[dict[str, Any]],
        job: dict[str, Any],
        query_string: str,
    ) -> dict[str, Any]:
        """Assemble the response envelope, identical in shape for any row count.

        NG-SIEM jobs carry no `meta.pagination`, so this keeps the house `results` key
        and swaps the pagination block for a `job` block. Zero rows also get the CQL
        guide and a hint chosen from `job.processed_events`.

        Args:
            events: The event records returned by the job
            job: Job metadata from `_extract_job_metadata`
            query_string: The CQL query as submitted

        Returns:
            Dict with `results`, `query_used`, `job`, and on zero rows also
            `cql_guide` and `hint`
        """
        envelope: dict[str, Any] = {
            "results": events,
            "query_used": query_string,
            "job": job,
        }

        if events:
            return envelope

        processed = job.get("processed_events")
        if isinstance(processed, int) and not isinstance(processed, bool) and processed > 0:
            hint = _CQL_CONFIRMED_ZERO_HINT.format(processed_events=processed)
        else:
            hint = _CQL_UNSCANNED_ZERO_HINT

        envelope["cql_guide"] = SEARCH_NGSIEM_CQL_DOCUMENTATION
        envelope["hint"] = hint
        return envelope

    async def search_ngsiem(
        self,
        query_string: str = Field(
            description=(
                "The CQL (CrowdStrike Query Language) query to execute. "
                "Consult `falcon://ngsiem/search/cql-guide` to construct this query. "
                "CQL is pipe-based: `filter | command | command` — not SQL or Splunk "
                "SPL (do not use SELECT/WHERE/stats/`| limit`). Build a query by "
                "starting from a tag or field filter and piping into commands. "
                "Common building blocks: tag filter `#event_simpleName=ProcessRollup2`; "
                "field match `UserName=*`; aggregate `groupBy([ComputerName], function=count())`; "
                "order `sort(_count, order=desc)`; limit raw events `head(5)`. "
                "Examples: '#event_simpleName=ProcessRollup2 | head(5)' and "
                "'#event_simpleName=ProcessRollup2 | groupBy([ComputerName], function=count()) "
                "| sort(_count, order=desc)'. "
                "For anything beyond these building blocks (distinct count, time "
                "bucketing, regex/contains match, filtering on an aggregate), read "
                "`falcon://ngsiem/search/cql-guide` — it has working examples."
            ),
        ),
        start: str | None = Field(
            default=None,
            description=(
                "Search start time as an ISO 8601 timestamp. Required unless hours_back "
                "is given. Example: start='2025-01-01T00:00:00Z'"
            ),
            examples={"2025-01-01T00:00:00Z"},
        ),
        repository: str = Field(
            default="search-all",
            description=(
                "Repository (or view) to search. Defaults to search-all (all event "
                "data). Which repositories exist depends on the users tenant and its "
                "configuration, so this is not a closed list. Common repositories/views: "
                "search-all (all event data), "
                "investigate_view (endpoint events), "
                "xdr (XDR data), "
                "third-party (third-party source events), "
                "falcon_for_it_view (Falcon for IT data), "
                "forensics_view (Falcon Forensics triage data). "
                "Custom and other built-in repositories/views can also be passed by name. "
                "Pass the bare name only: values containing '/', '\\', or '%' are rejected."
            ),
        ),
        end: str | None = Field(
            default=None,
            description=(
                "Search end time as an ISO 8601 timestamp. "
                "If not provided, defaults to the current time. "
                "Example: end='2025-02-06T00:00:00Z'"
            ),
            examples={"2025-01-01T00:00:00Z"},
        ),
        hours_back: float | None = Field(
            default=None,
            gt=0,
            le=MAX_HOURS_BACK,
            description=(
                "Shortcut for the window: search this many hours back from end (or from "
                "now). Use instead of start."
            ),
        ),
        check_cql: bool = Field(
            default=False,
            description=(
                "Check the query locally before sending it. Common mistakes fail at once "
                "with ok=false, the issues in `cql_lint` and a corrected query in `fix`: "
                "limit(N) instead of head(N), single-quoted strings, a tag field such as "
                "event_simpleName without its # prefix, and sort() without limit=, which "
                "silently keeps only 200 rows."
            ),
        ),
        max_rows: int | None = Field(
            default=None,
            ge=1,
            le=MAX_ROWS_LIMIT,
            description=(
                "Return at most this many rows. When more came back, `truncated` is true "
                "and `total_rows` gives the full count."
            ),
        ),
        time_budget_seconds: int | None = Field(
            default=None,
            ge=MIN_TIME_BUDGET_SECONDS,
            le=MAX_TIME_BUDGET_SECONDS,
            description=(
                "Stop the search after this many seconds and return the rows found so far "
                "with `partial` set to true, instead of an error. Use about 50 to stay "
                "under a 60-second client timeout. Without it, the search runs up to "
                "FALCON_MCP_NGSIEM_TIMEOUT seconds and a timeout is an error."
            ),
        ),
    ) -> dict[str, Any]:
        """Execute a CQL (CrowdStrike Query Language) query against CrowdStrike Next-Gen SIEM.

        Use this to search security events, logs, and telemetry with CQL. CQL is a
        pipe-based language (`filter | command | command`): start from a tag or field
        filter (e.g. `#event_simpleName=ProcessRollup2`, `UserName=*`) and pipe into
        commands like `groupBy([...], function=count())` and `sort()`; keep the time
        range tight. Consult `falcon://ngsiem/search/cql-guide` to construct the query —
        it has the pipe model, core commands, and working examples (distinct count, time
        bucketing, regex match, filtering on an aggregate). Returns
        `{results, query_used, job}`, where `job` carries the row count, events scanned,
        the window searched, and `job.parsed_query` — the API's own normalization of the
        query it ran. Check `job.parsed_query` against your intent: unrecognized words
        become free-text stages instead of an error, so `| limit 5` runs as `| limit | 5`
        and returns the wrong rows silently. On zero rows a hint says whether the job
        scanned events (a real negative) or scanned none (unresolved). Search times out
        after FALCON_MCP_NGSIEM_TIMEOUT seconds (default: 300).

        For a bounded call, set check_cql=true, max_rows and time_budget_seconds (about
        50): mistakes fail locally with a fix, large results are cut to max_rows with
        `truncated` set, and a slow search returns partial rows with `partial` set.
        """
        repository = unwrap_field_default(repository)
        start = unwrap_field_default(start)
        end = unwrap_field_default(end)
        hours_back = unwrap_field_default(hours_back)
        check_cql = unwrap_field_default(check_cql)
        max_rows = unwrap_field_default(max_rows)
        time_budget_seconds = unwrap_field_default(time_budget_seconds)

        # `repository` is interpolated into the request path, so validate it before it
        # can reach any of the three calls below.
        repository_error = _validate_repository(repository)
        if repository_error is not None:
            return repository_error

        if check_cql:
            issues, fixed = lint_cql(query_string)
            if issues:
                return {
                    "ok": False,
                    "error": "The CQL query has mistakes that would fail or return wrong rows.",
                    "cql_lint": issues,
                    "cql": query_string,
                    "fix": fixed,
                }

        window = _resolve_search_window(start, end, hours_back)
        if "error" in window:
            return window

        bounded = time_budget_seconds is not None
        timeout_seconds = time_budget_seconds if bounded else TIMEOUT_SECONDS
        outcome = await self._run_search_job(
            query_string=query_string,
            start_ms=window["start_ms"],
            end_ms=window["end_ms"],
            repository=repository,
            timeout_seconds=timeout_seconds,
            deadline=time.monotonic() + timeout_seconds if bounded else None,
        )

        if outcome.error is not None:
            return self._format_cql_error_response(outcome.error, query_string)

        if outcome.timed_out and bounded:
            envelope = self._build_job_envelope(
                outcome.partial_events or [], outcome.job or {}, query_string
            )
            envelope["partial"] = True
            envelope["partial_reason"] = (
                f"The search did not finish within {timeout_seconds} seconds, so it was "
                "stopped. These are the rows found so far; narrow the window or the query "
                "for a complete answer."
            )
            return self._finish_bounded_envelope(envelope, max_rows, check_cql)

        if outcome.timed_out:
            # How far the job got, and whether cleanup actually stopped it.
            details: dict[str, Any] = {
                "job_id": outcome.job_id,
                "timeout_seconds": TIMEOUT_SECONDS,
                "stop_status_code": outcome.stop_status_code,
            }
            if outcome.job is not None:
                details["last_job_status"] = outcome.job

            error_response = _format_error_response(
                message=f"NGSIEM search timed out after {TIMEOUT_SECONDS} seconds. "
                "Try narrowing your query or reducing the time range.",
                details=details,
                operation="GetSearchStatusV1",
            )
            return self._format_cql_error_response(error_response, query_string)

        envelope = self._build_job_envelope(outcome.events or [], outcome.job or {}, query_string)
        if bounded or max_rows is not None or check_cql:
            envelope.setdefault("partial", False)
            return self._finish_bounded_envelope(envelope, max_rows, check_cql)
        return envelope

    @staticmethod
    def _finish_bounded_envelope(
        envelope: dict[str, Any],
        max_rows: int | None,
        check_cql: bool,
    ) -> dict[str, Any]:
        """Apply the row cap and mark the envelope for callers that asked for bounds."""
        rows = envelope.get("results") or []
        envelope["total_rows"] = len(rows)
        envelope["truncated"] = max_rows is not None and len(rows) > max_rows
        if envelope["truncated"]:
            envelope["results"] = rows[:max_rows]
        if check_cql:
            envelope["ok"] = True
        return envelope

    async def _run_search_job(
        self,
        query_string: str,
        start_ms: int,
        end_ms: int | None,
        repository: str,
        timeout_seconds: float,
        deadline: float | None = None,
    ) -> _SearchJobOutcome:
        """Start a search job, poll it to completion, and stop it on timeout.

        Every call goes through `command_async`, so the event loop stays free.
        Errors are returned unformatted; each caller decides how to present them.

        Args:
            query_string: The CQL query to run
            start_ms: Search start, Unix epoch milliseconds
            end_ms: Search end, Unix epoch milliseconds, or None for now
            repository: The repository or view to search, already validated
            timeout_seconds: Polling budget, counted in poll intervals
            deadline: Optional `time.monotonic()` value after which polling stops,
                so a caller running several jobs can cap their wall-clock total

        Returns:
            The outcome: events and job metadata, an error, or a timeout
        """
        # Step 1: Start the search job
        # Note: FalconPy uber class passes body unchanged; API expects camelCase keys
        body_params: dict[str, Any] = {
            "queryString": query_string,
            "start": start_ms,
        }
        if end_ms is not None:
            body_params["end"] = end_ms

        logger.debug("Starting NGSIEM search with query: %s", query_string)

        start_response = await self.client.command_async(
            operation="StartSearchV1",
            repository=repository,
            body=body_params,
        )

        start_status = start_response.get("status_code")
        if start_status != 200:
            return _SearchJobOutcome(
                error=handle_api_response(
                    start_response,
                    operation="StartSearchV1",
                    error_message="Failed to start NGSIEM search",
                    default_result=[],
                )
            )

        job_id = start_response.get("body", {}).get("id")
        if not job_id:
            return _SearchJobOutcome(
                error=_format_error_response(
                    message="Failed to start NGSIEM search: no job ID returned",
                    details=start_response.get("body", {}),
                    operation="StartSearchV1",
                )
            )

        logger.debug("NGSIEM search job started: %s", job_id)

        # Step 2: Poll for completion
        elapsed = 0.0
        last_job_meta: dict[str, Any] | None = None
        last_events: list[dict[str, Any]] = []
        while elapsed < timeout_seconds and (deadline is None or time.monotonic() < deadline):
            await asyncio.sleep(POLL_INTERVAL_SECONDS)
            elapsed += POLL_INTERVAL_SECONDS

            poll_response = await self.client.command_async(
                operation="GetSearchStatusV1",
                repository=repository,
                search_id=job_id,
            )

            poll_status = poll_response.get("status_code")
            if poll_status != 200:
                return _SearchJobOutcome(
                    job_id=job_id,
                    error=handle_api_response(
                        poll_response,
                        operation="GetSearchStatusV1",
                        error_message="Failed to poll NGSIEM search status",
                        default_result=[],
                    ),
                )

            body = poll_response.get("body", {})
            last_job_meta = self._extract_job_metadata(body, repository, job_id)
            last_events = list(body.get("events") or [])
            if body.get("done"):
                logger.debug("NGSIEM search job completed: %s", job_id)
                return _SearchJobOutcome(
                    job_id=job_id,
                    events=list(body.get("events") or []),
                    job=last_job_meta,
                )

        # Step 3: Timeout — attempt cleanup
        logger.warning("NGSIEM search job timed out: %s", job_id)
        stop_response = await self.client.command_async(
            operation="StopSearchV1",
            repository=repository,
            id=job_id,
        )
        return _SearchJobOutcome(
            job_id=job_id,
            job=last_job_meta,
            timed_out=True,
            stop_status_code=stop_response.get("status_code"),
            partial_events=last_events,
        )

    def _list_with_meta(
        self,
        operation: str,
        params: dict[str, Any],
        error_message: str,
        filter_used: str | None,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Run a single-step list operation and wrap it in the pagination envelope.

        Args:
            operation: The API operation name
            params: Query-string parameters
            error_message: Message prefix used if the request fails
            filter_used: The filter sent, echoed back in the envelope

        Returns:
            The pagination envelope, or a one-item list holding the error dict
        """
        results, pagination = self._base_search_with_meta(
            operation=operation,
            search_params=params,
            error_message=error_message,
        )

        if self._is_error(results):
            return [results]

        # Parsers and lookup files may come back as bare names rather than objects.
        return self._build_pagination_envelope(list(results), pagination, filter_used)

    def list_ngsiem_data_connections(
        self,
        filter: str | None = Field(
            default=None,
            description="FQL filter expression for data connections.",
            examples={"status:'Active'"},
        ),
        limit: int = Field(
            default=100,
            ge=1,
            le=1000,
            description="Maximum number of data connections to return: 1-1000. Default is 100.",
        ),
        offset: int | None = Field(
            default=None,
            ge=0,
            description="Starting index of overall result set from which to return results.",
        ),
        sort: str | None = Field(
            default=None,
            description="Sort field and direction, for example 'name.asc'.",
            examples={"name.asc", "status.desc"},
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """List Next-Gen SIEM data connections.

        Use this to check which third-party sources feed Next-Gen SIEM and whether
        they are delivering events, for example when a `falcon_search_ngsiem` query
        on third-party data returns nothing. Each connection carries its vendor,
        product, parser, `status` (such as Active, Idle or Pending) and
        `last_ingested_volume_one_day`; "0 B" means nothing arrived in the last 24
        hours. Use `falcon_get_ngsiem_data_connection_status` for one connection's
        provisioning status.
        """
        return self._list_with_meta(
            operation="ExternalListDataConnections",
            params={
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
            },
            error_message="Failed to list NGSIEM data connections",
            filter_used=filter,
        )

    def get_ngsiem_data_connection_status(
        self,
        ids: list[str] = Field(
            min_length=1,
            description=(
                "IDs of the data connections to check. Get them from "
                "`falcon_list_ngsiem_data_connections`."
            ),
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Get the provisioning status of Next-Gen SIEM data connections.

        Use this after `falcon_list_ngsiem_data_connections` to see whether a
        connection finished provisioning or is stuck when it is not ingesting.
        It reports status per connection; it is not a tenant-wide health check.
        """
        return self._base_get_by_ids(
            operation="ExternalGetDataConnectionStatus",
            ids=ids,
            use_params=True,
        )

    def list_ngsiem_parsers(
        self,
        filter: str | None = Field(
            default=None,
            description="Filter on parser name. Only a text match on name is supported: name:~'value'.",
            examples={"name:~'okta'"},
        ),
        parser_type: str | None = Field(
            default=None,
            description="Only return parsers of this type: 'ootb' (built-in), 'custom', or 'extension'.",
            examples={"ootb", "custom", "extension"},
        ),
        update_available: bool | None = Field(
            default=None,
            description="If true, only parsers with an update available; if false, only up-to-date parsers.",
        ),
        limit: int = Field(
            default=100,
            ge=1,
            le=1000,
            description="Maximum number of parsers to return: 1-1000. Default is 100.",
        ),
        offset: int | None = Field(
            default=None,
            ge=0,
            description="Starting index of overall result set from which to return results.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """List Next-Gen SIEM parsers.

        Use this when fields in a `falcon_search_ngsiem` query on third-party data
        do not match what you expect: parsers turn raw log lines into the
        structured fields a query filters on. Can narrow to built-in, custom or
        extension parsers, or to parsers with an update available.
        """
        if isinstance(parser_type, str) and parser_type not in _PARSER_TYPES:
            return [
                _format_error_response(
                    f"Invalid parser_type {parser_type!r}: must be one of "
                    f"{', '.join(_PARSER_TYPES)}.",
                    operation="ListParsers",
                )
            ]

        # The API takes the string 'true' or 'false', not a JSON boolean.
        update_filter: str | None = None
        if isinstance(update_available, bool):
            update_filter = "true" if update_available else "false"

        return self._list_with_meta(
            operation="ListParsers",
            params={
                "repository": _PARSERS_REPOSITORY,
                "filter": filter,
                "parser_type": parser_type,
                "update_available": update_filter,
                "limit": limit,
                "offset": offset,
            },
            error_message="Failed to list NGSIEM parsers",
            filter_used=filter,
        )

    def list_ngsiem_lookup_files(
        self,
        search_domain: str = Field(
            default="all",
            description=(
                "Search domain (view or repository) to list lookup files from: "
                "'all', 'falcon', 'third-party', 'dashboards', 'parsers-repository', "
                "or 'query-audit'. Default is 'all'."
            ),
            examples={"all", "third-party"},
        ),
        filter: str | None = Field(
            default=None,
            description="Filter on file name. Only a text match on name is supported: name:~'value'.",
            examples={"name:~'allowlist'"},
        ),
        limit: int = Field(
            default=100,
            ge=1,
            le=1000,
            description="Maximum number of lookup files to return: 1-1000. Default is 100.",
        ),
        offset: int | None = Field(
            default=None,
            ge=0,
            description="Starting index of overall result set from which to return results.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """List Next-Gen SIEM lookup files.

        Use this to confirm that a lookup file a CQL query references with
        `match()` or `lookup()` exists in the expected search domain; a missing
        file is a common cause of unexpected join results. Results are usually
        bare file names.
        """
        if isinstance(search_domain, str) and search_domain not in _LOOKUP_FILE_SEARCH_DOMAINS:
            return [
                _format_error_response(
                    f"Invalid search_domain {search_domain!r}: must be one of "
                    f"{', '.join(_LOOKUP_FILE_SEARCH_DOMAINS)}.",
                    operation="ListLookupFiles",
                )
            ]

        return self._list_with_meta(
            operation="ListLookupFiles",
            params={
                "search_domain": search_domain,
                "filter": filter,
                "limit": limit,
                "offset": offset,
            },
            error_message="Failed to list NGSIEM lookup files",
            filter_used=filter,
        )

    async def _process_tree_search(
        self,
        budget: _SearchBudget,
        purpose: str,
        query_string: str,
        start: datetime,
        end: datetime,
    ) -> _SearchJobOutcome | None:
        """Run one process-tree search if the search count and time budget allow it.

        Records the search in `budget.searches`. Returns None, with a note, when the
        budget has no room left for it.
        """
        if len(budget.searches) >= _PROCESS_TREE_MAX_SEARCHES:
            budget.notes.append(f"Skipped the {purpose} search: the search limit was reached.")
            return None
        remaining = budget.deadline - time.monotonic()
        if remaining < POLL_INTERVAL_SECONDS:
            budget.notes.append(f"Skipped the {purpose} search: the time budget was spent.")
            return None

        outcome = await self._run_search_job(
            query_string=query_string,
            start_ms=_to_ms(start),
            end_ms=_to_ms(end),
            repository=_PROCESS_TREE_REPOSITORY,
            timeout_seconds=remaining,
            deadline=budget.deadline,
        )

        if outcome.error is not None:
            status = "error"
        elif outcome.timed_out:
            status = "timed_out"
        else:
            status = "completed"
        budget.searches.append(
            {
                "purpose": purpose,
                "query_used": query_string,
                "start": _epoch_ms_to_iso(_to_ms(start)),
                "end": _epoch_ms_to_iso(_to_ms(end)),
                "status": status,
                "event_count": len(outcome.events) if outcome.events is not None else None,
                "job_id": outcome.job_id,
            }
        )
        return outcome

    async def get_process_tree(
        self,
        device_id: str = Field(
            description="Host to examine: its 32-character hexadecimal agent ID (AID).",
            examples={"0123456789abcdef0123456789abcdef"},
        ),
        pivot_time: str = Field(
            description=(
                "ISO 8601 timestamp near when the pivot process ran, such as the "
                "detection's timestamp. The search window is centred on it."
            ),
            examples={"2025-01-01T12:00:00Z"},
        ),
        pivot_process_id: str | int | None = Field(
            default=None,
            description=(
                "The pivot's TargetProcessId (the sensor's process ID, digits only), "
                "for example from a detection's process details. Preferred over "
                "`pivot_image`. One of the two is required."
            ),
            examples={"123456789012"},
        ),
        pivot_image: str | None = Field(
            default=None,
            description=(
                "The pivot's image file name, such as 'powershell.exe'. Used when "
                "`pivot_process_id` is unknown: the process with this name that started "
                "closest to `pivot_time` is taken as the pivot. Letters, digits, '.', "
                "'_', '-' and spaces only."
            ),
            examples={"powershell.exe"},
        ),
        window_minutes: int = Field(
            default=10,
            ge=1,
            le=120,
            description="Minutes searched either side of `pivot_time`: 1-120. Default is 10.",
        ),
        ancestry_max: int = Field(
            default=12,
            ge=1,
            le=30,
            description="Maximum number of ancestors to walk up: 1-30. Default is 12.",
        ),
        descendants_max: int = Field(
            default=200,
            ge=1,
            le=1000,
            description="Maximum number of descendants to return: 1-1000. Default is 200.",
        ),
    ) -> dict[str, Any]:
        """Reconstruct the process tree around one process on one host from NGSIEM.

        Use this to see what started a suspicious process and what it went on to run.
        It searches ProcessRollup2 events for the host in a window around
        `pivot_time`, finds the pivot by `pivot_process_id` (or by `pivot_image`),
        walks parent process IDs up for `ancestry` (nearest parent first) and child
        processes down for `descendants`. When the pivot started long before
        `pivot_time`, as with behavioural detections, it looks the process up over the
        previous 7 days and re-centres the window on its start. A missing parent gets
        one lookup over the same 7 days. At most 4 searches run, within
        FALCON_MCP_NGSIEM_TIMEOUT seconds in total. `delivery_vector` is a heuristic
        suggestion of how the chain started (for example `phishing_doc`,
        `browser_drive_by`, `lateral_winrm`), based only on image names and command
        lines. `searches` lists each query run and `notes` explains any gap.
        """
        device_id = unwrap_field_default(device_id)
        pivot_time = unwrap_field_default(pivot_time)
        pivot_process_id = unwrap_field_default(pivot_process_id)
        pivot_image = unwrap_field_default(pivot_image)
        window_minutes = unwrap_field_default(window_minutes)
        ancestry_max = unwrap_field_default(ancestry_max)
        descendants_max = unwrap_field_default(descendants_max)

        # Validate everything before any search starts. Only the AID and process ids
        # reach CQL, and `_process_rollup_query` checks them again.
        if not isinstance(device_id, str) or not _DEVICE_ID_PATTERN.fullmatch(device_id):
            return _format_error_response(
                "Invalid device_id: must be the host's 32-character hexadecimal agent ID."
            )
        device_id = device_id.lower()

        pivot_dt = _parse_pivot_time(pivot_time)
        if pivot_dt is None:
            return _format_error_response(
                "Invalid pivot_time: must be an ISO 8601 timestamp such as '2025-01-01T12:00:00Z'."
            )

        target_pid: str | None = None
        if pivot_process_id is not None:
            if isinstance(pivot_process_id, int) and not isinstance(pivot_process_id, bool):
                pivot_process_id = str(pivot_process_id)
            if not _is_valid_process_id(pivot_process_id):
                return _format_error_response(
                    "Invalid pivot_process_id: must be the TargetProcessId, 1-20 digits."
                )
            target_pid = str(pivot_process_id)

        image_name: str | None = None
        if pivot_image is not None:
            if not isinstance(pivot_image, str) or not _IMAGE_NAME_PATTERN.fullmatch(pivot_image):
                return _format_error_response(
                    "Invalid pivot_image: must be a file name such as 'powershell.exe', "
                    "using only letters, digits, '.', '_', '-' and spaces."
                )
            image_name = pivot_image.strip().lower() or None

        if target_pid is None and image_name is None:
            return _format_error_response(
                "Provide pivot_process_id or pivot_image to identify the pivot process."
            )

        for label, value, low, high in (
            ("window_minutes", window_minutes, 1, 120),
            ("ancestry_max", ancestry_max, 1, 30),
            ("descendants_max", descendants_max, 1, 1000),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                return _format_error_response(
                    f"Invalid {label}: must be an integer from {low} to {high}."
                )

        budget = _SearchBudget(deadline=time.monotonic() + TIMEOUT_SECONDS)
        window = timedelta(minutes=window_minutes)
        window_query = _process_rollup_query(device_id, _PROCESS_TREE_EVENT_LIMIT)

        outcome = await self._process_tree_search(
            budget, "window", window_query, pivot_dt - window, pivot_dt + window
        )
        if outcome is not None and outcome.error is not None:
            error_response = dict(outcome.error)
            error_response["searches"] = budget.searches
            return error_response

        result: dict[str, Any] = {
            "pivot": None,
            "ancestry": [],
            "descendants": [],
            "delivery_vector": None,
            "window": {},
            "unresolved_parent_process_id": None,
            "descendants_truncated": False,
            "searches": budget.searches,
            "notes": budget.notes,
        }

        def describe_window(center: datetime, events: list[dict[str, Any]]) -> dict[str, Any]:
            return {
                "pivot_time": _epoch_ms_to_iso(_to_ms(center)),
                "start": _epoch_ms_to_iso(_to_ms(center - window)),
                "end": _epoch_ms_to_iso(_to_ms(center + window)),
                "anchor_recovered": False,
                "events_scanned": len(events),
                "event_limit_reached": len(events) >= _PROCESS_TREE_EVENT_LIMIT,
            }

        if outcome is None or outcome.events is None:
            budget.notes.append(
                "The window search did not complete in time. Retry with a smaller window_minutes."
            )
            result["window"] = describe_window(pivot_dt, [])
            return result

        events = outcome.events
        result["window"] = describe_window(pivot_dt, events)
        if len(events) >= _PROCESS_TREE_EVENT_LIMIT:
            budget.notes.append(
                f"The window returned the maximum of {_PROCESS_TREE_EVENT_LIMIT} events, "
                "so the tree may be incomplete. Retry with a smaller window_minutes."
            )
        rows = _sorted_nodes(events)
        pivot = _find_pivot(rows, target_pid, image_name, _to_ms(pivot_dt))

        # Anchor recovery: a detection can fire hours after its process started, which
        # leaves the process outside a window centred on the detection. One probe for
        # the process itself finds its real start, and the window is re-centred there.
        if pivot is None and target_pid is not None:
            probe = await self._process_tree_search(
                budget,
                "anchor_probe",
                _process_rollup_query(device_id, 1, target_pid),
                pivot_dt - _ANCHOR_PROBE_LOOKBACK,
                pivot_dt + window,
            )
            probe_node = _process_node(probe.events[0]) if probe and probe.events else None
            start_ms = probe_node.get("_start_ms") if probe_node else None
            if probe_node is not None and isinstance(start_ms, (int, float)):
                center = datetime.fromtimestamp(start_ms / 1000, tz=timezone.utc)
                recentred = await self._process_tree_search(
                    budget, "recentred_window", window_query, center - window, center + window
                )
                if recentred is not None and recentred.events:
                    events = recentred.events
                    rows = _sorted_nodes(events)
                    result["window"] = describe_window(center, events)
                    budget.notes.append(
                        "The pivot was not in the window around pivot_time; the window was "
                        "re-centred on the process's own start time."
                    )
                else:
                    budget.notes.append(
                        "The pivot was found by its process ID outside the window, but the "
                        "re-centred search returned nothing, so its relatives come from the "
                        "original window only."
                    )
                pivot = _find_pivot(rows, target_pid, None, start_ms)
                if pivot is None:
                    pivot = probe_node
                    rows = [probe_node, *rows]
                pivot_dt = center
                result["window"]["anchor_recovered"] = True
            elif probe is not None and probe.events is not None:
                budget.notes.append(
                    f"No ProcessRollup2 event for TargetProcessId {target_pid} on this host "
                    "in the 7 days before pivot_time. Its telemetry may have aged out or "
                    "never reached NGSIEM."
                )

        if pivot is None:
            if target_pid is None:
                budget.notes.append(
                    f"No process named {image_name} on this host within {window_minutes} "
                    "minutes of pivot_time."
                )
            return result

        index: dict[str, dict[str, Any]] = {}
        for row in rows:
            if row["process_id"]:
                index.setdefault(row["process_id"], row)

        ancestry, unresolved, widened = await self._walk_ancestry(
            budget, device_id, pivot, index, pivot_dt, window, ancestry_max
        )
        descendants, truncated = _walk_descendants(rows, pivot, descendants_max)

        result["pivot"] = _public_node(pivot)
        result["ancestry"] = [_public_node(node) for node in ancestry]
        result["descendants"] = [_public_node(node) for node in descendants]
        result["unresolved_parent_process_id"] = unresolved
        result["descendants_truncated"] = truncated
        result["delivery_vector"] = _classify_delivery_vector([pivot, *ancestry], widened)
        if unresolved is not None:
            budget.notes.append(
                f"Parent process {unresolved} was not found, so the ancestry stops there."
            )
        return result

    async def _walk_ancestry(
        self,
        budget: _SearchBudget,
        device_id: str,
        pivot: dict[str, Any],
        index: dict[str, dict[str, Any]],
        pivot_dt: datetime,
        window: timedelta,
        ancestry_max: int,
    ) -> tuple[list[dict[str, Any]], str | None, bool]:
        """Walk parent process ids up from the pivot.

        A parent missing from the window gets one lookup over the 7 days before the
        pivot; the walk stops at the next gap after that.

        Returns:
            The ancestors nearest first, the parent id the walk could not resolve, and
            whether a parent came from that wider lookup
        """
        ancestry: list[dict[str, Any]] = []
        seen = {pivot["process_id"]}
        current = pivot
        lookup_used = False
        widened = False
        for depth in range(1, ancestry_max + 1):
            parent_id = current.get("parent_process_id")
            if not parent_id or parent_id in seen:
                return ancestry, None, widened
            parent = index.get(parent_id)
            if parent is None and not lookup_used:
                lookup_used = True
                lookup = await self._process_tree_search(
                    budget,
                    "parent_lookup",
                    _process_rollup_query(device_id, _PARENT_LOOKUP_LIMIT, parent_id),
                    pivot_dt - _ANCHOR_PROBE_LOOKBACK,
                    pivot_dt + window,
                )
                if lookup is not None and lookup.events:
                    parent = _process_node(lookup.events[0])
                    widened = True
            if parent is None:
                return ancestry, parent_id, widened
            seen.add(parent_id)
            ancestry.append({**parent, "depth": depth})
            current = parent
        return ancestry, None, widened

    def lookup_cql_function(
        self,
        name: str = Field(
            description=(
                "CQL function name to look up, such as 'groupBy', 'array:filter' or "
                "'formatTime'. Matched exactly, then ignoring case, then by close or "
                "partial matches."
            ),
            examples={"groupBy", "sort", "array:filter"},
        ),
    ) -> dict[str, Any]:
        """Look up a CQL (LogScale) query function before using it in a query.

        Use this to check that a function exists and how to call it when writing a
        `falcon_search_ngsiem` query. Returns its signature, parameters (name and
        whether required), categories, default argument and a link to its
        documentation page. When the name is not a function, returns the closest
        function names instead. Works offline from a catalog shipped with the server;
        no Falcon API call is made.
        """
        name = unwrap_field_default(name)
        if not isinstance(name, str):
            return _format_error_response("Invalid name: must be a CQL function name.")
        query = name.strip().split("(", 1)[0].strip()
        if not 0 < len(query) <= _CQL_FUNCTION_QUERY_MAX_LENGTH:
            return _format_error_response(
                f"Invalid name: must be 1-{_CQL_FUNCTION_QUERY_MAX_LENGTH} characters."
            )

        catalog = _load_cql_catalog()
        if query in catalog:
            return {"match": "exact", "function": dict(catalog[query])}

        by_lower = {function_name.lower(): function_name for function_name in catalog}
        lowered = query.lower()
        if lowered in by_lower:
            return {"match": "case_insensitive", "function": dict(catalog[by_lower[lowered]])}

        close = difflib.get_close_matches(lowered, list(by_lower), n=10, cutoff=0.6)
        partial = sorted((n for n in by_lower if lowered in n), key=lambda n: (len(n), n))
        ordered = list(dict.fromkeys([*close, *partial]))
        candidates = [dict(catalog[by_lower[n]]) for n in ordered]
        response: dict[str, Any] = {
            "match": "candidates" if candidates else "none",
            "query": query,
            "candidates": candidates[:_CQL_FUNCTION_CANDIDATE_LIMIT],
            "candidate_count": len(candidates),
            "hint": f"No CQL function is named '{query}'.",
        }
        if lowered in _CQL_NON_FUNCTIONS:
            response["hint"] += " " + _CQL_NON_FUNCTIONS[lowered]
        return response
