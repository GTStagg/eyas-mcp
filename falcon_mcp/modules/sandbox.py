"""
Sandbox module for Falcon MCP Server

This module provides tools for Falcon Sandbox (Falcon Intelligence): search detonation
reports and submissions, read a trimmed report, submit a file or URL for analysis,
upload samples, and delete reports or samples. Malware samples, memory dumps and other
binary artifacts are deliberately not downloadable through this server.
"""

import base64
import binascii
import re
from typing import Any

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from mcp.types import ToolAnnotations
from pydantic import AnyUrl, Field

from falcon_mcp.common.errors import _format_error_response, handle_api_response
from falcon_mcp.common.logging import get_logger
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.sandbox import SANDBOX_FQL_DOCUMENTATION

logger = get_logger(__name__)

FQL_GUIDE_URI = "falcon://sandbox/search/fql-guide"

MAX_SEARCH_LIMIT = 100
MAX_SAMPLE_CHECK = 200
# The API takes samples up to 256 MB; content arrives base64-encoded in a tool call,
# so one upload is held well below that.
MAX_UPLOAD_BYTES = 32 * 1024 * 1024

# Sandbox environments the API accepts, from the FalconPy documentation
ENVIRONMENTS = {
    100: "Windows 7, 32-bit",
    110: "Windows 7, 64-bit",
    140: "Windows 11, 64-bit",
    160: "Windows 10, 64-bit",
    200: "Android (static analysis)",
    300: "Linux Ubuntu 16.04, 64-bit",
    400: "macOS Catalina 10.15",
}
ENVIRONMENT_HELP = "Sandbox environment: " + ", ".join(
    f"{env_id} = {name}" for env_id, name in ENVIRONMENTS.items()
) + "."
NETWORK_SETTINGS = ("default", "tor", "simulated", "offline")
ACTION_SCRIPTS = (
    "default",
    "default_maxantievasion",
    "default_randomfiles",
    "default_randomtheme",
    "default_openie",
)

SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}")
REPORT_ID_PATTERN = re.compile(r"[0-9a-fA-F]{32}_[0-9a-fA-F]{32}")
URL_PATTERN = re.compile(r"(?:https?|ftp)://\S+", re.IGNORECASE)
SAMPLE_NAME_PATTERN = re.compile(r"[^\x00-\x1f/\\]{1,255}")
DATE_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}")
TIME_PATTERN = re.compile(r"\d{2}:\d{2}")

# What a trimmed full report keeps of each list section, and how many entries
_PROCESS_FIELDS = (
    "uid", "parent_uid", "pid", "name", "normalized_path", "command_line", "sha256", "process_flags",
)
_SIGNATURE_FIELDS = ("name", "category", "threat_level_human", "description", "attack_id")
_EXTRACTED_FILE_FIELDS = (
    "name", "file_path", "sha256", "file_size", "type_tags", "threat_level_readable",
)
_HTTP_FIELDS = ("method", "url", "host", "host_ip", "host_port", "response_code")
_SCALAR_FIELDS = (
    "sha256", "environment_id", "environment_description", "submit_name", "submission_type",
    "verdict", "threat_score", "classification_tags", "file_type", "file_size", "architecture",
    "sample_flags", "network_settings", "packer", "is_certificates_valid",
    "certificates_validation_message", "incidents",
)
_SECTION_CAP = 100
_COMMAND_LINE_CAP = 1000
_DESCRIPTION_CAP = 300
SEVERE = ("malicious", "suspicious")


def _error(message: str, operation: str) -> dict[str, Any]:
    return _format_error_response(message, operation=operation)


def _pick(item: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {k: item[k] for k in fields if item.get(k) not in (None, "", [])}


def _trim_sandbox(sandbox: dict[str, Any], include_informative: bool) -> dict[str, Any]:
    """Keep what an analyst reads from one analysed sample and drop the bulk."""
    out: dict[str, Any] = {k: sandbox[k] for k in _SCALAR_FIELDS if k in sandbox}
    omitted: dict[str, int] = {}

    signatures = [s for s in sandbox.get("signatures") or [] if isinstance(s, dict)]
    kept = [
        _pick(s, _SIGNATURE_FIELDS)
        for s in signatures
        if include_informative or s.get("threat_level_human") in SEVERE
    ]
    for signature in kept:
        # Descriptions often embed raw evidence, up to 16 KB for one signature
        description = signature.get("description")
        if isinstance(description, str) and len(description) > _DESCRIPTION_CAP:
            signature["description"] = description[:_DESCRIPTION_CAP] + "..."
    out["signatures"] = kept[:_SECTION_CAP]
    omitted["signatures"] = len(signatures) - len(out["signatures"])

    techniques: dict[str, dict[str, Any]] = {}
    for attack in sandbox.get("mitre_attacks") or []:
        if not isinstance(attack, dict):
            continue
        severity = (
            "malicious" if attack.get("malicious_identifiers")
            else "suspicious" if attack.get("suspicious_identifiers")
            else "informative"
        )
        if severity == "informative" and not include_informative:
            continue
        key = str(attack.get("attack_id"))
        if key not in techniques:
            techniques[key] = {
                "attack_id": attack.get("attack_id"),
                "tactic": attack.get("tactic"),
                "technique": attack.get("technique"),
                "severity": severity,
            }
    out["mitre_attacks"] = list(techniques.values())

    processes = []
    for p in (sandbox.get("processes") or [])[:_SECTION_CAP]:
        if isinstance(p, dict):
            trimmed = _pick(p, _PROCESS_FIELDS)
            if isinstance(trimmed.get("command_line"), str):
                trimmed["command_line"] = trimmed["command_line"][:_COMMAND_LINE_CAP]
            processes.append(trimmed)
    out["processes"] = processes

    network: dict[str, Any] = {}
    for key in ("contacted_hosts", "dns_requests", "suricata_alerts"):
        if sandbox.get(key):
            network[key] = sandbox[key][:_SECTION_CAP]
    if sandbox.get("http_requests"):
        network["http_requests"] = [
            _pick(h, _HTTP_FIELDS) for h in sandbox["http_requests"][:_SECTION_CAP] if isinstance(h, dict)
        ]
    if sandbox.get("urls"):
        network["urls"] = sandbox["urls"][:_SECTION_CAP]
    out["network"] = network

    out["extracted_files"] = [
        _pick(f, _EXTRACTED_FILE_FIELDS)
        for f in (sandbox.get("extracted_files") or [])[:_SECTION_CAP]
        if isinstance(f, dict)
    ]
    out["omitted"] = {k: v for k, v in omitted.items() if v}
    return out


class SandboxModule(BaseModule):
    """Module for Falcon Sandbox analysis."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(server=server, method=self.search_sandbox_reports, name="search_sandbox_reports")
        self._add_tool(server=server, method=self.get_sandbox_report, name="get_sandbox_report")
        self._add_tool(
            server=server, method=self.search_sandbox_submissions, name="search_sandbox_submissions"
        )
        self._add_tool(server=server, method=self.check_sandbox_samples, name="check_sandbox_samples")
        self._add_tool(
            server=server,
            method=self.submit_to_sandbox,
            name="submit_to_sandbox",
            annotations=ToolAnnotations(
                readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
            ),
        )
        self._add_tool(
            server=server,
            method=self.upload_sandbox_sample,
            name="upload_sandbox_sample",
            annotations=ToolAnnotations(
                readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
            ),
        )
        self._add_tool(
            server=server,
            method=self.delete_sandbox_report,
            name="delete_sandbox_report",
            annotations=ToolAnnotations(
                readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True
            ),
        )
        self._add_tool(
            server=server,
            method=self.delete_sandbox_sample,
            name="delete_sandbox_sample",
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
                uri=AnyUrl(FQL_GUIDE_URI),
                name="falcon_sandbox_fql_guide",
                description=(
                    "Contains the guide for the `filter` param of the "
                    "`falcon_search_sandbox_reports` and `falcon_search_sandbox_submissions` tools."
                ),
                text=SANDBOX_FQL_DOCUMENTATION,
            ),
        )

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #

    def search_sandbox_reports(
        self,
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter on reports. Sample fields need the `sandbox.` prefix, e.g. "
                "sandbox.sha256:'<sha256>'. See `falcon://sandbox/search/fql-guide`."
            ),
            examples=["verdict:'malicious'+created_timestamp:>'now-7d'", "sandbox.sha256:'<sha256>'"],
        ),
        limit: int = Field(
            default=10, ge=1, le=MAX_SEARCH_LIMIT,
            description=f"The maximum reports to return. [1-{MAX_SEARCH_LIMIT}]",
        ),
        offset: int | None = Field(default=None, description="The offset to start from."),
        sort: str | None = Field(
            default="created_timestamp.desc",
            description="created_timestamp.desc (default) or created_timestamp.asc.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search Falcon Sandbox reports and return their summaries: verdict, threat score, file type and environment.

        Use this to see whether a file or URL has been detonated before (filter on
        sandbox.sha256) or to review recent malicious results. Each summary has `id`,
        `verdict`, `created_timestamp` and `sandbox` (with `sha256`, `submit_name`,
        `threat_score`, `environment_description` and `file_type`). Read a whole report
        with falcon_get_sandbox_report.
        Responses include `pagination.total`.
        """
        ids, pagination = self._base_search_with_meta(
            operation="QueryReports",
            search_params={"filter": filter, "limit": limit, "offset": offset, "sort": sort},
            error_message="Failed to search sandbox reports",
        )
        if self._is_error(ids):
            return self._format_fql_error_response([ids], filter, SANDBOX_FQL_DOCUMENTATION)
        if not ids:
            return self._build_pagination_envelope([], pagination, filter)

        summaries = self._base_get_by_ids(
            operation="GetSummaryReports", ids=ids, use_params=True
        )
        if self._is_error(summaries):
            return [summaries]
        summaries = self._reorder_by_ids(ids, summaries, id_field="id")
        return self._build_pagination_envelope(summaries, pagination, filter)

    def get_sandbox_report(
        self,
        report_id: str = Field(
            description="The report ID, from falcon_search_sandbox_reports or a submission.",
        ),
        include_informative: bool = Field(
            default=False,
            description=(
                "Also list informative signatures and MITRE techniques. By default only "
                "malicious and suspicious ones are returned."
            ),
        ),
    ) -> dict[str, Any]:
        """Read one sandbox report: what the sample did, trimmed to what an analyst needs.

        Returns `id`, `verdict`, `created_timestamp` and `sandbox`, one entry per analysed
        sample with its verdict, threat score and file facts, `signatures`,
        `mitre_attacks` (each with `severity`), `processes` (with command lines),
        `network` (contacted hosts, DNS and HTTP requests, Suricata alerts, URLs) and
        `extracted_files`. Extracted strings, the behaviour visualization and binary
        structure are left out; full reports run to hundreds of kilobytes.
        """
        operation = "GetReports"
        rid = report_id.strip() if isinstance(report_id, str) else ""
        if not REPORT_ID_PATTERN.fullmatch(rid):
            return _error(
                f"Invalid report_id {report_id!r}. Report IDs come from "
                "falcon_search_sandbox_reports.",
                operation,
            )
        response = self.client.command(operation, parameters={"ids": [rid]})
        reports = handle_api_response(
            response, operation=operation, error_message="Failed to get the sandbox report"
        )
        if isinstance(reports, dict):
            return reports
        if not reports:
            return _error(f"No sandbox report with ID {rid}.", operation)

        report = reports[0]
        return {
            "id": report.get("id"),
            "verdict": report.get("verdict"),
            "created_timestamp": report.get("created_timestamp"),
            "origin": report.get("origin"),
            "sandbox": [
                _trim_sandbox(s, include_informative)
                for s in report.get("sandbox") or []
                if isinstance(s, dict)
            ],
        }

    def search_sandbox_submissions(
        self,
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter on submissions, e.g. state:'running'. See "
                "`falcon://sandbox/search/fql-guide`."
            ),
        ),
        ids: list[str] | None = Field(
            default=None,
            description="Submission IDs to look up directly, instead of a filter.",
        ),
        limit: int = Field(
            default=10, ge=1, le=MAX_SEARCH_LIMIT,
            description=f"The maximum submissions to return. [1-{MAX_SEARCH_LIMIT}]",
        ),
        offset: int | None = Field(default=None, description="The offset to start from."),
        sort: str | None = Field(
            default="created_timestamp.desc",
            description="created_timestamp.desc (default) or created_timestamp.asc.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Check the state of sandbox submissions: created, running, success or error.

        Use this after falcon_submit_to_sandbox to see whether an analysis has finished.
        Analysis usually takes under 15 minutes. A finished submission's ID is also its
        report ID for falcon_get_sandbox_report.
        """
        if ids:
            wanted = list(dict.fromkeys(i.strip() for i in ids if isinstance(i, str) and i.strip()))
            if not wanted or len(wanted) > MAX_SEARCH_LIMIT:
                return _error(
                    f"Pass between 1 and {MAX_SEARCH_LIMIT} submission IDs.", "GetSubmissions"
                )
            found = self._base_get_by_ids(operation="GetSubmissions", ids=wanted, use_params=True)
            if self._is_error(found):
                return [found]
            return {"results": found, "not_found": [i for i in wanted if i not in {s.get("id") for s in found}]}

        submission_ids, pagination = self._base_search_with_meta(
            operation="QuerySubmissions",
            search_params={"filter": filter, "limit": limit, "offset": offset, "sort": sort},
            error_message="Failed to search sandbox submissions",
        )
        if self._is_error(submission_ids):
            return self._format_fql_error_response(
                [submission_ids], filter, SANDBOX_FQL_DOCUMENTATION
            )
        if not submission_ids:
            return self._build_pagination_envelope([], pagination, filter)

        submissions = self._base_get_by_ids(
            operation="GetSubmissions", ids=submission_ids, use_params=True
        )
        if self._is_error(submissions):
            return [submissions]
        submissions = self._reorder_by_ids(submission_ids, submissions, id_field="id")
        return self._build_pagination_envelope(submissions, pagination, filter)

    def check_sandbox_samples(
        self,
        sha256s: list[str] = Field(
            description=f"SHA256 hashes to check, at most {MAX_SAMPLE_CHECK}.",
        ),
    ) -> dict[str, Any]:
        """Check which files are already uploaded to the sandbox, by SHA256.

        A file listed in `found` can be submitted with falcon_submit_to_sandbox by its
        hash, without uploading it again. Returns `found` and `not_found`.
        """
        operation = "QuerySampleV1"
        hashes = list(dict.fromkeys(h.strip().lower() for h in sha256s or [] if isinstance(h, str)))
        bad = [h for h in hashes if not SHA256_PATTERN.fullmatch(h)]
        if not hashes or bad:
            return _error(f"Pass SHA256 hashes (64 hex characters). Invalid: {bad[:5]}", operation)
        if len(hashes) > MAX_SAMPLE_CHECK:
            return _error(f"At most {MAX_SAMPLE_CHECK} hashes per call.", operation)

        response = self.client.command(operation, body={"sha256s": hashes})
        status = response.get("status_code")
        body = response.get("body") or {}
        if status is None or status >= 300:
            error: dict[str, Any] = handle_api_response(
                response, operation=operation, error_message="Failed to check sandbox samples"
            )
            return error
        # Unknown hashes come back as an error message under 200, not as a failure
        found = {
            str(r.get("sha256") if isinstance(r, dict) else r).lower()
            for r in body.get("resources") or []
        }
        return {
            "found": [h for h in hashes if h in found],
            "not_found": [h for h in hashes if h not in found],
        }

    # ------------------------------------------------------------------ #
    # Writes
    # ------------------------------------------------------------------ #

    def submit_to_sandbox(
        self,
        url: str | None = Field(
            default=None,
            description="A web page or file URL (http, https or ftp) to detonate. Give url or sha256.",
        ),
        sha256: str | None = Field(
            default=None,
            description=(
                "SHA256 of a file already uploaded (falcon_upload_sandbox_sample, or "
                "check with falcon_check_sandbox_samples). Give url or sha256."
            ),
        ),
        environment_id: int = Field(
            default=160,
            description=ENVIRONMENT_HELP,
        ),
        network_settings: str = Field(
            default="default",
            description="'default' (full network), 'simulated', 'offline' or 'tor'.",
        ),
        submit_name: str | None = Field(
            default=None,
            description="Name for the sample, used for file type detection, e.g. 'invoice.docm'.",
        ),
        command_line: str | None = Field(
            default=None,
            description="Command line passed to the sample when it runs. At most 2048 characters.",
        ),
        action_script: str | None = Field(
            default=None,
            description=f"Runtime script: {', '.join(ACTION_SCRIPTS)}.",
        ),
        document_password: str | None = Field(
            default=None,
            description="Password the sandbox enters when an Office or PDF sample asks for one. At most 32 characters.",
        ),
        system_date: str | None = Field(
            default=None, description="Date the sandbox clock shows, as yyyy-MM-dd."
        ),
        system_time: str | None = Field(
            default=None, description="Time the sandbox clock shows, as HH:mm."
        ),
        user_tags: list[str] | None = Field(
            default=None, description="Tags to label the submission."
        ),
    ) -> dict[str, Any]:
        """Submit a URL or an uploaded file to Falcon Sandbox for detonation.

        The sandbox runs the sample in an isolated machine and reports its behaviour,
        usually within 15 minutes. Each submission uses the tenant's sandbox quota.
        Returns the submission with its `id` and `state`; follow it with
        falcon_search_sandbox_submissions, then read the result with
        falcon_get_sandbox_report using the same ID.
        """
        operation = "Submit"
        target_url = url.strip() if isinstance(url, str) and url.strip() else None
        target_hash = sha256.strip().lower() if isinstance(sha256, str) and sha256.strip() else None
        if bool(target_url) == bool(target_hash):
            return _error("Give exactly one of url or sha256.", operation)
        if target_url and not URL_PATTERN.fullmatch(target_url):
            return _error("url must be an http, https or ftp URL without spaces.", operation)
        if target_hash and not SHA256_PATTERN.fullmatch(target_hash):
            return _error("sha256 must be 64 hexadecimal characters.", operation)
        if environment_id not in ENVIRONMENTS:
            return _error(
                f"environment_id must be one of {sorted(ENVIRONMENTS)}.", operation
            )
        if network_settings not in NETWORK_SETTINGS:
            return _error(f"network_settings must be one of {list(NETWORK_SETTINGS)}.", operation)
        if action_script is not None and action_script not in ACTION_SCRIPTS:
            return _error(f"action_script must be one of {list(ACTION_SCRIPTS)}.", operation)
        if command_line is not None and len(command_line) > 2048:
            return _error("command_line must be at most 2048 characters.", operation)
        if document_password is not None and len(document_password) > 32:
            return _error("document_password must be at most 32 characters.", operation)
        if system_date is not None and not DATE_PATTERN.fullmatch(system_date):
            return _error("system_date must look like 2026-11-14.", operation)
        if system_time is not None and not TIME_PATTERN.fullmatch(system_time):
            return _error("system_time must look like 13:45.", operation)

        job: dict[str, Any] = {"environment_id": environment_id, "network_settings": network_settings}
        if target_url:
            job["url"] = target_url
        else:
            job["sha256"] = target_hash
        optional = {
            "submit_name": submit_name,
            "command_line": command_line,
            "action_script": action_script,
            "document_password": document_password,
            "system_date": system_date,
            "system_time": system_time,
        }
        job.update({k: v for k, v in optional.items() if v})
        body: dict[str, Any] = {"sandbox": [job]}
        tags = [t.strip() for t in user_tags or [] if isinstance(t, str) and t.strip()]
        if tags:
            body["user_tags"] = tags

        response = self.client.command(operation, body=body)
        submissions = handle_api_response(
            response, operation=operation, error_message="Failed to submit to the sandbox"
        )
        if isinstance(submissions, dict):
            return submissions
        submission = submissions[0] if submissions else {}
        return {
            "submission": submission,
            "id": submission.get("id") if isinstance(submission, dict) else None,
            "state": submission.get("state") if isinstance(submission, dict) else None,
            "environment": ENVIRONMENTS[environment_id],
        }

    def upload_sandbox_sample(
        self,
        file_name: str = Field(
            description="Name of the file, e.g. 'invoice.docm'. Used for file type detection.",
        ),
        content_base64: str = Field(
            description=(
                f"The file's content, base64-encoded. Under {MAX_UPLOAD_BYTES // (1024 * 1024)} "
                "MB once decoded. Only content passed here is sent: the server never reads "
                "files from its own disk."
            ),
        ),
        comment: str | None = Field(
            default=None, description="A note identifying the file for other users."
        ),
    ) -> dict[str, Any]:
        """Upload a file to Falcon Sandbox so it can be submitted for detonation.

        The upload is always confidential: only users in this CID can see it, and it is
        not shared through MalQuery. Returns the sample's `sha256`; pass it to
        falcon_submit_to_sandbox to analyse the file. Uploading the same file again
        changes nothing.
        """
        operation = "UploadSampleV2"
        name = file_name.strip() if isinstance(file_name, str) else ""
        if not SAMPLE_NAME_PATTERN.fullmatch(name):
            return _error("file_name must be 1-255 characters, without slashes or control characters.", operation)
        if not isinstance(content_base64, str) or not content_base64.strip():
            return _error("content_base64 must hold the file's content, base64-encoded.", operation)
        if len(content_base64) > (MAX_UPLOAD_BYTES // 3 + 1) * 4 + 1024:
            return _error(f"The sample must be under {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.", operation)
        try:
            data = base64.b64decode("".join(content_base64.split()), validate=True)
        except (binascii.Error, ValueError):
            return _error("content_base64 is not valid base64.", operation)
        if not data:
            return _error("The sample is empty.", operation)
        if len(data) >= MAX_UPLOAD_BYTES:
            return _error(f"The sample must be under {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.", operation)

        form: dict[str, Any] = {"file_name": name, "is_confidential": "true"}
        if comment and comment.strip():
            form["comment"] = comment.strip()
        response = self.client.command(operation, data=form, files=[("sample", (name, data))])
        uploaded = handle_api_response(
            response, operation=operation, error_message="Failed to upload the sample"
        )
        if isinstance(uploaded, dict):
            return uploaded
        record = uploaded[0] if uploaded else {}
        return {
            "sha256": record.get("sha256") if isinstance(record, dict) else None,
            "file_name": name,
            "size_bytes": len(data),
            "confidential": True,
        }

    def delete_sandbox_report(
        self,
        report_id: str = Field(description="The report ID to delete."),
    ) -> dict[str, Any]:
        """Delete a sandbox report permanently.

        The report and its analysis can't be recovered; the sample itself stays
        uploaded (remove it with falcon_delete_sandbox_sample).
        """
        operation = "DeleteReport"
        rid = report_id.strip() if isinstance(report_id, str) else ""
        if not REPORT_ID_PATTERN.fullmatch(rid):
            return _error(f"Invalid report_id {report_id!r}.", operation)
        response = self.client.command(operation, parameters={"ids": rid})
        if response.get("status_code") not in (200, 202, 204):
            error: dict[str, Any] = handle_api_response(
                response, operation=operation, error_message="Failed to delete the sandbox report"
            )
            return error
        return {"deleted": True, "report_id": rid}

    def delete_sandbox_sample(
        self,
        sha256: str = Field(description="SHA256 of the uploaded sample to delete."),
    ) -> dict[str, Any]:
        """Delete an uploaded sample permanently, with its metadata and submissions.

        Reports already produced from it are not deleted by this tool.
        """
        operation = "DeleteSampleV2"
        digest = sha256.strip().lower() if isinstance(sha256, str) else ""
        if not SHA256_PATTERN.fullmatch(digest):
            return _error("sha256 must be 64 hexadecimal characters.", operation)
        response = self.client.command(operation, parameters={"ids": digest})
        if response.get("status_code") not in (200, 202, 204):
            error: dict[str, Any] = handle_api_response(
                response, operation=operation, error_message="Failed to delete the sample"
            )
            return error
        return {"deleted": True, "sha256": digest}
