"""
Contains Falcon Sandbox resources.
"""

from falcon_mcp.common.utils import generate_md_table

# Fields checked against a live tenant. Fields of the analysed sample need the
# `sandbox.` prefix: without it the API matches nothing rather than rejecting the filter.
_REPORT_FIELDS = [
    ("Name", "Type", "Description"),
    ("verdict", "String", "Overall verdict. Ex: verdict:'malicious'"),
    ("sandbox.verdict", "String", "Verdict for the analysed sample."),
    ("sandbox.threat_score", "Integer", "0-100. Ex: sandbox.threat_score:>=70"),
    ("sandbox.sha256", "String", "SHA256 of the analysed file. Ex: sandbox.sha256:'<sha256>'"),
    ("sandbox.submit_name", "String", "Name the file or URL was submitted under."),
    ("sandbox.environment_id", "Integer", "Sandbox environment, e.g. 160 for Windows 10 64-bit."),
    (
        "origin",
        "String",
        "Where the sample came from: quarantine (quarantined on an endpoint), workflow "
        "(Fusion SOAR), uiproxy (submitted by a person in the console), android, "
        "malware_agent, csglobalcommandengine. Ex: origin:'uiproxy'",
    ),
    ("id", "String", "Report ID, which is also the submission ID."),
    ("created_timestamp", "Timestamp", "When the report was created. Ex: created_timestamp:>'now-7d'"),
]

_SUBMISSION_FIELDS = [
    ("Name", "Type", "Description"),
    ("state", "String", "created, running, success or error. Ex: state:'running'"),
    ("sandbox.sha256", "String", "SHA256 of the submitted file."),
    ("id", "String", "Submission ID."),
    ("created_timestamp", "Timestamp", "When it was submitted. Ex: created_timestamp:>'now-24h'"),
]

SANDBOX_FQL_DOCUMENTATION = (
    """Falcon Query Language (FQL) - Falcon Sandbox Guide

Falcon Sandbox detonates files and URLs and reports what they did. Reports and
submissions are searched with FQL.

=== BASIC SYNTAX ===
property_name:[operator]'value'

=== OPERATORS ===
• = (default): Equals
• !: Not equal
• >, >=, <, <=: Comparison (numbers and timestamps)

=== COMBINING ===
• + (AND): verdict:'malicious'+created_timestamp:>'now-7d'
• , (OR): verdict:'malicious',verdict:'suspicious'

=== REPORT FILTERS (falcon_search_sandbox_reports) ===
"""
    + generate_md_table(_REPORT_FIELDS)
    + """

Verdicts seen: malicious, suspicious, no specific threat, whitelisted.

=== SUBMISSION FILTERS (falcon_search_sandbox_submissions) ===
"""
    + generate_md_table(_SUBMISSION_FIELDS)
    + """

=== SORT ===
created_timestamp.desc or created_timestamp.asc.

=== NOTES ===
• Sample fields need the `sandbox.` prefix: `sha256:'...'` silently matches nothing,
  `sandbox.sha256:'...'` works.
• Has this file been detonated before? Search reports with sandbox.sha256.
• Reports don't name the endpoint a file came from. Find it by SHA256 with
  falcon_search_quarantined_files (for origin quarantine) or falcon_get_threatgraph_ran_on.
"""
)
