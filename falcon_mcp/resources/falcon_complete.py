"""
Contains Falcon Complete resources.
"""

from falcon_mcp.common.utils import generate_md_table

# Fields the Message Center case search accepts, as its API documents them.
_MESSAGE_CENTER_CASE_FIELDS = [
    ("Name", "Type", "Description"),
    ("_all", "String", "Free text across the case and its activity. Ex: _all:'*powershell*'"),
    ("case.id", "String", "Case ID. Ex: case.id:'Abc123Def4567'"),
    ("case.key", "String", "Case number shown in the console. Ex: case.key:'CS-12345'"),
    ("case.title", "String", "Case title. Ex: case.title:*'*blocklist*'"),
    ("case.body", "String", "Case description text."),
    ("activity.body", "String", "Text of any message on the case."),
    (
        "case.status",
        "String",
        "Numeric status code, not a name. Ex: case.status:'2'. Aggregate on it with "
        "falcon_aggregate_message_center_cases to see which codes the tenant uses.",
    ),
    (
        "case.type",
        "String",
        "Numeric type code. Each case also carries `case_type`, the type's name, such "
        "as 'Falcon Complete Support Issue', 'Blocklist', 'Falcon Incident' or "
        "'NGSIEM Detection'. Ex: case.type:'10001'",
    ),
    ("case.created_time", "Timestamp", "When the case was opened. Ex: case.created_time:>'2026-01-01'"),
    ("case.last_modified_time", "Timestamp", "When the case last changed."),
    ("case.aids", "String", "Host AID linked to the case."),
    ("case.hosts", "String", "Host name linked to the case."),
    ("case.ip_addresses", "String", "IP address linked to the case."),
    ("case.detections.id", "String", "Detection or alert ID linked to the case."),
    ("case.incidents.id", "String", "Incident ID linked to the case."),
    ("case.assigner.display_name", "String", "Display name of who opened the case."),
    ("case.assigner.uid", "String", "Login of who opened the case."),
]

MESSAGE_CENTER_CASES_FQL_DOCUMENTATION = (
    """Falcon Query Language (FQL) - Message Center Cases Guide

Message Center holds the cases Falcon Complete and CrowdStrike Support open with you,
and the ones you open with them, each with its thread of activity.

=== BASIC SYNTAX ===
property_name:[operator]'value'

=== OPERATORS ===
• = (default): Equals
• !: Not equal
• >, >=, <, <=: Comparison (timestamps)
• *: Wildcard, as in case.title:*'*blocklist*'

=== COMBINING ===
• + (AND): case.type:'10201'+case.created_time:>'2026-01-01'
• , (OR): case.status:'2',case.status:'4'

=== AVAILABLE FILTERS ===
"""
    + generate_md_table(_MESSAGE_CENTER_CASE_FIELDS)
    + """

=== SORT ===
case.created_time, case.last_modified_time or case.status, followed by .asc or
.desc. Ex: case.last_modified_time.desc

=== NOTES ===
• Field names need the `case.` or `activity.` prefix; `status` alone is rejected.
• Status and type are codes. Use the `case_type` name on each case to tell types apart.
"""
)
