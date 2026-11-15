"""
Contains Users resources.
"""

from falcon_mcp.common.utils import generate_md_table

# Fields the user search accepts, as its API documents them
_USER_SEARCH_FIELDS = [
    ("Name", "Type", "Description"),
    ("uid", "String", "Login email address. Ex: uid:*'*@example.com'"),
    ("first_name", "String", "First name. Ex: first_name:'Jane'"),
    ("last_name", "String", "Last name. Ex: last_name:'Doe'"),
    ("name", "String", "Full name."),
    ("uuid", "String", "User UUID."),
    ("status", "String", "Account status. Ex: status:'active'"),
    ("has_temporary_roles", "Boolean", "Users holding a role grant that expires. Ex: has_temporary_roles:true"),
    ("cid", "String", "The CID the user belongs to."),
    ("assigned_cids", "String", "CIDs the user holds roles in (Flight Control)."),
]

SEARCH_USERS_FQL_DOCUMENTATION = (
    """Falcon Query Language (FQL) - Users Search Guide

Falcon console users: their login email, names, status and the CIDs they belong to.
Roles are not searchable here; use falcon_get_user_roles for those.

=== BASIC SYNTAX ===
property_name:[operator]'value'

=== OPERATORS ===
• = (default): Equals
• !: Not equal
• *: Wildcard, as in uid:*'*jdoe*'

=== COMBINING ===
• + (AND): status:'active'+uid:*'*@example.com'
• , (OR): first_name:'Jane',first_name:'John'

=== AVAILABLE FILTERS ===
"""
    + generate_md_table(_USER_SEARCH_FIELDS)
    + """

=== SORT ===
uid, first_name or last_login_at, followed by .asc or .desc. Ex: last_login_at.desc

=== NOTES ===
• `user_type` ('internal' or 'external') is a separate parameter, not a filter field.
• Each result's `last_login_at` shows when the user last signed in, for finding unused accounts.
"""
)
