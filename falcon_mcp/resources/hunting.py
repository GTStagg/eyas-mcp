"""
Contains Hunting (CrowdStrike published hunting content) FQL filter resources.

The CAO Hunting API documents `filter` only as "FQL query specifying the filter
parameters" and `q` as a phrase-prefix match across every indexed string field.
It does not publish a list of filterable fields, and the fields below have not
been verified against a live tenant. The guides say so, and steer callers to `q`
first and to field names read from a returned record second.
"""

from falcon_mcp.common.fql import FQL_BASE_OPERATORS

_SHARED_NOTES = """
=== START WITH q, NOT filter ===
`q` is a phrase-prefix match across every indexed string field ("_all"), so it
finds content by technique, tool, actor or behavior without knowing any field
name: q='rundll32', q='Cobalt Strike', q='T1059'. Reach for `filter` only to
narrow on a structured field.

=== FILTER FIELDS ===
The API does not publish its filterable fields. Build a filter from a field
name you have seen in a returned record (call the tool once with `q` or with no
arguments, then read the keys). Filter on top-level scalar fields such as `id`
or `name` first; nested fields may not be indexed.

• An unknown field is expected to return a 400 naming it.
• A known field with an unsupported operator may return an empty 200 instead,
  so an empty result after a filter change does not prove nothing matches.
• Use ~ for word matching on long text fields; exact match on a long text
  field rarely hits.

=== SORT ===
`sort` takes a field from the returned records, with a dot separator:
'name.asc'. If a sort is rejected with a 400, drop it; results still come back
in the API's default order.
"""

SEARCH_HUNTING_GUIDES_FQL_DOCUMENTATION = (
    """Falcon Query Language (FQL) - Search Hunting Guides Guide

Hunting guides are narrative, CrowdStrike-authored runbooks: how to
investigate a behavior or adversary technique end to end, and what to check
next.

"""
    + FQL_BASE_OPERATORS
    + "\n"
    + _SHARED_NOTES
    + """
=== EXAMPLES ===
• Guides mentioning a tool: q='mimikatz'
• Guides for a technique ID: q='T1003'
• One guide by ID: id:'<guide id>'
• Guides whose name contains a word: name:~'persistence'
"""
)

SEARCH_HUNTING_QUERIES_FQL_DOCUMENTATION = (
    """Falcon Query Language (FQL) - Search Hunting Queries Guide

Hunting queries (the API calls them intelligence queries) are runnable,
CrowdStrike-authored detection and hunting logic. Most are CQL for Falcon
Next-Gen SIEM / event search; CrowdStrike also publishes content in other
languages. The query text is in the returned record, ready to adapt.

"""
    + FQL_BASE_OPERATORS
    + "\n"
    + _SHARED_NOTES
    + """
=== LANGUAGE ===
CrowdStrike's export of this content offers these languages: cql, snort,
suricata, yara. If a returned record carries a `language` field, filter on it
with one of those values, e.g. language:'cql'. Pass
include_translated_content='SPL' to the tool to also get an AI-translated
Splunk SPL version where one exists.

=== EXAMPLES ===
• Queries mentioning a binary: q='rundll32'
• Queries for a technique ID: q='T1218'
• CQL queries only (if `language` is present): language:'cql'
• One query by ID: id:'<query id>'
"""
)
