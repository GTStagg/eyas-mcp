<!-- meta:title Falcon Complete -->
<!-- meta:description This module provides read-only tools for Falcon Complete: Message Center cases and their activity threads, and the counts behind the Falcon Complete dashboard -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

This module provides read-only tools for Falcon Complete: Message Center cases and their activity threads, and the counts behind the Falcon Complete dashboard

## API Scopes

- `Falcon Complete Dashboards:read`
- `Message Center:read`

## Tools

### `falcon_search_message_center_cases`

**Required scopes:** `Message Center:read`

Search Falcon Complete and Support cases in Message Center.

Use this to see what the Falcon Complete team or CrowdStrike Support has raised
with you (escalations, blocklist requests, incidents, support issues) and the
cases you opened with them. Consult
falcon://falcon-complete/message-center/cases/fql-guide before constructing
filter expressions. Returns full case records: key (the CS- number), title,
body, status and type codes, case_type name, the alert IDs, host names and
AIDs linked to it, and timestamps. Read a case's messages with
falcon_get_message_center_case_activities.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Show the Falcon Complete cases updated this week"
- "Which Message Center cases mention host WS-0042?"

### `falcon_get_message_center_cases`

**Required scopes:** `Message Center:read`

Get Message Center cases by ID and report which IDs don't exist.

Use this to re-read cases you already have IDs for, for example to check
whether their status changed. Returns `found` (full case records in the order
of `ids`) and `not_found` (IDs with no case).

**Example prompts:**

- "Has the status of these three Message Center cases changed?"

### `falcon_get_message_center_case_activities`

**Required scopes:** `Message Center:read`

Read the message thread of one Message Center case.

Use this to see what the Falcon Complete team or Support wrote on a case and
how its status changed. Returns activities with type (`comment` or
`status_change`), body, created_by and created_time, oldest first.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "What did the Falcon Complete team write on case CS-12345?"
- "Show only the comments on this case, newest first"

### `falcon_aggregate_message_center_cases`

**Required scopes:** `Message Center:read`

Count Message Center cases by status, type, opener or time.

Use this to answer "how many open cases" or "cases per month" without paging
through them. Returns `buckets` of `{label, count}`. Status and type labels
are numeric codes; search the cases to see each type's `case_type` name.

**Example prompts:**

- "How many Message Center cases are there of each type?"
- "How many cases were opened per month this year?"

### `falcon_aggregate_complete_dashboard`

**Required scopes:** `Falcon Complete Dashboards:read`

Count Falcon Complete dashboard data: escalations, remediations and more.

Use this to answer how many escalations, remediations, blocklist or allowlist
requests or alerts the Falcon Complete team has handled, optionally broken
down by a field. Returns `total` (records matching `filter`) and, when
`field` is set, `buckets` of `{label, count}`. The dashboard API lists only
record IDs, so read case details with falcon_search_message_center_cases.

**Example prompts:**

- "How many escalations has Falcon Complete raised, by severity?"
- "How many blocklist requests were made each month?"

## Resources

- **`falcon://falcon-complete/message-center/cases/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_message_center_cases` tool.
