<!-- meta:title Case Management -->
<!-- meta:description Managing CrowdStrike cases, including searching, creating, updating, and managing evidence and tags -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Managing CrowdStrike cases, including searching, creating, updating, and managing evidence and tags

## API Scopes

- `Case Templates:read`
- `Cases:read`
- `Cases:write`

## Tools

### `falcon_search_cases`

**Required scopes:** `Cases:read`

Find cases by criteria and return their complete details.

Use this to discover cases by status, severity, assignee, time range, or
evidence attributes. Consult falcon://cases/search/fql-guide before
constructing filter expressions. Returns full case records including
status, severity, evidence, assigned user, and analysis results.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Show me any open cases with high severity or above"
- "What cases have been created in the last 24 hours?"

### `falcon_get_cases`

**Required scopes:** `Cases:read`

Retrieve details for case IDs you already have.

Use when you have specific case IDs from search results or external
references. For discovering cases by criteria, use falcon_search_cases;
for files attached to a case, use falcon_aggregate_case_file_details.
Returns full case records. Their `analysis_results.files` field lists
forensic artifacts from detections, not attachments, and is empty for
cases that do have attachments.

**Example prompts:**

- "Pull up the full details on that case"

### `falcon_create_case`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Cases:write`

Create a new case in CrowdStrike.

Provide a name and severity at minimum. Optionally attach alert or event
evidence, assign a user, apply a template, and set tags. Returns the
created case record.

**Example prompts:**

- "Create a critical case called 'Suspicious lateral movement from WORKSTATION-42'"
- "Open a high-severity case for the credential theft alerts and attach them as evidence"
- "Create a case with a markdown-formatted description"

### `falcon_update_case`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Cases:write`

Update an existing case's fields.

Provide the case ID and any fields to change. Use expected_version for
optimistic concurrency control to prevent conflicting updates. Returns the
updated case record with incremented version.

**Example prompts:**

- "Set that case to in_progress and assign it to the analyst"
- "Close the case — investigation is complete"
- "Rewrite the case description as markdown"

### `falcon_add_case_alert_evidence`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Cases:write`

Attach alert evidence to an existing case.

Provide alert composite_id values from the Alerts v2 API (e.g. from
falcon_search_detections). Each case supports a maximum of 100 combined
evidence items. Returns the updated case record.

**Example prompts:**

- "Attach these detection alerts to the case"

### `falcon_add_case_event_evidence`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Cases:write`

Attach LogScale event evidence to an existing case.

Provide event IDs obtained from falcon_search_ngsiem or the Falcon
console. Each case supports a maximum of 100 combined evidence items.
Returns the updated case record.

**Example prompts:**

- "Add these NGSIEM event IDs to the case as evidence"

### `falcon_manage_case_tags`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Cases:write`

Add or remove tags on a case.

Set action to 'add' to attach new tags, or 'remove' to delete existing
tags. Returns the updated case record.

**Example prompts:**

- "Tag that case with 'ransomware' and 'escalated'"
- "Remove the 'escalated' tag from that case"

### `falcon_list_case_templates`

**Required scopes:** `Case Templates:read`

List available case templates.

Use to discover templates that can be applied when creating or updating
cases. Returns template details including name, custom fields, and SLA
configuration.

**Example prompts:**

- "What case templates are available?"

### `falcon_aggregate_case_slas`

**Required scopes:** `Case Templates:read`

Count case SLA definitions grouped by a field.

Use this to summarize the SLA policies configured in your tenant — for
example how many exist, or who created them — rather than to list them
individually. Consult falcon://cases/aggregates/fql-guide before
constructing filter expressions. Returns buckets of `label` and `count`.
Requires the Case Templates:read scope.

**Example prompts:**

- "How many case SLA policies do we have?"
- "Break down our case SLAs by who created them"

### `falcon_aggregate_case_templates`

**Required scopes:** `Case Templates:read`

Count case templates grouped by a field.

Use this to summarize the case templates configured in your tenant, such
as how many exist or which users author them; falcon_list_case_templates
returns the individual template records instead. Consult
falcon://cases/aggregates/fql-guide before constructing filter
expressions. Returns buckets of `label` and `count`. Requires the
Case Templates:read scope.

**Example prompts:**

- "How many case templates has each person created?"
- "Count the case templates added in the last 30 days"

### `falcon_aggregate_case_access_tags`

**Required scopes:** `Case Templates:read`

Count case access tags grouped by a field.

Use this to see which access tags control case visibility in your tenant
and how many of each exist. Access tags accept a narrower field set than
the other case aggregates — only key, id, and cid. Consult
falcon://cases/aggregates/fql-guide before constructing filter
expressions. Returns buckets of `label` and `count`. Requires the
Case Templates:read scope.

**Example prompts:**

- "What access tags are used to restrict case visibility, and how many of each?"

### `falcon_aggregate_case_notification_groups`

**Required scopes:** `Case Templates:read`

Count case notification groups grouped by a field.

Use this to summarize the notification groups that receive case updates,
such as how many are configured or who created them. Consult
falcon://cases/aggregates/fql-guide before constructing filter
expressions. Returns buckets of `label` and `count`. Requires the
Case Templates:read scope.

**Example prompts:**

- "How many case notification groups are configured?"
- "Show notification group counts by creator"

### `falcon_aggregate_case_file_details`

**Required scopes:** `Cases:read`

Report the files attached to cases, grouped and counted by a field.

Use this whenever a question mentions files, attachments or screenshots
on a case, including "what files are attached to case X" and "how many
files does case X have" — pass the case IDs as case_ids. Case records
from falcon_get_cases do not list attachments; their
`analysis_results.files` field holds forensic artifacts from detections
and is empty for cases that do have attachments. Consult
falcon://cases/file-aggregates/fql-guide before constructing filter
expressions. Returns buckets of `label` and `count`. Requires the
Cases:read scope.

**Example prompts:**

- "What file names show up most often across case attachments?"
- "How many files are attached to these two cases?"

### `falcon_search_case_files`

**Required scopes:** `Cases:read`

List the files attached to cases: name, size, type, SHA256, who added them and when.

Use this to see a case's evidence files, including ones retrieved from hosts
with falcon_retrieve_rtr_file_to_case. Each record has `id`, `name`, `case_id`,
`file_size`, `file_type`, `hash_value`, `description`, `uploaded_on`,
`uploaded_by` and `source`. The API does not report how many files match in
total; `pagination.next_offset` is set when a full page came back.

**Example prompts:**

- "What files are attached to this case?"

### `falcon_get_rtr_file_metadata`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Cases:read`

Read a file's metadata on a host over RTR, without retrieving the file.

Use this to confirm a file exists on a host and see its details before
retrieving it into a case with falcon_retrieve_rtr_file_to_case. The host must
be online. Nothing on the host changes, but the request goes through an RTR
session on it. Returns the API's response.

**Example prompts:**

- "Does C:\Users\Public\update.exe exist on host 0123456789abcdef0123456789abcdef?"

### `falcon_retrieve_rtr_file_to_case`

**Required scopes:** `Cases:write`

Collect a file from a host over RTR and attach it to a case as evidence.

The file goes straight from the host into the case; its content never passes
through this server. Use this to preserve a suspicious executable, script or
document during an investigation. The host must be online. Afterwards the file
appears in falcon_search_case_files with its SHA256. Returns the API's response.

**Example prompts:**

- "Collect C:\Users\Public\update.exe from this host into the case"

### `falcon_add_rtr_session_file_to_case`

**Required scopes:** `Cases:write`

Attach a file an RTR session already collected (with `get`) to a case.

Use this when an analyst has fetched a file in an RTR session and it should be
kept with the case. List a session's collected files and their SHA256 with
falcon_list_rtr_session_files. Returns the API's response.

**Example prompts:**

- "Add the file I pulled in this RTR session to the case"

## Resources

- **`falcon://cases/search/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_cases` tool.
- **`falcon://cases/aggregates/fql-guide`**: Contains the guide for the `filter` param of the `falcon_aggregate_case_slas`, `falcon_aggregate_case_templates`, `falcon_aggregate_case_access_tags`, and `falcon_aggregate_case_notification_groups` tools.
- **`falcon://cases/file-aggregates/fql-guide`**: Contains the guide for the `filter` param of the `falcon_aggregate_case_file_details` tool.
