<!-- meta:title Detections -->
<!-- meta:description Accessing and analyzing CrowdStrike Falcon detections -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Accessing and analyzing CrowdStrike Falcon detections

## API Scopes

- `Alerts:read`
- `Alerts:write`

## Tools

### `falcon_search_detections`

**Required scopes:** `Alerts:read`

Find detections (also called alerts) by criteria and return their complete details.

Use this to discover detections by severity, status, hostname, time range, or other
attributes — this is the tool for general alert and detection queries. Covers alerts
across all Falcon products: endpoint (EPP), identity (IDP), XDR, OverWatch, and
NG-SIEM. Consult falcon://detections/search/fql-guide before constructing filter
expressions. Returns full alert records including process context, device info,
tactic/technique details, and threat classification.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Show me new high severity detections from the last 7 days"
- "Find all unassigned critical detections"

### `falcon_get_detection_details`

**Required scopes:** `Alerts:read`

Retrieve details for detection IDs you already have.

Use when you have specific composite detection ID(s). For discovering detections
by criteria (severity, status, hostname, etc.), use falcon_search_detections
instead. Returns full detection records; IDs hidden from the Falcon UI are
omitted when include_hidden is False.

**Example prompts:**

- "Get me the details for this detection"

### `falcon_aggregate_detections`

**Required scopes:** `Alerts:read`

Count and summarize detections (also called alerts) without retrieving each record.

Use this for "how many" and "top N" questions — alerts per severity, status,
tactic, or host, distinct host counts, and alert volume over time — instead of
paging through falcon_search_detections. Consult
falcon://detections/search/fql-guide before constructing filter expressions.
Returns one aggregation per request holding `buckets`, which key on `label`
with a `count`; single-value aggregations (`cardinality`, `max`, `min`, `avg`,
`sum`) report their answer as `value` instead.

**Example prompts:**

- "How many detections do we have by severity?"
- "What are the top 10 hosts by alert count this week?"
- "Show me alert volume per day for the last 30 days"
- "How many distinct hosts have critical alerts?"

### `falcon_update_detections`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Alerts:write`

Update the status, assignment, visibility, comments, and tags of one or more detections.

Use to change status (new, in_progress, reopened, closed), assign to a user by UUID,
email address, or full name, unassign, append a comment, hide/show detections in the UI,
or add/remove tags. Resolution is tag-based: applying the conventional tags true_positive,
false_positive, or ignored is what populates the console's Resolution view. At least one
update parameter must be provided. Requests covering more than 1000 detection IDs are
chunked automatically so none are silently dropped. Returns `[]` (empty list) on success, or
`{"result": [], "hint": "..."}` when closing without adding a resolution tag in this call;
returns an error dict on failure. If a later chunk fails after earlier chunks already
applied, the error dict carries a `partial_success` block listing the already-updated ids so
the caller can retry only the remainder rather than re-applying non-idempotent actions.

**Example prompts:**

- "Mark detection abc123 as in_progress"
- "Assign detection abc123 to analyst@example.com"
- "Close these detections and add a comment: resolved via playbook"
- "Mark detection abc123 as a true positive and close it"
- "Remove all fc/ prefixed tags from this detection"

### `falcon_close_host_detections`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Alerts:read`, `Alerts:write`

Close every open detection on one host, with one resolution and comment.

Finds all detections on the host whose status is new, in_progress or reopened,
then closes them and tags them with the resolution. That includes endpoint
detections and alerts that name the host in other fields, such as Next-Gen SIEM
correlation detections; an alert that also names another host is left open and
listed unless include_multi_host is true. Use this once a host has been
investigated and cleaned up, or confirmed as a false positive, to clear its queue
in one step. Review the host's detections with falcon_search_detections first;
this closes all of them, whatever their severity. Running it again only touches
detections that are still open. Returns how many were found and closed, and the
composite IDs closed.

**Example prompts:**

- "Close every open detection on host abc123 as a true positive"

## Resources

- **`falcon://detections/search/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_detections` tool.
