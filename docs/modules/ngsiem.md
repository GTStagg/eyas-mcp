<!-- meta:title NGSIEM -->
<!-- meta:description Running search queries against CrowdStrike's Next-Gen SIEM via the asynchronous job-based search API, read-only tools for inspecting its ingest pipeline (data connections, parsers, and lookup files), a process-tree reconstruction built on that search API, and an offline lookup of CQL query functions -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Running search queries against CrowdStrike's Next-Gen SIEM via the asynchronous job-based search API, read-only tools for inspecting its ingest pipeline (data connections, parsers, and lookup files), a process-tree reconstruction built on that search API, and an offline lookup of CQL query functions

## API Scopes

- `NGSIEM:read`
- `NGSIEM:write`

## Tools

### `falcon_search_ngsiem`

**Required scopes:** `NGSIEM:read`, `NGSIEM:write`

Execute a CQL (CrowdStrike Query Language) query against CrowdStrike Next-Gen SIEM.

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

**Example prompts:**

- "Run this CQL query for the last 24 hours: #event_simpleName=ProcessRollup2"
- "Search NGSIEM for DNS events from January 2025"

### `falcon_list_ngsiem_data_connections`

**Required scopes:** `NGSIEM:read`

List Next-Gen SIEM data connections.

Use this to check which third-party sources feed Next-Gen SIEM and whether
they are delivering events, for example when a `falcon_search_ngsiem` query
on third-party data returns nothing. Each connection carries its vendor,
product, parser, `status` (such as Active, Idle or Pending) and
`last_ingested_volume_one_day`; "0 B" means nothing arrived in the last 24
hours. Use `falcon_get_ngsiem_data_connection_status` for one connection's
provisioning status.

**Example prompts:**

- "List our NGSIEM data connections and their status"

### `falcon_get_ngsiem_data_connection_status`

**Required scopes:** `NGSIEM:read`

Get the provisioning status of Next-Gen SIEM data connections.

Use this after `falcon_list_ngsiem_data_connections` to see whether a
connection finished provisioning or is stuck when it is not ingesting.
It reports status per connection; it is not a tenant-wide health check.

**Example prompts:**

- "What's the provisioning status of NGSIEM data connection <id>?"

### `falcon_list_ngsiem_parsers`

**Required scopes:** `NGSIEM:read`

List Next-Gen SIEM parsers.

Use this when fields in a `falcon_search_ngsiem` query on third-party data
do not match what you expect: parsers turn raw log lines into the
structured fields a query filters on. Can narrow to built-in, custom or
extension parsers, or to parsers with an update available.

**Example prompts:**

- "Which NGSIEM parsers have updates available?"

### `falcon_list_ngsiem_lookup_files`

**Required scopes:** `NGSIEM:read`

List Next-Gen SIEM lookup files.

Use this to confirm that a lookup file a CQL query references with
`match()` or `lookup()` exists in the expected search domain; a missing
file is a common cause of unexpected join results. Results are usually
bare file names.

**Example prompts:**

- "Is there an NGSIEM lookup file named allowlist?"

### `falcon_get_process_tree`

**Required scopes:** `NGSIEM:read`, `NGSIEM:write`

Reconstruct the process tree around one process on one host from NGSIEM.

Use this to see what started a suspicious process and what it went on to run.
It searches ProcessRollup2 events for the host in a window around
`pivot_time`, finds the pivot by `pivot_process_id` (or by `pivot_image`),
walks parent process IDs up for `ancestry` (nearest parent first) and child
processes down for `descendants`. When the pivot started long before
`pivot_time`, as with behavioural detections, it looks the process up over the
previous 7 days and re-centres the window on its start. When the sensor
blocked the process before it ran, so it has no ProcessRollup2 event, the
pivot comes from its ProcessBlocked event instead, marked `blocked`, and the
ancestry is walked from the parent that event names. A missing parent gets
one lookup over the same 7 days. At most 4 searches run, within
FALCON_MCP_NGSIEM_TIMEOUT seconds in total, or within `time_budget_seconds`,
after which the tree found so far comes back with `partial` set. Each node's
`signing` holds the raw sensor signing fields for its platform, if any.
`delivery_vector` is a heuristic
suggestion of how the chain started (for example `phishing_doc`,
`browser_drive_by`, `lateral_winrm`), based only on image names and command
lines. `searches` lists each query run and `notes` explains any gap.

**Example prompts:**

- "Show the process tree around powershell.exe on host <aid> at 2025-01-01T12:00:00Z"
- "What spawned process 123456789012 on host <aid>, and what did it launch?"

### `falcon_lookup_cql_function`

Look up a CQL (LogScale) query function before using it in a query.

Use this to check that a function exists and how to call it when writing a
`falcon_search_ngsiem` query. Returns its signature, parameters (name and
whether required), categories, default argument and a link to its
documentation page. When the name is not a function, returns the closest
function names instead. Works offline from a catalog shipped with the server;
no Falcon API call is made.

**Example prompts:**

- "What parameters does the CQL groupBy function take?"
- "Is limit() a CQL function?"

## Resources

- **`falcon://ngsiem/search/cql-guide`**: Contains the CQL authoring guide for the `query_string` param of the `falcon_search_ngsiem` tool.
