<!-- meta:title Real Time Response -->
<!-- meta:description Initiating and inspecting RTR sessions, for executing read-only RTR commands during host investigations, and for managing and running scripts from the tenant's custom RTR script library -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Initiating and inspecting RTR sessions, for executing read-only RTR commands during host investigations, and for managing and running scripts from the tenant's custom RTR script library

## API Scopes

- `Hosts:read`
- `Real time response:read`
- `real-time-response-audit:read`
- `Real time response (admin):write`
- `Real time response:write`

## Tools

### `falcon_search_rtr_sessions`

**Required scopes:** `Real time response:read`

Search RTR sessions and return full session details.

Use this to find sessions by hostname, agent ID, user, or creation time. Consult
falcon://rtr/sessions/search/fql-guide before constructing filter expressions.
Returns session metadata including host info, commands executed, and status.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Find all active RTR sessions"
- "Show me RTR sessions for host abc123"

### `falcon_search_rtr_audit_sessions`

**Required scopes:** `real-time-response-audit:read`

Search RTR audit sessions for accountability and timeline evidence.

Use this when you need to understand who used RTR, when they used it,
which host was targeted, or which command activity Falcon recorded.
This is read-only audit visibility; it does not open sessions or run
commands. Consult falcon://rtr/audit/sessions/search/fql-guide before
constructing filter expressions.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Show me RTR audit activity from the last 7 days"
- "Who used RTR against host BRR-WB-LIB-22?"

### `falcon_aggregate_rtr_sessions`

**Required scopes:** `Real time response:read`

Summarize RTR session activity with Falcon aggregation buckets.

Use this before detailed searches when the user asks which hosts,
users, origins, commands, or time windows account for RTR activity.
This is read-only summary visibility; it does not open sessions, run
commands, or return every session record.

**Example prompts:**

- "Summarize RTR sessions by command for the last 30 days"
- "Which hosts have the most RTR activity this week?"

### `falcon_get_rtr_session_details`

**Required scopes:** `Real time response:read`

Retrieve detailed metadata for one or more RTR sessions.

Use when you already have session IDs from search results. For discovering
sessions by criteria, use falcon_search_rtr_sessions instead. Returns full
session records.

**Example prompts:**

- "Get details for RTR session abc123"

### `falcon_init_rtr_session`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Real time response:read`

Initialize or reuse an RTR session for a single host.

Opens a live connection to the specified device for executing RTR commands.
Use queue_offline=True if the host may be offline. Returns session records
containing the session_id needed for subsequent commands.

**Example prompts:**

- "Start an RTR session on host xyz"

### `falcon_pulse_rtr_session`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Real time response:read`

Refresh an RTR session timeout for a single host.

Keeps an existing session alive by resetting its inactivity timer. Use this
to prevent session expiration during long investigations.

**Example prompts:**

- "Refresh the RTR session to keep it alive"

### `falcon_execute_rtr_read_only_command`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Real time response:read`

Execute a read-only RTR command on a single host.

Limited to read-only commands (ls, ps, cat, filehash, reg) for hunt and triage
workflows. Does not expose admin or remediation commands. Returns command records
containing a cloud_request_id for polling output via falcon_check_rtr_command_status.

**Example prompts:**

- "Run 'ps' on this host via RTR"
- "List running processes on host xyz"

### `falcon_run_rtr_read_only_command_and_wait`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Real time response:read`

Execute a read-only RTR command and poll until completion.

Use this for simple, focused RTR evidence collection when the user
wants the command output directly and does not need to manually manage
a cloud request ID. This polls command status until completion or
timeout, accumulating output chunks into one result. It still executes
an RTR command and creates RTR command activity, but it does not expose
RTR Admin or remediation APIs.

**Example prompts:**

- "Run 'ps' via RTR and return the output when it completes"
- "Check C:\Windows\win.ini on this RTR session and wait for the result"

### `falcon_run_rtr_read_only_command_on_hosts`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Real time response:read`

Run one read-only RTR command on several hosts at once and return each host's output.

Use this to ask the same question of a set of hosts, such as which of them run a
process or hold a file with a given hash. It accepts the same read-only commands
as falcon_execute_rtr_read_only_command and nothing more. It opens an RTR batch
session on online hosts only (nothing is queued for offline hosts), runs the
command, and reports output per host, with hosts that couldn't be reached listed
under `failed_hosts`. This creates RTR session and command activity, recorded in
the RTR audit log. Sessions expire on their own; close one early with
falcon_delete_rtr_session.

**Example prompts:**

- "Run 'netstat' via RTR on these five hosts and compare the output"

### `falcon_list_falcon_scripts`

**Required scopes:** `Real time response (admin):write`

List the CrowdStrike-published RTR scripts (Falcon scripts) available to this tenant.

Falcon scripts are host introspection scripts that CrowdStrike maintains, such as
Process, Service, RegistryKey, EventLog and BitLocker, and that return structured
JSON. Use this to find a script's exact name, its platforms and any input it
takes before calling falcon_run_falcon_script. This only reads the catalog; it
doesn't contact any host.

**Example prompts:**

- "Which CrowdStrike Falcon scripts can I run on Windows hosts?"

### `falcon_run_falcon_script`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Real time response:read`, `Real time response (admin):write`

Run a CrowdStrike-published Falcon script on one or more hosts.

Use this to collect structured host state, such as running processes, services,
registry keys or BitLocker status, from several hosts in one call. The script
name must come from falcon_list_falcon_scripts. Falcon scripts inspect hosts,
but they run through an RTR Admin batch session, so this needs the RTR Admin
scope and is recorded in the RTR audit log. Nothing is queued for offline hosts;
they are listed under `failed_hosts`. Each host's JSON output is decoded into
`output` when it parses, otherwise returned as `stdout`.

**Example prompts:**

- "Run the BitLocker Falcon script on these hosts"
- "Use the RegistryKey Falcon script to read the Run key on host xyz"

### `falcon_check_rtr_command_status`

**Required scopes:** `Real time response:read`

Get the status and output for an RTR command execution.

Poll this after falcon_execute_rtr_read_only_command to retrieve command
output. Use sequence_id to paginate through large output chunks.

**Example prompts:**

- "Check the status of RTR command request abc123"

### `falcon_list_rtr_session_files`

**Required scopes:** `Real time response:write`

List files extracted during an RTR session.

Returns file metadata for artifacts captured during the session, such as
files pulled with the `get` command.

**Example prompts:**

- "List files extracted during RTR session abc123"

### `falcon_delete_rtr_session`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Real time response:read`

Close an RTR session and release the host connection.

Use this when investigation is complete to free up session resources.

**Example prompts:**

- "End the RTR session abc123"

### `falcon_wait_for_rtr_sessions`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Hosts:read`, `Real time response:read`, `Real time response (admin):write`

Wait until hosts accept RTR sessions, retrying until they do or time runs out.

Use this after a change that briefly blocks RTR on a host, such as moving it into
a new host group or policy, or a reboot, before running RTR commands or scripts.
Each attempt opens an RTR batch session on the hosts that aren't ready yet; the
first attempt is immediate. By default it runs no commands, and the sessions
expire on their own. With probe='runscript' a host counts as ready only once a
harmless probe script actually runs on it, which is the check to use before
falcon_run_rtr_script_on_hosts. Returns `ready` (true when every host is ready),
the ready hosts with their session IDs, and the last error for hosts that never
got there.

**Example prompts:**

- "Wait until host abc123 accepts RTR again after moving it into the new group"

### `falcon_search_rtr_scripts`

**Required scopes:** `Real time response (admin):write`

Search the tenant's custom RTR script library.

Custom scripts are scripts your organization uploaded for RTR Admins to run with
`runscript -CloudFile`. They are separate from the CrowdStrike-published scripts
listed by falcon_list_falcon_scripts. Use this to find a script's exact name
before calling falcon_run_rtr_script_on_hosts, or to review what is in the
library. This only reads the library; it doesn't contact any host.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Which custom RTR scripts are in our library for Windows?"

### `falcon_create_rtr_script`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Real time response (admin):write`

Upload a script to the tenant's custom RTR script library.

Use this to stage a script that falcon_run_rtr_script_on_hosts will run. Uploading
doesn't run anything, but anyone with the chosen permission can run the script
on hosts afterwards, so review the content first. Prefer `private` unless others
need it, and delete one-off scripts with falcon_delete_rtr_scripts once they've
run. Needs the RTR Admin write scope.

**Example prompts:**

- "Upload this PowerShell script to the RTR script library as collect-triage"

### `falcon_delete_rtr_scripts`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Real time response (admin):write`

Delete scripts from the tenant's custom RTR script library.

Use this to remove one-off scripts after they've run, or scripts nobody should
run any more. Deletion can't be undone. It doesn't affect commands already
sent to hosts. Needs the RTR Admin write scope.

**Example prompts:**

- "Delete the one-off collect-triage script from the RTR library"

### `falcon_run_rtr_script_on_hosts`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Real time response:read`, `Real time response (admin):write`

Run a script from the custom RTR script library on one or more hosts.

This runs your organization's own code on the hosts with `runscript -CloudFile`,
so it can change anything on them. Only scripts already in the library can run;
upload one with falcon_create_rtr_script first. Hosts must be online: nothing is
queued, and hosts that can't be reached are listed under `failed_hosts`. Hosts
that haven't finished within the timeout keep running the script. Check them
later with falcon_check_rtr_admin_command_status and each host's `task_id`
rather than running the script again. Needs the RTR Admin scope; every run is
recorded in the RTR audit log.

**Example prompts:**

- "Run the collect-triage custom script on these two hosts"

### `falcon_check_rtr_admin_command_status`

**Required scopes:** `Real time response (admin):write`

Check whether RTR Admin commands sent to hosts have finished, and get their output.

Use this after falcon_run_rtr_script_on_hosts or falcon_run_falcon_script returns
hosts that hadn't finished within the timeout. It only reads command status; it
doesn't run anything again.

**Example prompts:**

- "Has the script finished on the hosts that timed out?"

## Resources

- **`falcon://rtr/sessions/search/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_rtr_sessions` tool.
- **`falcon://rtr/audit/sessions/search/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_rtr_audit_sessions` tool.
- **`falcon://rtr/sessions/aggregate-guide`**: Explains how to summarize RTR session activity with the `falcon_aggregate_rtr_sessions` tool.
- **`falcon://rtr/workflows/investigation-guide`**: Provides a safe read-only RTR workflow for endpoint investigation tools.
