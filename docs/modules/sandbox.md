<!-- meta:title Falcon Sandbox -->
<!-- meta:description Falcon Sandbox (Falcon Intelligence): search detonation reports and submissions, read a trimmed report, submit a file or URL for analysis, upload samples, and delete reports or samples -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Falcon Sandbox (Falcon Intelligence): search detonation reports and submissions, read a trimmed report, submit a file or URL for analysis, upload samples, and delete reports or samples

## API Scopes

- `Sandbox (Falcon Intelligence):read`
- `Sandbox (Falcon Intelligence):write`

## Tools

### `falcon_search_sandbox_reports`

**Required scopes:** `Sandbox (Falcon Intelligence):read`

Search Falcon Sandbox reports and return their summaries: verdict, threat score, file type and environment.

Use this to see whether a file or URL has been detonated before (filter on
sandbox.sha256) or to review recent malicious results. Each summary has `id`,
`verdict`, `created_timestamp` and `sandbox` (with `sha256`, `submit_name`,
`threat_score`, `environment_description` and `file_type`). Read a whole report
with falcon_get_sandbox_report.
Responses include `pagination.total`.

**Example prompts:**

- "Has this SHA256 been detonated in the sandbox before?"
- "Show malicious sandbox results from the last week"

### `falcon_get_sandbox_report`

**Required scopes:** `Sandbox (Falcon Intelligence):read`

Read one sandbox report: what the sample did, trimmed to what an analyst needs.

Returns `id`, `verdict`, `created_timestamp` and `sandbox`, one entry per analysed
sample with its verdict, threat score and file facts, `signatures`,
`mitre_attacks` (each with `severity`), `processes` (with command lines),
`network` (contacted hosts, DNS and HTTP requests, Suricata alerts, URLs) and
`extracted_files`. Extracted strings, the behaviour visualization and binary
structure are left out; full reports run to hundreds of kilobytes.

**Example prompts:**

- "What did the sample in this sandbox report do on the network?"

### `falcon_search_sandbox_submissions`

**Required scopes:** `Sandbox (Falcon Intelligence):read`

Check the state of sandbox submissions: created, running, success or error.

Use this after falcon_submit_to_sandbox to see whether an analysis has finished.
Analysis usually takes under 15 minutes. A finished submission's ID is also its
report ID for falcon_get_sandbox_report.

**Example prompts:**

- "Is my sandbox submission finished yet?"

### `falcon_check_sandbox_samples`

**Required scopes:** `Sandbox (Falcon Intelligence):read`

Check which files are already uploaded to the sandbox, by SHA256.

A file listed in `found` can be submitted with falcon_submit_to_sandbox by its
hash, without uploading it again. Returns `found` and `not_found`.

**Example prompts:**

- "Is this file already uploaded to the sandbox?"

### `falcon_submit_to_sandbox`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Sandbox (Falcon Intelligence):write`

Submit a URL or an uploaded file to Falcon Sandbox for detonation.

The sandbox runs the sample in an isolated machine and reports its behaviour,
usually within 15 minutes. Each submission uses the tenant's sandbox quota.
Returns the submission with its `id` and `state`; follow it with
falcon_search_sandbox_submissions, then read the result with
falcon_get_sandbox_report using the same ID.

**Example prompts:**

- "Detonate this URL in the Windows 10 sandbox with simulated network"

### `falcon_upload_sandbox_sample`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Sandbox (Falcon Intelligence):write`

Upload a file to Falcon Sandbox so it can be submitted for detonation.

The upload is always confidential: only users in this CID can see it, and it is
not shared through MalQuery. Returns the sample's `sha256`; pass it to
falcon_submit_to_sandbox to analyse the file. Uploading the same file again
changes nothing.

**Example prompts:**

- "Upload this file to the sandbox"

### `falcon_delete_sandbox_report`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Sandbox (Falcon Intelligence):write`

Delete a sandbox report permanently.

The report and its analysis can't be recovered; the sample itself stays
uploaded (remove it with falcon_delete_sandbox_sample).

**Example prompts:**

- "Delete this sandbox report"

### `falcon_delete_sandbox_sample`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Sandbox (Falcon Intelligence):write`

Delete an uploaded sample permanently, with its metadata and submissions.

Reports already produced from it are not deleted by this tool.

**Example prompts:**

- "Remove this uploaded sample from the sandbox"
