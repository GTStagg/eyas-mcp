<!-- meta:title On-Demand Scans -->
<!-- meta:description Falcon on-demand scans (ODS): search scans, their per-host results, the malicious files they found and scheduled scans; start a scan on hosts or host groups; cancel scans; and delete scheduled scans -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Falcon on-demand scans (ODS): search scans, their per-host results, the malicious files they found and scheduled scans; start a scan on hosts or host groups; cancel scans; and delete scheduled scans

## API Scopes

- `On-demand scans (ODS):read`
- `On-demand scans (ODS):write`

## Tools

### `falcon_search_ods_scans`

**Required scopes:** `On-demand scans (ODS):read`

Search on-demand malware scans: status, hosts targeted, files scanned and malicious files found.

Each scan has `id`, `status` (pending, running, completed, incomplete,
canceled), `initiated_from`, `description`, `hosts`, `targeted_platforms`,
`filecount` (scanned, malicious, quarantined, skipped), host counts by state,
the scan settings, and when it started and was created. For per-host results
use falcon_search_ods_scan_hosts; for what was found,
falcon_search_ods_malicious_files.

**Example prompts:**

- "Did any on-demand scan this week find malware?"

### `falcon_search_ods_scan_hosts`

**Required scopes:** `On-demand scans (ODS):read`

Get each host's result in on-demand scans: status, files scanned, malicious and quarantined.

Each record has `scan_id`, `host_id`, `platform_name`, `status`, `filecount`
and when the host started and finished. Filter on scan_id to see how one scan
went on every host.

**Example prompts:**

- "How did the last on-demand scan go on each host?"

### `falcon_search_ods_malicious_files`

**Required scopes:** `On-demand scans (ODS):read`

List the malicious files on-demand scans found: path, hash, severity and whether they were quarantined.

Each record carries `scan_id`, `host_id`, `filepath`, `filename`, `hash`,
`severity` and `quarantined`. Check a hash further with
falcon_search_sandbox_reports.

**Example prompts:**

- "What malicious files did the scan find, and were they quarantined?"

### `falcon_search_ods_scheduled_scans`

**Required scopes:** `On-demand scans (ODS):read`

List recurring on-demand scans set up in the console: their schedule, targets and settings.

**Example prompts:**

- "List the recurring scans set up in the console"

### `falcon_start_ods_scan`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `On-demand scans (ODS):write`

Start an on-demand malware scan of chosen paths on hosts or host groups.

The scan runs on each host as soon as it is online and uses its CPU; with
`quarantine` it also quarantines what it finds. Use it to sweep hosts for a
known threat or after an incident. Follow it with falcon_search_ods_scans,
falcon_search_ods_scan_hosts and falcon_search_ods_malicious_files. Returns the
API's response for the new scan.

**Example prompts:**

- "Scan C:\Users\** on these three hosts and quarantine anything malicious"

### `falcon_cancel_ods_scans`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `On-demand scans (ODS):write`

Cancel running on-demand scans. Files already quarantined stay quarantined.

**Example prompts:**

- "Cancel the on-demand scan that is still running"

### `falcon_delete_ods_scheduled_scans`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `On-demand scans (ODS):write`

Delete scheduled on-demand scans so they stop recurring. This cannot be undone.

Only the IDs given are deleted; this tool never deletes by filter.

**Example prompts:**

- "Delete the old weekly scheduled scan"

## Resources

- **`falcon://ods/search/fql-guide`**: Contains the guide for the `filter` param of the on-demand scan search tools.
