<!-- meta:title Audit Log -->
<!-- meta:description This module provides read-only tools for the Falcon audit log: who did what in the tenant, from console logins and API client changes to policy, workflow and case edits -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

This module provides read-only tools for the Falcon audit log: who did what in the tenant, from console logins and API client changes to policy, workflow and case edits

## API Scopes

- `Audit:read`

## Tools

### `falcon_search_audit_log`

**Required scopes:** `Audit:read`

Search the Falcon audit log: who did what in the tenant, when and from where.

Covers console logins, API client creation and changes, secret reads, policy,
workflow, case and detection changes, action request approvals, and every API
request. Use it to investigate a suspected compromised admin or API key, or to
see who changed a setting. Runs as a query job: when it finishes within
`wait_seconds`, returns `job_id`, `status`, `total_results`, the first page of
`results` (each with `action_timestamp`, `category`, `action`, `actor_*`,
`target_*`, `geo_*` and `extensions` holding the details) and `pagination`.
Otherwise returns `job_id` with `status` RUNNING; fetch it later with
falcon_get_audit_log_results.

**Example prompts:**

- "Who logged in to the Falcon console in the last 7 days?"
- "Which API clients were created or changed this month?"
- "Show everything user jdoe did yesterday"

### `falcon_get_audit_log_results`

**Required scopes:** `Audit:read`

Get the results of an audit log query job, or the next page of them.

Use it after falcon_search_audit_log returned a RUNNING job, or to page on
through a finished one with `offset`. Returns the same shape as
falcon_search_audit_log: `job_id`, `status`, `total_results`, `results` and
`pagination`, or `status` RUNNING if the job has still not finished.

**Example prompts:**

- "Get the next page of that audit log query"
