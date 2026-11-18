<!-- meta:title Seraphic Enterprise Browser -->
<!-- meta:description Falcon Seraphic Enterprise Browser: search the browser agents running in users' browsers, read the browser policy rules, check a browser extension's risk analysis and read the tenant's Seraphic settings; activate or deactivate agents; and queue response tasks on an agent, such as closing every window or removing browsing data -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Falcon Seraphic Enterprise Browser: search the browser agents running in users' browsers, read the browser policy rules, check a browser extension's risk analysis and read the tenant's Seraphic settings; activate or deactivate agents; and queue response tasks on an agent, such as closing every window or removing browsing data

## API Scopes

- `Secure Access:read`
- `Secure Access:write`

## Tools

### `falcon_search_browser_agents`

**Required scopes:** `Secure Access:read`

Search Seraphic Enterprise Browser agents: which users and hosts run a protected browser, and their state.

Each agent is one browser on one host. Records carry `id`, `hostname`,
`username`, `application_name` (the browser), `status`, `artifact_type`,
the extension or workspace version, OS, IP addresses, first and last seen,
whether the agent has the latest policy, and `self_info` (install type and
whether it can be disabled). Filters combine with AND.

**Example prompts:**

- "Which users are running the Seraphic browser extension on Chrome?"

### `falcon_get_browser_agents`

**Required scopes:** `Secure Access:read`

Get Seraphic Enterprise Browser agents by ID, with the IDs that matched no agent in `not_found`.

**Example prompts:**

- "Get the details of browser agent 0b5c8f1e-2d3a-4c6b-9e7f-1a2b3c4d5e6f"

### `falcon_search_browser_rules`

**Required scopes:** `Secure Access:read`

List Seraphic Enterprise Browser policy rules in one category, with their settings and scope.

Each rule has `id`, `name`, `displayName`, `description`, `status` (active or
inactive), `enabled`, `severity`, `priority`, `input_type`, its options in
`childrens`, the users or groups it applies to in `targets` (an empty list
with `anyTarget` true means everyone), the destination groups in
`destinations`, and the message users see when it triggers.

**Example prompts:**

- "Which browser DLP rules are active?"

### `falcon_get_browser_rules`

**Required scopes:** `Secure Access:read`

Get Seraphic Enterprise Browser policy rules by ID, with the IDs that matched no rule in `not_found`.

**Example prompts:**

- "Show browser rule 1042 and who it applies to"

### `falcon_get_browser_extension_analysis`

**Required scopes:** `Secure Access:read`

Get Seraphic's risk analysis of a browser extension: risk score, reputation, permissions and code findings.

The result has the store listing (publisher badges, users, rating), a
`risk_score` with its reasoning, `reputation`, `privacy_policy`,
`classification`, the permissions and sites the extension can reach, code
analysis (obfuscation, native APIs, vulnerable libraries, files containing
secrets, suspicious domains) and the risk score of earlier versions. The
first request for an extension starts the analysis; ask again a minute or
two later for the result.

**Example prompts:**

- "How risky is the Chrome extension ddkjiahejlhfcafbddmgiahcphecmpfh?"

### `falcon_get_browser_tenant_settings`

**Required scopes:** `Secure Access:read`

Get the tenant's Seraphic Enterprise Browser settings: browser sign-in, session and 2FA timeouts, report recipients and branding.

**Example prompts:**

- "How often does the enterprise browser make users sign in?"

### `falcon_activate_browser_agents`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Secure Access:write`

Activate Seraphic Enterprise Browser agents by ID, reversing falcon_deactivate_browser_agents.

**Example prompts:**

- "Reactivate the browser agent I deactivated earlier"

### `falcon_deactivate_browser_agents`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Secure Access:write`

Deactivate Seraphic Enterprise Browser agents by ID. Reverse it with falcon_activate_browser_agents.

Only the IDs given are changed; this tool never acts on a filter.

**Example prompts:**

- "Deactivate the browser agent on the retired kiosk"

### `falcon_run_browser_agent_tasks`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Secure Access:write`

Queue response tasks on a Seraphic browser agent: close every window, refresh every tab or remove browsing data.

Use it to respond to a compromised browser session, for example removing
browsing data after credential theft. Closing windows can lose a user's
unsaved work, and removing browsing data deletes it. The agent runs the
tasks when it next checks in.

**Example prompts:**

- "Remove browsing data and close all windows on that user's browser"
