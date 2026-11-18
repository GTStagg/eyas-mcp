<!-- meta:title Seraphic Enterprise Browser -->
<!-- meta:description Falcon Seraphic Enterprise Browser: search the browser agents running in users' browsers, read the browser policy rules, destination groups and sensitive data profiles, check a browser extension's risk analysis and read the tenant's Seraphic settings; activate or deactivate agents; queue response tasks on an agent, such as closing every window or removing browsing data; manage destination groups and sensitive data profiles; and change a rule's status or its extension list -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Falcon Seraphic Enterprise Browser: search the browser agents running in users' browsers, read the browser policy rules, destination groups and sensitive data profiles, check a browser extension's risk analysis and read the tenant's Seraphic settings; activate or deactivate agents; queue response tasks on an agent, such as closing every window or removing browsing data; manage destination groups and sensitive data profiles; and change a rule's status or its extension list

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

### `falcon_search_browser_destination_groups`

**Required scopes:** `Secure Access:read`

Search Seraphic Enterprise Browser destination groups: the named sets of sites the browser allows or blocks.

Each group has `id`, `name`, `description`, `domains` (wildcards such as
*.example.com allowed), `singleIps` (addresses or CIDR ranges), `ipsRange`,
`countries`, `classification` (site categories such as Gambling or AI
Related), `default` (true for Seraphic's built-in groups) and a usage count.
The tenant's own groups come first and Seraphic's built-in ones after them,
each part sorted by `sort_by`.

**Example prompts:**

- "Which browser destination groups block gambling sites?"

### `falcon_get_browser_destination_groups`

**Required scopes:** `Secure Access:read`

Get Seraphic Enterprise Browser destination groups by ID, with the IDs that matched no group in `not_found`.

**Example prompts:**

- "Show the domains in destination group 3f2a9c4e-8b1d-4e6f-9a2b-7c5d0e1f2a3b"

### `falcon_search_browser_data_profiles`

**Required scopes:** `Secure Access:read`

Search Seraphic Enterprise Browser sensitive data profiles: the patterns browser DLP looks for.

Each profile has `id`, `name`, `description`, `custom_regex` (name, regex
and threshold), `predefined_piis` (CrowdStrike's built-in detectors),
`apply_exact_match`, who created it, and what uses it.

**Example prompts:**

- "Which sensitive data profiles do the browser DLP rules use?"

### `falcon_get_browser_data_profiles`

**Required scopes:** `Secure Access:read`

Get Seraphic Enterprise Browser sensitive data profiles by ID, with what uses each and IDs that matched nothing in `not_found`.

**Example prompts:**

- "Show the regexes in sensitive data profile 4a3b0d5f-9c2e-4f70-8b3c-8d6e1f2a3b4c"

### `falcon_create_browser_destination_group`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Secure Access:write`

Create a Seraphic Enterprise Browser destination group, a named set of sites for browser rules to allow or block.

Give at least one of domains, single_ips, countries or classifications. The
group does nothing until it is attached in the console.

**Example prompts:**

- "Create a destination group for our file-sharing vendors' domains"

### `falcon_update_browser_destination_group`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Secure Access:read`, `Secure Access:write`

Add or remove sites in a Seraphic Enterprise Browser destination group, or rename it.

The tool reads the group, applies the additions and removals, and sends the
resulting lists, so entries not named stay as they are. The change applies
wherever the group is used. Seraphic's built-in groups can't be changed here.

**Example prompts:**

- "Add *.example.com to the approved AI tools destination group"

### `falcon_delete_browser_destination_group`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Secure Access:read`, `Secure Access:write`

Delete a Seraphic Enterprise Browser destination group. This cannot be undone.

Refuses Seraphic's built-in groups and groups still in use; detach the
group first.

**Example prompts:**

- "Delete the unused test destination group"

### `falcon_create_browser_data_profile`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Secure Access:write`

Create a Seraphic Enterprise Browser sensitive data profile from custom regexes, for browser DLP rules to detect.

The profile does nothing until it is attached in the console. CrowdStrike's
predefined PII detectors aren't offered here, because their names aren't
documented.

**Example prompts:**

- "Create a sensitive data profile that detects our employee ID format"

### `falcon_update_browser_data_profile`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Secure Access:read`, `Secure Access:write`

Add, replace or remove the regexes in a Seraphic Enterprise Browser sensitive data profile, or rename it.

The tool reads the profile, applies the changes and sends the resulting regex
list, so regexes not named stay as they are. The change applies wherever
the profile is used.

**Example prompts:**

- "Add a regex for project codes to the internal identifiers profile"

### `falcon_delete_browser_data_profile`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Secure Access:read`, `Secure Access:write`

Delete a Seraphic Enterprise Browser sensitive data profile. This cannot be undone.

Refuses a profile still in use; detach it first.

**Example prompts:**

- "Delete the sensitive data profile no rule uses"

### `falcon_set_browser_rule_status`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Secure Access:read`, `Secure Access:write`

Turn a Seraphic Enterprise Browser policy rule on or off by setting its status to active or inactive.

Setting a protection or DLP rule inactive stops the browser enforcing it for
everyone it targets. Read the rule with falcon_get_browser_rules first.

**Example prompts:**

- "Turn off browser rule 1042"

### `falcon_update_browser_rule_extensions`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Secure Access:read`, `Secure Access:write`

Add or remove browser extensions on a Seraphic Enterprise Browser extension rule's list.

Whether the listed extensions are blocked or allowed depends on the rule, so
read it with falcon_get_browser_rules first. Check an extension with
falcon_get_browser_extension_analysis before allowing it. The API applies each
kind of change separately, so the tool sends one call per kind and stops at
the first failure; `applied` lists what went through.

**Example prompts:**

- "Add this extension to the browser's extension block rule"
