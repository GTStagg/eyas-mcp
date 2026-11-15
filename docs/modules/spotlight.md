<!-- meta:title Spotlight -->
<!-- meta:description Accessing and managing CrowdStrike Falcon Spotlight vulnerabilities -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Accessing and managing CrowdStrike Falcon Spotlight vulnerabilities

## API Scopes

- `Vulnerabilities:read`

## Tools

### `falcon_search_vulnerabilities`

**Required scopes:** `Vulnerabilities:read`

Search for vulnerabilities in your CrowdStrike environment.

Use this to find vulnerabilities by CVE severity, status, host, or remediation
state. Consult falcon://spotlight/vulnerabilities/fql-guide before constructing
filter expressions. Returns vulnerability details including CVE info, host context,
and remediation guidance (based on facet selection).
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions. For cursor-based paging, use `pagination.next` as the `after` parameter on the next call.

**Example prompts:**

- "Show me open HIGH severity vulnerabilities"
- "Find vulnerabilities on host xyz"

### `falcon_get_installed_patches`

**Required scopes:** `Vulnerabilities:read`

Get the patches installed on hosts, with pending patches and whether a reboot is required.

Use this to check a host's patch level, or find hosts waiting on a reboot to
finish patching. Each record has `aid`, `hostname`, `device_type`,
`reboot_required`, `active_patches`, `pending_patches`, `last_patch_confirmed`
and `installed_patches` (each with `id` and `status`). For missing patches and
open CVEs, use falcon_search_vulnerabilities.
Responses include `pagination.total` and `pagination.next`.

**Example prompts:**

- "Which hosts need a reboot to finish patching?"
- "What patches are installed on host 0123456789abcdef0123456789abcdef?"

## Resources

- **`falcon://spotlight/vulnerabilities/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_vulnerabilities` tool.
- **`falcon://spotlight/installed-patches/fql-guide`**: Contains the guide for the `filter` param of the `falcon_get_installed_patches` tool.
