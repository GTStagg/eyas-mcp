<!-- meta:title MalQuery -->
<!-- meta:description Searching CrowdStrike's MalQuery malware corpus and checking quota usage -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Searching CrowdStrike's MalQuery malware corpus and checking quota usage

## API Scopes

- `MalQuery:read`

## Tools

### `falcon_get_malquery_quotas`

**Required scopes:** `MalQuery:read`

Get MalQuery quota usage.

Use this before a large hunt to check how many MalQuery searches and downloads
the tenant has used and has left. Returns the quota counters and limits.

**Example prompts:**

- "How many MalQuery searches do we have left this month?"

### `falcon_get_malquery_file_metadata`

**Required scopes:** `MalQuery:read`

Get MalQuery metadata for file hashes.

Use this when you have a file hash and want to know what CrowdStrike's malware
corpus knows about it: file type, size, first-seen date, verdict label and malware
family. The family and label are often good patterns for
`falcon_start_malquery_exact_search`. Returns one record per hash MalQuery knows.

**Example prompts:**

- "Look up the malware family and first-seen date for these hashes in MalQuery"

### `falcon_start_malquery_exact_search`

**Required scopes:** `MalQuery:read`

Start a MalQuery exact search.

Use this to find samples in CrowdStrike's malware corpus that contain a distinctive
string or byte sequence, such as a C2 domain, PDB path or mutex name. It searches
CrowdStrike's corpus, not your hosts, and doesn't change tenant state, but each search
counts against the tenant's MalQuery quota. The search runs asynchronously: this
returns a `request_id` to pass to `falcon_get_malquery_request`. See
falcon://malquery/exact-search/pattern-guide for pattern types and options.

**Example prompts:**

- "Search MalQuery for samples containing the string 'evil-c2.example.com'"
- "Hunt MalQuery for PE files with the hex sequence 4d5a90000300 first seen in 2024"

### `falcon_get_malquery_request`

**Required scopes:** `MalQuery:read`

Get the status and results of a MalQuery search.

Use this to poll a search started with `falcon_start_malquery_exact_search`. When
`status` is `inprogress`, wait and call again; when it is `done`, `results` holds
the matching samples.

**Example prompts:**

- "Is my MalQuery search 9f1c2e4a-6b7d-4c8e-9a0b-1c2d3e4f5a6b finished yet?"

## Resources

- **`falcon://malquery/exact-search/pattern-guide`**: Pattern types, options and workflow for the `falcon_start_malquery_exact_search` and `falcon_get_malquery_request` tools.
