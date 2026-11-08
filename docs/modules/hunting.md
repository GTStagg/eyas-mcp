<!-- meta:title Hunting -->
<!-- meta:description Searching and reading CrowdStrike's published hunting content: hunting guides (narrative investigation runbooks) and hunting queries (runnable detection and hunting logic, which the API calls intelligence queries) -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Searching and reading CrowdStrike's published hunting content: hunting guides (narrative investigation runbooks) and hunting queries (runnable detection and hunting logic, which the API calls intelligence queries)

## API Scopes

- `CAO Hunting:read`

## Tools

### `falcon_search_hunting_guides`

**Required scopes:** `CAO Hunting:read`

Search CrowdStrike's published hunting guides and return their content.

Use this when planning a threat hunt or investigating a behavior, technique or
adversary, to find the runbook CrowdStrike researchers already wrote for it:
why the activity matters, what to look at, and what to check next. Pair it with
falcon_search_hunting_queries for the runnable logic. Start with `q`; consult
falcon://hunting/guides/fql-guide before building a `filter`. Returns full guide
records, with long text clipped to `max_text_chars`.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Find CrowdStrike hunting guides about credential dumping with mimikatz"
- "Is there a CrowdStrike hunting guide for T1003?"

### `falcon_get_hunting_guides`

**Required scopes:** `CAO Hunting:read`

Read CrowdStrike hunting guides by ID.

Use this when you already hold guide IDs, for example to reread a guide with a
larger `max_text_chars` after a search clipped it. To find guides by topic, use
falcon_search_hunting_guides. Returns full guide records.

**Example prompts:**

- "Show me the full text of hunting guide <id>"

### `falcon_search_hunting_queries`

**Required scopes:** `CAO Hunting:read`

Search CrowdStrike's published hunting queries and return them in full.

Use this before writing a hunting or detection query from scratch: CrowdStrike
researchers publish ready-made queries, most in CQL for Next-Gen SIEM, for many
techniques and tools. Adapt a published query rather than inventing one. Start
with `q`; consult falcon://hunting/queries/fql-guide before building a `filter`.
Returns full query records including the query text, with long text clipped to
`max_text_chars`.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Find CrowdStrike's published hunting queries for suspicious rundll32 activity"

### `falcon_get_hunting_queries`

**Required scopes:** `CAO Hunting:read`

Read CrowdStrike hunting queries by ID.

Use this when you already hold query IDs, for example to fetch an SPL
translation of a query found earlier. To find queries by topic, use
falcon_search_hunting_queries. Returns full query records including the query
text.

**Example prompts:**

- "Get the SPL translation of hunting query <id>"

## Resources

- **`falcon://hunting/guides/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_hunting_guides` tool.
- **`falcon://hunting/queries/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_hunting_queries` tool.
