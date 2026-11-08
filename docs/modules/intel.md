<!-- meta:title Intel -->
<!-- meta:description Accessing and analyzing CrowdStrike Falcon intelligence data -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Accessing and analyzing CrowdStrike Falcon intelligence data

## API Scopes

- `Actors (Falcon Intelligence):read`
- `Indicators (Falcon Intelligence):read`
- `Reports (Falcon Intelligence):read`

## Tools

### `falcon_search_actors`

**Required scopes:** `Actors (Falcon Intelligence):read`

Research threat actors and adversary groups tracked by CrowdStrike intelligence.

Use this to search actors by name, target countries/industries, or activity dates.
Consult falcon://intel/actors/fql-guide before constructing filter expressions.
Returns full actor profiles including aliases, motivations, and targeting details.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Find threat actors targeting financial services"
- "Search for BEAR adversary groups"

### `falcon_search_indicators`

**Required scopes:** `Indicators (Falcon Intelligence):read`

Search for threat indicators and IOCs from CrowdStrike intelligence.

Use this to find indicators by type, publish date, malware family, or threat actor
association. Consult falcon://intel/indicators/fql-guide before constructing filter
expressions. Returns full indicator details including labels, relations, and kill
chain stage.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Find intelligence IOCs of type domain published this year"

### `falcon_search_reports`

**Required scopes:** `Reports (Falcon Intelligence):read`

Search CrowdStrike intelligence publications and threat reports.

Use this to find reports by name, target industry, threat type, or publication date.
Consult falcon://intel/reports/fql-guide before constructing filter expressions.
Returns full report metadata including title, description, and target details.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Find intelligence reports published in the last 30 days"

### `falcon_get_mitre_report`

**Required scopes:** `Actors (Falcon Intelligence):read`

Generate a MITRE ATT&CK report for a given threat actor.

Accepts an actor name (e.g., 'WARP PANDA') or numeric ID. Returns MITRE ATT&CK
tactics, techniques, and procedures (TTPs) for the actor. JSON format returns a
parsed list of dicts; CSV format returns raw CSV text.

**Example prompts:**

- "Generate MITRE ATT&CK report for FANCY BEAR"

### `falcon_get_intel_reports`

**Required scopes:** `Reports (Falcon Intelligence):read`

Read the full content of CrowdStrike intelligence reports by ID.

Use this after falcon_search_reports to read what a report actually says: the
search returns report metadata, and this returns every field, including the
analytic write-up, along with actors, targeting, malware and MITRE ATT&CK
mappings. This is the right tool when asked to go deeper on a campaign or
report than its one-line summary. Long text is clipped to `max_text_chars`;
some long-form reports keep extra depth in an attached PDF that this does not
return.

**Example prompts:**

- "Read the full CrowdStrike intelligence report CSA-260901"

### `falcon_get_intel_actors`

**Required scopes:** `Actors (Falcon Intelligence):read`

Read full CrowdStrike threat actor profiles by ID.

Use this after falcon_search_actors identifies an adversary, when you need the
complete profile rather than the search summary: the full description, aliases,
first and last activity, targeted industries, countries and regions, origins,
motivations, capabilities and objectives. For the actor's ATT&CK techniques, use
falcon_get_mitre_report. Long text is clipped to `max_text_chars`.

**Example prompts:**

- "Give me the full CrowdStrike profile for FANCY BEAR"

## Resources

- **`falcon://intel/actors/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_actors` tool.
- **`falcon://intel/indicators/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_indicators` tool.
- **`falcon://intel/reports/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_reports` tool.
