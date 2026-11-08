<!-- meta:title Threat Graph -->
<!-- meta:description This module provides read-only tools for looking up vertices and walking edges in CrowdStrike Falcon Threat Graph -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

This module provides read-only tools for looking up vertices and walking edges in CrowdStrike Falcon Threat Graph

## API Scopes

- `Threatgraph:read`

## Tools

### `falcon_get_threatgraph_summary`

**Required scopes:** `Threatgraph:read`

Summarize Threat Graph vertices.

Use this to see what Threat Graph knows about a vertex, such as the process
behind an alert: its properties, device and the edges that touch it. The ids
must be Threat Graph vertex ids taken from Falcon data, such as an alert's
`triggering_process_graph_id`; raw domain, IP or hash values are rejected.
For file hashes use falcon_get_threatgraph_ran_on instead. See
falcon://threatgraph/graph/pivot-guide for vertex types and id formats.
Returns one record per vertex.

**Example prompts:**

- "Summarize the Threat Graph process vertex behind detection <composite_id>"

### `falcon_get_threatgraph_ran_on`

**Required scopes:** `Threatgraph:read`

Find the devices where an indicator was seen in Threat Graph.

Use this to answer "which devices ran this file?" for a SHA256, SHA1 or MD5
hash. Tenants have been seen to reject domain and IP lookups here; for those,
walk from a process with falcon_get_threatgraph_edges. Returns the matching
Threat Graph records and a `pagination.next` cursor, which is null when the
API returns no cursor. An indicator no device ran within the retention
period gives empty results with a `note`, not an error.

**Example prompts:**

- "Find every host where MD5 d41d8cd98f00b204e9800998ecf8427e executed"

### `falcon_get_threatgraph_edges`

**Required scopes:** `Threatgraph:read`

Follow one edge type from a Threat Graph vertex.

Use this to pivot one hop at a time, for example from a process to its child
processes, the domains it looked up or the files it wrote. Each edge names
its neighbouring vertex id, which you can pass back in for the next hop.
Returns the edges and a `pagination.next` cursor, which is null when the API
returns no cursor.

**Example prompts:**

- "Show the child processes of a Threat Graph process vertex"

### `falcon_list_threatgraph_edge_types`

**Required scopes:** `Threatgraph:read`

List the Threat Graph edge types.

Use this to find the right `edge_type` for falcon_get_threatgraph_edges
instead of guessing a name. Returns the edge type names the API accepts.

**Example prompts:**

- "List the Threat Graph edge types I can pivot on"
