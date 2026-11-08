"""
Contains Threat Graph resources.
"""

THREATGRAPH_GUIDE = """Falcon Threat Graph pivot guide

Threat Graph is the graph of sensor telemetry for your tenant. Its nodes are
vertices (processes, modules, devices, detections and more) and its links are
typed, directed edges (`child_process`, `dns_request`, `wrote_module` and so
on). The Threat Graph tools look things up in that graph and walk it one hop
at a time. They never change tenant state.

=== Tools ===

falcon_get_threatgraph_summary
  Records for one or more vertices of a single vertex type: properties,
  device, timestamp and the edges that touch them. Takes vertex ids, not raw
  indicator values.

falcon_get_threatgraph_ran_on
  Devices on which an indicator was seen. Built for file hashes
  (`sha256`, `sha1`, `md5`): "which devices ran this binary". A hash no
  device ran within the retention period gives empty results with a note.
  The API also lists `domain`, `ipv4` and `ipv6`, but tenants have been seen
  to reject those with a 400.

falcon_get_threatgraph_edges
  One hop from a vertex id along one named edge type. Each edge row names
  the neighbouring vertex, which you can pass back in for the next hop.

falcon_list_threatgraph_edge_types
  The edge type vocabulary the API accepts (several hundred names). Check it
  before guessing an edge type name.

=== Vertex ids ===

Vertex ids are opaque identifiers that Falcon hands out. Don't build them by
hand and don't pass raw values: the summary tool rejects a domain, IP or hash
with "Invalid or unsupported id". Get them from Falcon data:

  - an alert or detection's `triggering_process_graph_id` or
    `parent_process_graph_id`, shaped `pid:<aid>:<number>`
  - the `id` of a record from falcon_get_threatgraph_summary
  - the neighbouring vertex named in a row from falcon_get_threatgraph_edges

=== Vertex types (vertex_type for the summary tool) ===

Each type has a singular and a plural spelling. Common ones:

  processes                 Process vertices (`pid:` ids). Use this for the
                            process graph ids on alerts.
  module                    A file (executable or library).
  sensor / devices          A Falcon sensor (host).
  detection, incident       Detections and incidents.
  any-vertex                Lets the API work out the type from the id.

The tool accepts only the vertex types FalconPy lists for this endpoint.
File hashes are not vertex types: look them up with
falcon_get_threatgraph_ran_on.

=== Common edge types (edge_type for the edges tool) ===

  child_process / parent_process    Process tree walking
  dns_request                       Process -> domain lookups
  connected_ip4 / connected_ip6     Process -> outbound connections
  wrote_module / written_by_process File writes
  associated_module                 Process -> its executable module
  user / user_session               Process -> user context
  triggered_detection               Process -> detection it raised

Edge type names are lowercase letters, digits and underscores. Run
falcon_list_threatgraph_edge_types for the full list.

=== Parameters shared by several tools ===

scope      `device` (default) for device-scoped vertices such as processes,
           `customer` for tenant-wide vertices.
nano       true returns timestamps with nanosecond precision.
limit      1-100 per page.
offset     The cursor from the previous page's `pagination.next`. Pass it
           unchanged to get the next page. `pagination.next` is null when the
           API returns no cursor.

=== Suggested workflow ===

1. File hash: falcon_get_threatgraph_ran_on with the hash and its type, to
   list the devices that ran it.
2. Alert: take its `triggering_process_graph_id` and call
   falcon_get_threatgraph_summary with vertex_type `processes`.
3. Walk from that process with falcon_get_threatgraph_edges, for example
   `child_process` to see what it spawned, `parent_process` for what started
   it, or `dns_request` for what it resolved.
"""
