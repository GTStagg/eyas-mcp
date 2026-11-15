<!-- meta:title Hosts -->
<!-- meta:description Accessing and managing CrowdStrike Falcon hosts/devices -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Accessing and managing CrowdStrike Falcon hosts/devices

## API Scopes

- `Hosts:read`
- `Network Containment Allowlist:read`
- `Hosts:write`
- `Network Containment Allowlist:write`

## Tools

### `falcon_search_hosts`

**Required scopes:** `Hosts:read`

Search hosts and their sensor state: filter by hostname, platform, IP, sensor version, containment (network-quarantine) status, assigned policies, or grouping tags.

Use this to find devices and check their protection state - whether a host is
contained, what sensor version it runs, which policies apply. For drive encryption,
disk/memory/CPU, OS security settings, or internet exposure, use
`falcon_search_managed_assets`. See `falcon://hosts/search/fql-guide` for filters;
returns full host details.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Find all Windows hosts in my environment"
- "Show me hosts last seen in the past 24 hours"

### `falcon_get_host_details`

**Required scopes:** `Hosts:read`

Retrieve detailed information for one or more host device IDs.

Use when you already have specific device IDs from search results, the Falcon
console, or the Streaming API. For discovering hosts by criteria, use
falcon_search_hosts instead. Returns comprehensive host details.

**Example prompts:**

- "Get the full details for host device abc123"

### `falcon_manage_host_grouping_tags`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Hosts:write`

Add or remove Falcon Grouping Tags on one or more hosts.

Set action to 'add' to attach tags, or 'remove' to detach them, on every device
in `ids`. Grouping tags can drive dynamic host group assignment and therefore
policy assignment, so changing them may change a host's security posture.
Adding a tag a host already has, or removing one it lacks, is a no-op. Returns
one record per device, each with `device_id`, `updated`, and `code`. Tag names
are case-sensitive, so removing a tag requires the exact casing it was created
with.

### `falcon_contain_hosts`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Hosts:write`

Network-contain one or more hosts.

Use this to isolate a compromised or suspicious host during incident response.
A contained host loses all network access except to the CrowdStrike Falcon
cloud (and any IPs the tenant's containment policy allows) until containment
is lifted with `falcon_lift_host_containment`, which interrupts its users and
services. Containing an already-contained host is a no-op. Returns the API's
per-host results as `succeeded_ids` and `resources`; on a partial failure,
`partial_failure` is true and `failed_ids` and `errors` say which hosts were
not contained and why. The sensor applies containment asynchronously, so
verify the state afterwards with `falcon_search_hosts` filtering on `status`
(`containment_pending`, then `contained`).

**Example prompts:**

- "Network-contain host 0123456789abcdef0123456789abcdef"
- "Contain the hosts with active critical alerts"

### `falcon_lift_host_containment`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Hosts:write`

Lift network containment from one or more hosts.

Use this once remediation is complete to restore a contained host's normal
network access. Lifting containment on a host that is not contained is a
no-op. Returns the API's per-host results as `succeeded_ids` and `resources`;
on a partial failure, `partial_failure` is true and `failed_ids` and `errors`
say which hosts were not released and why. The sensor applies the change
asynchronously, so verify the state afterwards with `falcon_search_hosts`
filtering on `status` (`lift_containment_pending`, then `normal`).

**Example prompts:**

- "Lift containment on host 0123456789abcdef0123456789abcdef"

### `falcon_get_host_online_state`

**Required scopes:** `Hosts:read`

Check whether hosts are online right now: `state` is online, offline or unknown.

Use this before starting an RTR session, containing a host or running a script,
to know whether the sensor will act now or queue the request. Returns
`results` (one record per host with `id`, `state` and `last_seen`) and
`not_found` (IDs that match no host).

**Example prompts:**

- "Is host 0123456789abcdef0123456789abcdef online right now?"

### `falcon_search_containment_allowlist`

**Required scopes:** `Network Containment Allowlist:read`

List the network containment allowlist: what contained hosts can still reach.

A contained host loses network access except to the Falcon cloud and these
rules: IP addresses and ranges (ip_range), DNS servers (ip_dns) and domains
(fqdn). Check them before containing a host, for example to keep a remediation
server or patch source reachable. Returns `results`, each with `id`, `type`,
`rule`, `label`, `options` (`allow_subdomain` for fqdn rules), `created_by` and
`created_on`, and `counts` by type.

**Example prompts:**

- "What can a contained host still reach?"

### `falcon_create_containment_allowlist_rules`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Network Containment Allowlist:read`, `Network Containment Allowlist:write`

Add rules to the network containment allowlist so contained hosts can still reach them.

Every contained host in the tenant can reach what this allowlist names, so add
only what remediation needs. A domain (fqdn) rule needs at least one DNS server
(ip_dns) rule, existing or in the same call. Rules that already exist with the
same type and value are skipped and listed in `already_present`. Returns the
API's response for the rules added.

**Example prompts:**

- "Let contained hosts reach our remediation subnet 10.20.0.0/16"

### `falcon_update_containment_allowlist_labels`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Network Containment Allowlist:read`, `Network Containment Allowlist:write`

Rename network containment allowlist rules.

Only the label changes. To change a rule's type, value or subdomain option,
delete it and add a new one.

**Example prompts:**

- "Rename the containment allowlist rule for 10.20.0.0/16"

### `falcon_delete_containment_allowlist_rules`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Network Containment Allowlist:read`, `Network Containment Allowlist:write`

Remove rules from the network containment allowlist.

Contained hosts immediately lose access to what the rules allowed, which can cut
a remediation tool or patch source off from them. The last DNS server (ip_dns)
rule can't be removed while any domain (fqdn) rule remains. Returns `deleted` and,
if any removal failed, `failed` with the API's reason.

**Example prompts:**

- "Remove the old patch server from the containment allowlist"

### `falcon_get_host_network_history`

**Required scopes:** `Hosts:read`

Get the history of IP and MAC addresses each host has used.

Use this to tie an IP address seen at a point in time back to the host that held
it, or to see where a host has been on the network. Returns `results` (one
record per host with `device_id` and `history`, a list of `ip_address`,
`mac_address` and `timestamp`) and `not_found` (IDs that match no host).
To find hosts by their current IP, use falcon_search_hosts with `local_ip` or
`external_ip`.

**Example prompts:**

- "Which IP addresses has host 0123456789abcdef0123456789abcdef used?"

### `falcon_get_host_login_history`

**Required scopes:** `Hosts:read`

Get the users who recently logged in to each host, with login times.

Use this to see who was on a host around an incident, or which accounts touch a
machine. Returns `results` (one record per host with `device_id` and
`recent_logins`, a list of `user_name` and `login_time`) and `not_found` (IDs
that match no host). To go the other way, from a user to the hosts they used,
use falcon_get_user_endpoint_history.

**Example prompts:**

- "Who logged in to host 0123456789abcdef0123456789abcdef recently?"
- "Show interactive logins on this host over the last 30 days"

### `falcon_search_hidden_hosts`

**Required scopes:** `Hosts:read`

Search hidden hosts: hosts removed from the console, which falcon_search_hosts does not return.

Hidden hosts drop out of Falcon's reporting, so check them when scoping an
incident or when a known machine is missing from host searches. Returns full
host details (`host_hidden_status` is `hidden`). Restore a host with
falcon_unhide_hosts.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count).

**Example prompts:**

- "List hidden Windows hosts"
- "Is host WS-0142 hidden?"

### `falcon_hide_hosts`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Hosts:write`

Hide hosts: take them out of the console and out of Falcon's reporting.

Use this for decommissioned or duplicate hosts. A hidden host goes silent:
Falcon reports nothing new for it, so never hide a host that is part of an
active investigation. Reverse it with falcon_unhide_hosts;
find hidden hosts with falcon_search_hidden_hosts. Hiding an already hidden host
is a no-op. Returns per-host results as `succeeded_ids` and `resources`; on a
partial failure, `partial_failure` is true and `failed_ids` and `errors` say
which hosts were not hidden and why.

**Example prompts:**

- "Hide the duplicate host record 0123456789abcdef0123456789abcdef"

### `falcon_unhide_hosts`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Hosts:write`

Unhide hosts: restore hidden hosts to the console and to Falcon's reporting.

Unhiding a host that is not hidden is a no-op. Returns per-host results as
`succeeded_ids` and `resources`; on a partial failure, `partial_failure` is true
and `failed_ids` and `errors` say which hosts were not restored and why.

**Example prompts:**

- "Unhide host 0123456789abcdef0123456789abcdef"

### `falcon_delete_hosts`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Hosts:write`

Permanently delete hosts from Falcon. This cannot be undone.

Use this only for hosts that are gone for good, such as retired machines. To
take a host out of view reversibly, use falcon_hide_hosts instead. Returns
per-host results as `succeeded_ids` and `resources`; when the API confirms only
some hosts, `partial_failure` is true and `failed_ids` and `errors` say which.
Verify afterwards with falcon_search_hosts and falcon_search_hidden_hosts before
retrying.

**Example prompts:**

- "Permanently delete retired host 0123456789abcdef0123456789abcdef"

## Resources

- **`falcon://hosts/search/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_hosts` tool.
