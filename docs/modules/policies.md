<!-- meta:title Policies -->
<!-- meta:description This module provides a unified set of tools for managing CrowdStrike host-based policies across all six policy types — prevention, sensor_update, firewall, device_control, response, and content_update — behind a single `policy_type` discriminator -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

This module provides a unified set of tools for managing CrowdStrike host-based policies across all six policy types — prevention, sensor_update, firewall, device_control, response, and content_update — behind a single `policy_type` discriminator

## API Scopes

- `Content Update Policies:read`
- `Device Control Policies:read`
- `Firewall Management:read`
- `Prevention Policies:read`
- `Response Policies:read`
- `Sensor Update Policies:read`
- `Content Update Policies:write`
- `Device Control Policies:write`
- `Firewall Management:write`
- `Prevention Policies:write`
- `Response Policies:write`
- `Sensor Update Policies:write`

## Tools

### `falcon_search_policies`

**Required scopes:** `Content Update Policies:read`, `Device Control Policies:read`, `Firewall Management:read`, `Prevention Policies:read`, `Response Policies:read`, `Sensor Update Policies:read`

Search host-based policies of a given type and return full policy records.

Use this to find prevention, sensor update, firewall, device control,
response, or content update policies by name, platform, enabled state, or
timestamp — the `policy_type` parameter selects which policy API is
queried. Consult falcon://policies/search/fql-guide before constructing
filter expressions; the `name` match operator differs per type. Returns
full policy records including id, name, platform_name, enabled, settings,
and assigned host groups.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "List all firewall policies"
- "Show enabled sensor update policies for Windows"
- "Find prevention policies whose name contains 'default'"

### `falcon_get_policies`

**Required scopes:** `Content Update Policies:read`, `Device Control Policies:read`, `Firewall Management:read`, `Prevention Policies:read`, `Response Policies:read`, `Sensor Update Policies:read`

Get full host-based policy records by policy ID.

Use this when you already have policy IDs (for example from a host's
device_policies or an earlier search) and need the complete record: name,
platform_name, enabled, settings (prevention_settings for prevention) and
host groups. Returns `found` (the records, in the order of `ids`) and
`not_found` (the IDs the tenant has no policy of that type for). Read-only.

**Example prompts:**

- "Show the full settings of prevention policy 1a2b3c"

### `falcon_search_policy_members`

**Required scopes:** `Content Update Policies:read`, `Device Control Policies:read`, `Firewall Management:read`, `Prevention Policies:read`, `Response Policies:read`, `Sensor Update Policies:read`

Search for the host members governed by a specific policy.

Use this to list the devices a policy is applied to — answering "which
machines does this policy govern?". This differs from falcon_search_policies
(which returns the policy object, whose groups[] lists host GROUPS, not
resolved hosts) and from falcon_search_host_group_members (which lists one
group's hosts; a policy may target several groups or apply globally).
Requires the policy `id`; filters on HOST attributes — consult
falcon://hosts/search/fql-guide for the filter syntax. Returns full host
device entities including device_id, hostname, platform_name, and network
context.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "What hosts are assigned to firewall policy 1a2b3c?"

### `falcon_get_prevention_posture`

**Required scopes:** `Prevention Policies:read`

Summarize prevention policy posture: what is disabled, unassigned or only detecting.

Use this to answer questions like "which prevention policies detect but don't
block?" across the tenant. For each prevention policy it reports every ML slider's
detection and prevention level, how many toggles are on, its host groups, and
flags: `disabled` (the policy is off), `no_host_groups` (it isn't assigned to any
host group, so it applies to no hosts; never set on `platform_default`) and
`detect_only_sliders` (an ML slider detects with prevention off). Returns a summary with counts per platform and per flag, plus the policies.
For the full settings of one policy use falcon_search_policies. Read-only.

**Example prompts:**

- "Which prevention policies detect but don't block?"
- "Show me disabled or unassigned Windows prevention policies"

### `falcon_create_policy`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Content Update Policies:write`, `Device Control Policies:write`, `Firewall Management:write`, `Prevention Policies:write`, `Response Policies:write`, `Sensor Update Policies:write`

Create a host-based policy of the given type.

Provide a name and (for every type except content_update) a platform_name.
Detailed per-type settings construction is out of scope for v1 — the
typical flow is to clone an existing policy with clone_id and then adjust
it via falcon_update_policy, or pass an opaque settings object. New
policies are created disabled. Returns the created policy record.

**Example prompts:**

- "Create a disabled firewall policy named 'Test FW' for Windows"

### `falcon_update_policy`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Content Update Policies:write`, `Device Control Policies:write`, `Firewall Management:write`, `Prevention Policies:write`, `Response Policies:write`, `Sensor Update Policies:write`

Update an existing host-based policy of the given type.

Provide the policy `id` plus any fields to change (name, description,
settings). platform_name is not updatable after creation. Uses HTTP PATCH
semantics — unspecified fields are left unchanged. Firewall policies accept
only name and description here; they have no settings field, and rule-group
attachment is a whole-container operation this tool does not expose. Returns
the updated policy record.

**Example prompts:**

- "Rename prevention policy 1a2b3c to 'Servers - Strict'"

### `falcon_delete_policies`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Content Update Policies:write`, `Device Control Policies:write`, `Firewall Management:write`, `Prevention Policies:write`, `Response Policies:write`, `Sensor Update Policies:write`

Delete one or more host-based policies of the given type.

Provide the policy_type and a non-empty list of policy `ids`. A policy
must be DISABLED before it can be deleted — an enabled policy returns an
HTTP 400. Set disable_first=true to disable them in the same call, or
disable them first with falcon_perform_policy_action(action_name="disable").
The Default policy of each type cannot be deleted. Returns the API response
for the deletion.

**Example prompts:**

- "Delete firewall policy 1a2b3c"

### `falcon_perform_policy_action`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Content Update Policies:write`, `Device Control Policies:write`, `Firewall Management:write`, `Prevention Policies:write`, `Response Policies:write`, `Sensor Update Policies:write`

Perform an action on one or more policies of the given type.

Use this to enable/disable policies or attach/detach host groups (and, for
prevention, Custom IOA rule groups; for content_update, content overrides).
action_name is validated against the actions valid for that policy_type —
rule-group actions are prevention-only. The add/remove-host-group and
add/remove-rule-group actions require a group_id. Returns the updated policy
records.

**Example prompts:**

- "Disable prevention policy 1a2b3c"
- "Add host group 9z8y7x to sensor update policy 1a2b3c"

### `falcon_set_policy_precedence`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Content Update Policies:read`, `Device Control Policies:read`, `Firewall Management:read`, `Prevention Policies:read`, `Response Policies:read`, `Sensor Update Policies:read`, `Content Update Policies:write`, `Device Control Policies:write`, `Firewall Management:write`, `Prevention Policies:write`, `Response Policies:write`, `Sensor Update Policies:write`

Set the precedence (evaluation order) of policies for a platform.

Two modes, one per call. Complete mode: `ids` is the COMPLETE ordered set of
non-Default policies for the platform, highest precedence first; partial
lists are rejected by the API. Relative mode: name the policy to move in
`move_id` and either place_first=true or place_after=<policy id>; the server
reads the current order, moves that one policy and sends the complete list.
platform_name is required for every type except content_update. Returns the
API response; relative mode returns `{"result": ..., "ids_sent": [...]}`.

**Example prompts:**

- "Set the precedence order of these Windows prevention policies: 1a2b3c, 4d5e6f, 7g8h9i"
- "Move Windows prevention policy 1a2b3c to the top of the precedence order"

## Resources

- **`falcon://policies/search/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_policies` tool.
