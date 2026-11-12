<!-- meta:title Host Groups -->
<!-- meta:description Searching, creating, updating, and deleting CrowdStrike Falcon host groups, as well as managing group membership -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Searching, creating, updating, and deleting CrowdStrike Falcon host groups, as well as managing group membership

## API Scopes

- `Host Groups:read`
- `Hosts:read`
- `Host Groups:write`

## Tools

### `falcon_search_host_groups`

**Required scopes:** `Host Groups:read`

Search for host groups in your CrowdStrike environment.

Use this to find host groups by name, type, creator, or timestamps. Consult
falcon://host-groups/search/fql-guide before constructing filter expressions.
Returns full host group details including id, name, group_type, description,
and audit metadata in a single call.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Show me all static host groups"
- "Find host groups created in the last 30 days"

### `falcon_get_host_groups`

**Required scopes:** `Host Groups:read`

Get host groups by ID and report which IDs don't exist.

Use this to confirm a host group still exists and to read its name,
group_type (static, staticByID or dynamic), assignment_rule, description and
audit fields before acting on it. Returns `found` (records in the order of
`ids`) and `not_found` (IDs with no host group).

### `falcon_search_host_group_members`

**Required scopes:** `Host Groups:read`

Search for the host members of a specific host group.

Use this to list the devices that belong to a host group. Requires the group
`id` and filters on HOST attributes (platform, hostname, etc.) — consult
falcon://hosts/search/fql-guide for the filter syntax. Returns full host device
entities including device_id, hostname, platform, and network context.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "List the Windows hosts in host group abc123"
- "Show me the members of the Production Servers group"

### `falcon_get_host_group_membership`

**Required scopes:** `Host Groups:read`, `Hosts:read`

List every host group a single host belongs to.

Use this to answer "which groups is this host in" before changing its group
membership or to explain which policies reach it. Reads the host's group IDs
from its device record, then returns full details for each group, including
name, group_type, and assignment_rule. Dynamic group membership reflects
Falcon's latest evaluation, so a recent tag or attribute change may not show
yet. The host record can be stale; set verify to check membership group by
group, for example verify='static' before saving groups to restore after
incident response.

**Example prompts:**

- "Which host groups is device <device_id> a member of?"

### `falcon_create_host_group`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Host Groups:write`

Create a host group.

Provide a name and group_type. 'dynamic' groups take an assignment_rule (host
FQL) that automatically includes matching hosts. 'static' and 'staticByID' groups
are created empty (no assignment_rule) and populated afterwards via
falcon_perform_host_group_action. Returns the created host group record on success.

**Example prompts:**

- "Create a static host group called 'Critical Servers'"
- "Create a dynamic host group for all Windows hosts"

### `falcon_update_host_group`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Host Groups:write`

Update an existing host group.

Provide the group `id` and any fields to change. name and description are safe
for any group type; only set assignment_rule on 'dynamic' groups. Unspecified
fields are left unchanged. Returns the updated host group record on success.

**Example prompts:**

- "Rename host group abc123 to 'Decommissioned'"
- "Update the assignment rule for the dynamic Windows group"

### `falcon_delete_host_groups`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Host Groups:write`

Delete one or more host groups.

Provide the host group `ids` to delete. This permanently removes the groups.
Returns an empty list on success.

**Example prompts:**

- "Delete host group abc123"

### `falcon_perform_host_group_action`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Host Groups:read`, `Host Groups:write`

Add or remove hosts from one or more static host groups.

Set action_name to 'add-hosts' or 'remove-hosts', provide the target group
`ids`, and select hosts with `device_ids` (preferred) or a host FQL `filter`,
which acts on every matching host. Every group is looked up first: the call
is refused for dynamic groups, whose members come from their assignment rule,
and for group IDs that don't exist. Returns the updated host group records.

**Example prompts:**

- "Add the hosts matching platform_name Windows to group abc123"
- "Remove host device xyz from host group abc123"

## Resources

- **`falcon://host-groups/search/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_host_groups` tool.
