<!-- meta:title Identity Protection -->
<!-- meta:description Accessing CrowdStrike Falcon Identity Protection capabilities -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Accessing CrowdStrike Falcon Identity Protection capabilities

## API Scopes

- `Alerts:read`
- `Hosts:read`
- `Identity Protection Assessment:read`
- `Identity Protection Detections:read`
- `Identity Protection Entities:read`
- `Identity Protection Policy Rules:read`
- `Identity Protection Timeline:read`
- `Identity Protection GraphQL:write`

## Tools

### `falcon_idp_investigate_entity`

**Required scopes:** `Identity Protection Assessment:read`, `Identity Protection Detections:read`, `Identity Protection Entities:read`, `Identity Protection Timeline:read`, `Identity Protection GraphQL:write`

Investigate one or more Identity Protection entities by ID, name, email, IP, or domain.

Use this to look up entity details, activity timelines, relationship graphs, and risk
assessments; at least one identifier must be supplied, and multiple identifiers are
combined with AND logic (email and IP cannot be combined — email takes precedence).
Returns a structured response with an investigation_summary, resolved entity IDs,
and results keyed by each requested investigation type.

**Example prompts:**

- "Investigate user john.doe@company.com and show their risk assessment"
- "Look up entity Administrator in domain CORP.LOCAL"

### `falcon_search_idp_sensors`

**Required scopes:** `Identity Protection Entities:read`

Search Identity Protection sensors on domain controllers and other identity hosts.

Use this to check Identity Protection coverage and health: which domain
controllers run the identity sensor, their status and status causes, the
assigned identity policy, and per-protocol enforcement settings (Kerberos,
NTLM, LDAP, LDAPS, SMB, RDP). Returns full sensor details.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Which domain controllers have the Identity Protection sensor, and are any unhealthy?"

### `falcon_search_idp_policy_rules`

**Required scopes:** `Identity Protection Policy Rules:read`

Search Identity Protection policy rules.

Use this to review which identity policies are in place, such as rules that
block, require MFA for, or allow authentication traffic, and whether each is
enabled or running in simulation mode. Returns full rule details including
conditions and actions.
Responses include `pagination.total` (the total number of matching rules) — use it to answer "how many" questions.
When it exceeds the number of results, raise `limit` to get the rest.

**Example prompts:**

- "What Identity Protection policy rules are enabled?"
- "List identity policy rules that are still in simulation mode"

### `falcon_search_risky_identities`

**Required scopes:** `Identity Protection Assessment:read`, `Identity Protection Detections:read`, `Identity Protection Entities:read`, `Identity Protection Timeline:read`, `Identity Protection GraphQL:write`

List the highest-risk identities from Identity Protection.

Use this to answer "who are my riskiest users" questions. Returns active
entities sorted by risk score, highest first, each with its risk score,
severity, risk factors (such as stale account, exposed password, or
privileged), and Active Directory account details. To dig into one identity,
pass its entityId to `falcon_idp_investigate_entity`.
Responses include `pagination.next` when more results are available.

**Example prompts:**

- "Who are the 10 riskiest users in Identity Protection?"

### `falcon_get_user_endpoint_history`

**Required scopes:** `Hosts:read`

List the endpoints a user has recently logged into.

Use this to scope a possibly compromised account: it returns the hosts
whose most recent logged-in user is this account, within the lookback
window, newest login first. Each host has device_id, hostname,
last_login_user, last_login_timestamp, platform_name, os_product_name and
last_seen. Only the latest login per host is known, so a host where
someone else has logged in since will not appear. Pass a device_id to
`falcon_correlate_host_identity` for the identity side of one host.
Responses include `pagination.total`, the number of matching hosts.

**Example prompts:**

- "Which endpoints has jdoe logged into in the last 7 days?"

### `falcon_correlate_host_identity`

**Required scopes:** `Alerts:read`, `Hosts:read`, `Identity Protection Assessment:read`, `Identity Protection Detections:read`, `Identity Protection Entities:read`, `Identity Protection Timeline:read`, `Identity Protection GraphQL:write`

Correlate a host with the identity last logged into it.

Use this to bridge an endpoint investigation to Identity Protection.
Returns `host` (device_id, hostname, machine_domain, last_login_user,
last_login_timestamp, platform_name); `identity`, the Identity Protection
entity for that user with its risk score, severity, risk factors and AD
accounts, or null when none matches; and `idp_detections`, recent
Identity Protection detections whose user, source account or destination
account is that user. When the host's domain matches one of several
same-named accounts, that account wins (`identity_match` is 'domain').
If the identity or detection lookup fails, its error is reported in
`identity_error` or `idp_detections_error` and the rest is still returned.
Pass `identity.entityId` to `falcon_idp_investigate_entity` to dig deeper.

**Example prompts:**

- "Who last logged into host 0123456789abcdef0123456789abcdef, and is that identity risky?"

## Resources

- **`falcon://idp/sensors/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_idp_sensors` tool.
