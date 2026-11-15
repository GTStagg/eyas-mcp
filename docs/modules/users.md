<!-- meta:title Users and Roles -->
<!-- meta:description Falcon console users and roles: search users, see who holds which roles and what a role permits, grant or revoke roles, reset a user's password or 2FA, and create, rename or delete users -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Falcon console users and roles: search users, see who holds which roles and what a role permits, grant or revoke roles, reset a user's password or 2FA, and create, rename or delete users

## API Scopes

- `User Management:read`
- `User Management:write`

## Tools

### `falcon_search_users`

**Required scopes:** `User Management:read`

Search Falcon console users: login email, name, status, MFA factors, last login and user type.

Use this to find a user's UUID before checking or changing their roles, or to
review accounts (for example ones that have not logged in recently). Each
record has `uuid`, `uid` (login email), `first_name`, `last_name`, `status`,
`factors`, `last_login_at`, `created_at` and `user_type`. For each user's
roles, use falcon_get_user_roles.
Responses include `pagination.total`.

**Example prompts:**

- "List users who have not logged in for 90 days"
- "Find the Falcon user jdoe@example.com"

### `falcon_get_user_roles`

**Required scopes:** `User Management:read`

Get the roles each user holds, or find which users hold a given role.

Returns `results`, one record per user with `uuid` and `grants` (each with
`role_id`, `role_name`, `grant_type` and `expires_at` when temporary), and
`not_found` for UUIDs that match no user. With `role_ids`, only those roles are
reported and `holders` lists the users that hold any of them, which answers
questions like "who is a Falcon Administrator?".

**Example prompts:**

- "Who is a Falcon Administrator?"
- "What roles does jdoe@example.com have?"

### `falcon_search_roles`

**Required scopes:** `User Management:read`

List the Falcon roles available in this tenant, with their IDs and descriptions.

Built-in roles have readable IDs (falconhost_admin is Falcon Administrator,
remote_responder_three is Real Time Responder - Administrator); custom roles
have generated IDs. Returns `results` sorted by display name, each with `id`,
`display_name`, `description`, `type` and `is_global`. Use the IDs with
falcon_get_user_roles, falcon_get_role_permissions and falcon_manage_user_roles.

**Example prompts:**

- "List the custom roles in this tenant"
- "What is the role ID for Real Time Responder - Administrator?"

### `falcon_get_role_permissions`

**Required scopes:** `User Management:read`

List what a role permits: the permission IDs it grants.

Use this to see whether a role allows an action, for example whether a role can
run RTR commands or manage users. Returns `role_id`, `total` (all permissions in
the role), `matched` (after `contains`) and `permissions` (IDs, or full records
with `include_details`), capped at 500 with `truncated` set when there are more.

**Example prompts:**

- "Which RTR permissions does the Falcon Analyst role have?"

### `falcon_manage_user_roles`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `User Management:read`, `User Management:write`

Grant roles to a Falcon user or revoke them.

Roles decide what a user can see and do in Falcon, so a grant can give
administrator or RTR access and a revoke can lock a user out of their work.
The roles are checked against the tenant's role list and the user against the
user list before anything changes; the grant applies in the user's own CID.
Re-granting a held role or revoking one the user lacks changes nothing. Verify
afterwards with falcon_get_user_roles.

**Example prompts:**

- "Grant jdoe the Falcon Analyst - Read Only role until Friday"
- "Revoke RTR Administrator from jdoe"

### `falcon_reset_user_credentials`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `User Management:write`

Reset users' two-factor authentication or password.

Use this when an account may be compromised or a user lost their 2FA device.
The users must set up 2FA again or choose a new password before they can sign
in; Falcon emails them. No credential passes through this tool.

**Example prompts:**

- "Reset 2FA for jdoe, they lost their phone"

### `falcon_create_user`

**Required scopes:** `User Management:write`

Create a Falcon console user. The new user has no roles until granted some.

Falcon emails the user an activation link to set their own password, or signs
them in through single sign-on where that is enabled; this tool never sets a
password. Returns the new user record with its `uuid`; grant roles next with
falcon_manage_user_roles.

**Example prompts:**

- "Create a Falcon user for new.analyst@example.com"

### `falcon_update_user`

**Required scopes:** `User Management:write`

Change a Falcon user's first and last name. Both are required.

The login email (uid), roles and status are not changed by this tool.

**Example prompts:**

- "Change jdoe's last name to Smith"

### `falcon_delete_user`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `User Management:write`

Permanently delete a Falcon console user. This cannot be undone.

The user loses all access at once. To cut access but keep the account, revoke
their roles with falcon_manage_user_roles instead.

**Example prompts:**

- "Delete the Falcon account of a departed employee"

## Resources

- **`falcon://users/search/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_users` tool.
