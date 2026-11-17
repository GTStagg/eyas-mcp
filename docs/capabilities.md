<!-- meta:title What eyas-mcp Adds -->
<!-- meta:description Capabilities eyas-mcp has added since it was imported from falcon-mcp v0.20.2. -->
<!-- meta:link-base /eyas-mcp/ -->

# What eyas-mcp Adds

eyas-mcp was imported from falcon-mcp v0.20.2 and has been developed independently since (see [NOTICE.md](https://github.com/GTStagg/eyas-mcp/blob/main/NOTICE.md)). This page summarizes what it can do that the import point couldn't. The comparison is with falcon-mcp v0.20.2, not with later falcon-mcp releases. It describes capabilities, not individual tools: the [module reference](modules/overview.md) lists every tool, and the [changelog](changelog.md) records each change.

## At a glance

| | falcon-mcp v0.20.2 | eyas-mcp 0.22.0 |
|---|---|---|
| Modules | 28 | 36 |
| Tools | 170 | 273 (103 added, none removed or renamed) |
| Tools that change tenant state | 47 | 81 |
| FalconPy minimum | 1.6.4 | 1.6.7 |

Tool names, the `falcon_mcp` package and the `FALCON_MCP_*` variables are unchanged, so existing prompts and configurations keep working.

## Capabilities

### Host incident response

The import point could find hosts and run read-only Real Time Response (RTR) commands. eyas-mcp covers the whole response loop:

- **Context before acting:** whether a host is online, its IP, MAC and login history, and hosts hidden from the console.
- **Containment:** contain a host or lift containment, and manage the allowlist of addresses and domains a contained host can still reach.
- **Remote response:** a custom RTR script library, CrowdStrike-published Falcon scripts, runs across many hosts at once, and waiting until hosts are ready for a session.
- **Remediation:** on-demand malware scans on hosts or host groups, and their results.
- **Evidence and cleanup:** collect files from hosts straight into cases, close every open detection on a host in one step, and hide or remove retired hosts.

### Investigation

- Process trees rebuilt from Next-Gen SIEM events, including processes Falcon blocked.
- Threat Graph pivots, such as which hosts ran a given file.
- Searches of CrowdStrike's MalQuery malware corpus, and its published hunting guides and queries.
- Hosts linked to the identities that used them, users linked to the hosts they logged in to, the highest-risk identities, and Identity Protection sensors and policy rules.
- Asset search across managed, unmanaged and unsupported devices.
- Next-Gen SIEM searches with time and row limits and an optional CQL syntax check, CQL function lookup, and Next-Gen SIEM data connections, parsers and lookup files.

### Malware analysis and threat intelligence

- **Falcon Sandbox:** submit files or URLs, read reports trimmed to what an analyst needs, and tell samples quarantined on an endpoint from ones submitted by hand.
- **CVE intelligence:** whether a vulnerability is exploited in the wild, and by which actors.
- **Malware families:** profiles with their ATT&CK techniques, and whether each family has been seen in the tenant.
- **Rule sets:** CrowdStrike's YARA and Snort/Suricata rule sets.
- **Reports and actors:** full intelligence report and actor content, not just summaries.

### Governance and accountability

- The Falcon audit log: console logins, API client and secret changes, policy, workflow, case and detection changes, and API requests.
- Users and roles: who holds which role and what each role permits, plus granting or revoking roles, resetting 2FA or passwords, and managing users.
- A host's prevention posture, full policy records by ID, the host groups a host belongs to (verified against each group), and moving a single policy in precedence order.

### Service and platform coverage

- **Falcon Complete:** read, open and reply to Message Center cases, and count escalations, remediations and other dashboard data.
- **AI agent security:** Guardian lookups and fleet-wide tool and skill usage rankings, and AI agents built in SaaS platforms connected to Shield.
- **Spotlight:** each host's installed and pending patches.

## Under the hood

The import point already had dynamic mode, `--read-only`, tool allow and deny lists, scope hints for failed calls, and stdio and HTTP transports. eyas-mcp builds on them.

### Safety annotations are tested

Every tool tells MCP clients whether it reads or changes tenant state, and whether a change is destructive. A test traces each tool to the Falcon operations its code calls and fails when the annotations understate them, so a write tool can't present itself as a read.

### Hardening

- An HTTP server can refuse to start without an API key (`--require-api-key`), and a malformed key gets a 401 instead of a server error.
- Proxy credentials stay out of debug logs, and logs show only the last four characters of a member CID.
- API error details keep the status code and body and leave out response headers.
- Tool arguments are checked so they can't add clauses to FQL filters, chain extra RTR commands or alter GraphQL queries.
- Calls that could reach far more than intended are refused: an IOC removal that names IDs and a filter at once (the API would delete by the filter), and identity investigations that would fan out into thousands of calls.

### Built for agents

- Large responses are trimmed to the fields an analyst uses.
- Lookups by ID return the IDs that matched nothing in a `not_found` list instead of failing the call.
- Long-running searches have time budgets and return a job ID to pick up later.
- Tool and resource lists come out in the same order on every start, so clients' prompt caches stay valid across restarts.

### Independent distribution

eyas-mcp has its own version numbers, starting at 0.21.0. It's installed only from its GitHub repository, and Docker images are built from source.
