<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/eyas-mcp-logo-dark.svg">
    <img alt="eyas-mcp" src="docs/assets/eyas-mcp-logo-light.svg" width="420">
  </picture>
</p>

# eyas-mcp

[![Python Tests](https://github.com/GTStagg/eyas-mcp/actions/workflows/python-test.yml/badge.svg)](https://github.com/GTStagg/eyas-mcp/actions/workflows/python-test.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-0a0a0a?logo=python&logoColor=ef4444)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-dc2626)](LICENSE)
[![Independent project](https://img.shields.io/badge/independent-not_affiliated_with_CrowdStrike-0a0a0a)](NOTICE.md)

**eyas-mcp** is an independent Model Context Protocol (MCP) server for the CrowdStrike Falcon platform. It connects AI agents to Falcon through [FalconPy](https://falconpy.io), with the aim of being a complete, agent-friendly integration layer for the Falcon APIs.

It's built for organizations to put under their own AI integrations: Claude, ChatGPT and the OpenAI Agents SDK, Gemini, GitHub Copilot, Cursor, or an assistant or agent of their own. Any MCP client can use it, and every tool declares whether it reads or changes tenant state so a client can decide what needs a person's approval.

> [!NOTE]
> eyas-mcp is an independent project derived from CrowdStrike's MIT-licensed [falcon-mcp](https://github.com/CrowdStrike/falcon-mcp) at v0.20.2. It is not affiliated with, endorsed by, or supported by CrowdStrike. See [NOTICE.md](NOTICE.md). CrowdStrike and Falcon are trademarks of CrowdStrike, Inc.

## Documentation

See the [`docs/`](docs/overview.md) folder for configuration, usage and module reference. To connect a client, start with [Client Integration](docs/usage/editor-integration.md). To build your own application or agent on eyas-mcp, see [Building Your Own Integration](docs/usage/building-integrations.md).

## Modules

| Module | Description |
| ------ | ----------- |
| Core | Basic connectivity and system information |
| [AgentWorks](docs/modules/agentworks.md) | Call, list, and observe Charlotte AI agents and their execution traces |
| [Case Management](docs/modules/cases.md) | Case lifecycle management, evidence attachment, tagging, and templates |
| [Cloud Security](docs/modules/cloud.md) | Kubernetes containers, image vulnerabilities, CSPM asset inventory, IOM findings, suppression rules, cloud risks, cloud insights, and cloud groups |
| [Correlation Rules](docs/modules/correlationrules.md) | Search, create, update, and manage NG-SIEM correlation rules |
| [Custom IOA](docs/modules/custom-ioa.md) | Create and manage Custom IOA behavioral detection rules and rule groups |
| [Data Security](docs/modules/data-security.md) | Search, create, and update Data Security classifications, policies, content patterns, applications, web locations, sensitivity labels, and file types |
| [Detections](docs/modules/detections.md) | Find, aggregate, analyze, and update detections, and close every open detection on a host, including Next-Gen SIEM correlation alerts |
| [Discover](docs/modules/discover.md) | Search or list the full application inventory, search assets of every entity type (managed, unmanaged and unsupported) with per-type totals, including drive encryption and system-insights posture, and search local and Active Directory accounts |
| [Exclusions](docs/modules/exclusions.md) | Search, create, update, and delete IOA, machine learning, sensor visibility, and certificate-based exclusions |
| [Falcon Complete](docs/modules/falcon-complete.md) | Read Message Center cases and their message threads, and count Falcon Complete escalations, remediations, blocklist and allowlist requests and alerts |
| [Firewall Management](docs/modules/firewall.md) | Search and manage firewall rules and rule groups |
| [Fusion SOAR](docs/modules/fusion.md) | Search Fusion SOAR workflow definitions and executions, list workflow triggers, read execution results, and run on-demand workflows |
| [Guardian](docs/modules/guardian.md) | Monitor AI agent activity, sessions, tool and skill usage, and inventory; fetch records by ID; and rank tool and skill calls across the fleet |
| [Host Groups](docs/modules/host-groups.md) | Search, get by ID, create, update, and delete host groups; add or remove hosts in static groups by device ID; list the groups a single host belongs to, optionally verified against each group |
| [Hosts](docs/modules/hosts.md) | Search and query hosts/devices, manage grouping tags, and contain or lift containment |
| [Hunting](docs/modules/hunting.md) | Search and read CrowdStrike's published hunting guides and hunting queries, with optional SPL translations |
| [Identity Protection](docs/modules/idp.md) | Entity investigation, highest-risk identities, user-to-endpoint login history, host-to-identity correlation, Identity Protection sensors, and policy rules |
| [Intel](docs/modules/intel.md) | Research threat actors, IOCs, and intelligence reports, and read full report and actor content |
| [IOC](docs/modules/ioc.md) | Search, create, and remove custom indicators of compromise |
| [MalQuery](docs/modules/malquery.md) | Search CrowdStrike's malware corpus by hash or byte pattern and check quota usage |
| [NGSIEM](docs/modules/ngsiem.md) | Execute CQL queries against Next-Gen SIEM with an optional CQL pre-flight check and time and row limits, rebuild a host's process tree, look up CQL functions, and inspect data connections, parsers, and lookup files |
| [Policies](docs/modules/policies.md) | Search, get by ID, create, update, and delete prevention, sensor update, firewall, device control, response, and content update policies; manage host-group assignment, enable/disable, and precedence; report a host's prevention posture |
| [Quarantine](docs/modules/quarantine.md) | Search quarantine records, preview action counts, and release, unrelease, or delete quarantined files |
| [Real Time Response](docs/modules/rtr.md) | Audit and summarize RTR sessions, run read-only triage on one or many hosts, wait until hosts are ready (optionally proven by a test script), run CrowdStrike-published Falcon scripts, and manage and run a custom RTR script library |
| [Recon](docs/modules/recon.md) | Search and aggregate Falcon Intelligence Recon notifications (recon alerts), monitoring rules, and exposed-data records for dark web, leaked credentials, and typosquatting, and preview prospective rule noise |
| [Scheduled Reports](docs/modules/scheduled-reports.md) | Manage scheduled reports and download report files |
| [Sensor Usage](docs/modules/sensor-usage.md) | Access and analyze sensor usage data |
| [Serverless](docs/modules/serverless.md) | Search for vulnerabilities in serverless functions |
| [Shield](docs/modules/shield.md) | SaaS security posture, checks, alerts, app inventory, and AI agents built in connected SaaS platforms |
| [Spotlight](docs/modules/spotlight.md) | Manage and analyze vulnerability data and security assessments |
| [Threat Graph](docs/modules/threatgraph.md) | Look up Threat Graph vertices, find which devices ran a file hash, and pivot along graph edges |
| [Zero Trust Assessment](docs/modules/zero-trust-assessment.md) | Retrieve Zero Trust Assessment posture scores and sensor and OS hardening signals for hosts |

See the [Module Overview](docs/modules/overview.md) for required API scopes, available tools, and FQL resources.

> [!NOTE]
> The Guardian module reads the `/aidr` API, whose route and parameter surface is not
> yet uniform across Falcon deployments. Some tools return HTTP 400 or 404 where an
> older surface is live. See the [Guardian module docs](docs/modules/guardian.md) for the details.

## Quick Start

### Install

eyas-mcp is installed directly from GitHub and isn't published to any package index:

```bash
uv tool install git+https://github.com/GTStagg/eyas-mcp.git
```

### Configure

Set the required environment variables (or use a `.env` file — see the [Configuration Guide](docs/getting-started/configuration.md)):

```bash
export FALCON_CLIENT_ID="your-client-id"
export FALCON_CLIENT_SECRET="your-client-secret"
export FALCON_BASE_URL="https://api.crowdstrike.com"
```

### Run

```bash
eyas-mcp
```

See the [Getting Started guide](docs/getting-started/installation.md) for full installation and configuration details.

## Client Integration

The example below is Claude Desktop's format, which most clients share. See [Client Integration](docs/usage/editor-integration.md) for Claude Code, VS Code with GitHub Copilot, Cursor, Gemini CLI, OpenAI Codex CLI, the OpenAI Agents SDK and the Responses API.

### Using `uvx` (recommended)

```json
{
  "mcpServers": {
    "eyas-mcp": {
      "command": "uvx",
      "args": [
        "--env-file",
        "/path/to/.env",
        "--from",
        "git+https://github.com/GTStagg/eyas-mcp.git",
        "eyas-mcp"
      ]
    }
  }
}
```

### With Module Selection

```json
{
  "mcpServers": {
    "eyas-mcp": {
      "command": "uvx",
      "args": [
        "--env-file",
        "/path/to/.env",
        "--from",
        "git+https://github.com/GTStagg/eyas-mcp.git",
        "eyas-mcp",
        "--modules",
        "detections,hosts,intel"
      ]
    }
  }
}
```

### Docker

```json
{
  "mcpServers": {
    "eyas-mcp-docker": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--env-file",
        "/full/path/to/.env",
        "eyas-mcp:latest"
      ]
    }
  }
}
```

See the [Usage guide](docs/usage/cli.md) for all command line options, module configuration, and library usage.

## Container Usage

```bash
# Build the image from this repository
docker build -t eyas-mcp .

# Run with .env file (stdio transport)
docker run -i --rm --env-file /path/to/.env eyas-mcp:latest

# Run with streamable-http transport (add --api-key when the port is reachable beyond localhost)
docker run --rm -p 8000:8000 --env-file /path/to/.env \
  eyas-mcp:latest \
  --transport streamable-http --host 0.0.0.0 --api-key your-secret-key
```

> [!CAUTION]
> HTTP transports have no authentication by default. Binding to a non-loopback address (`--host 0.0.0.0`)
> exposes an unauthenticated server that anyone who can reach the port can drive with your CrowdStrike
> credentials. Keep the default loopback bind for local use and set `--api-key` whenever you bind wider.
> On a managed runtime such as AWS Bedrock AgentCore or Google Cloud Run, the platform can authenticate
> callers for you, but only if its ingress is set to require it. Check that an unauthenticated request
> from outside is rejected before you rely on it. See the
> [Configuration guide](docs/getting-started/configuration.md#http-transport-security).

See the [Docker Deployment guide](docs/deployment/docker.md) for building from GitHub, pinning a commit, custom ports, and advanced configurations.

## Dynamic Mode

Running many modules at once inflates the context window every AI client must hold. Dynamic mode
replaces the full tool surface with three tools — `falcon_list_enabled_tools` to see every tool the
server has available, `falcon_search_tools` to find candidate tools by keyword and then fetch the parameter
schema for the one you pick, and `falcon_execute_tool` to run it — so agents only load the schemas
they actually need.

```bash
eyas-mcp --dynamic
# or: FALCON_MCP_DYNAMIC=true
```

See the [Dynamic Mode guide](docs/usage/dynamic-mode.md) for
the full discover → execute workflow and trade-offs.

## Restricting What a Server Can Do

`--modules` is all-or-nothing per module: enabling one to get its search tools also exposes every
mutating tool it carries. Three tool-level options narrow that surface.

```bash
# Investigation-only server: no tool that mutates tenant state is registered
eyas-mcp --read-only

# Expose exactly two tools, nothing else
eyas-mcp --tools falcon_search_detections,falcon_search_hosts

# Keep the module, drop one tool
eyas-mcp --modules hostgroups --exclude-tools falcon_delete_host_groups

# All of detections, plus one tool from a module you did not enable
eyas-mcp --modules detections --tools falcon_search_applications
```

| Flag | Environment Variable | Effect |
| --- | --- | --- |
| `--read-only` | `FALCON_MCP_READ_ONLY` | Registers only read-only tools |
| `--tools` | `FALCON_MCP_TOOLS` | Allow-list of tool names, added to the enabled modules |
| `--exclude-tools` | `FALCON_MCP_EXCLUDE_TOOLS` | Deny-list of tool names |

Tool names are the `falcon_`-prefixed names your client displays. An unrecognized name aborts
startup rather than being ignored, so a typo in a deny-list cannot silently leave a tool exposed.

### Composing the options

`--tools` is **additive**, not a narrowing filter. It grants individual tools on top of whatever
`--modules` already enabled, reaching across the module boundary:

- `--tools X` on its own registers **only** X — no modules are loaded by default.
- `--modules detections --tools X` registers every `detections` tool **plus** X, even when X
  belongs to a module that is not enabled. That module contributes only X, not its whole surface,
  and `falcon_list_enabled_modules` does not list it. `falcon_list_enabled_tools` does list X — it
  reports the tools available on the server, so it is the reliable answer to "is this capability
  available here?"

To *subtract*, use `--exclude-tools` or `--read-only`. All four knobs compose, and they resolve in
a fixed order:

1. `--exclude-tools` removes a tool unconditionally, even if `--tools` names it.
2. `--read-only` removes every mutating tool unconditionally, even if `--tools` names it.
3. `--tools` adds the tools it names, bypassing the module gate.
4. `--modules` decides which tools are candidates by default.

Because the first two rules always win, `--read-only` and `--exclude-tools` are safe to set as a
deployment-wide floor: an additive `--tools` list cannot widen past them. Combining them is how you
express "search everything, change nothing, and don't even offer that one tool":

```bash
eyas-mcp --read-only --exclude-tools falcon_execute_rtr_read_only_command
```

Filtering applies to dynamic mode too — a withheld tool is absent from `falcon_search_tools`
results and rejected by `falcon_execute_tool`. Because dynamic mode dispatches by name rather than
registering tools individually, that rejection spells out that the tool exists but the server's
configuration withholds it, and names the one rule responsible, so an agent reports a disabled tool
as disabled instead of telling the user the capability does not exist.
`falcon_list_enabled_tools` carries a `filters_active` field in either mode whenever a rule is in
effect. The startup log reports which rules are active and how many tools `--read-only` and
`--exclude-tools` withheld, so you can confirm what you deployed. Run with `--debug` to see the
withheld tools by name.

These options filter tools, not resources. A withheld tool's FQL guide resource stays available —
guides are static field documentation carrying no tenant data.

## Deployment Options

- [Docker](docs/deployment/docker.md)
- [Google Cloud (Agent Platform / Gemini Enterprise)](./examples/adk/README.md) (inherited example, not re-tested since the move to eyas-mcp)

## Development

```bash
# Clone and install
git clone https://github.com/GTStagg/eyas-mcp.git
cd eyas-mcp
uv sync --all-extras

# Run tests
uv run pytest
```

### Developer Documentation

- [Documentation Guide](docs/development/docs-site.md): Architecture and maintenance guide for the documentation
- [Module Development Guide](docs/development/module-development.md): Instructions for implementing new modules
- [Resource Development Guide](docs/development/resource-development.md): Instructions for implementing resources
- [Integration Testing Guide](docs/development/integration-testing.md): Guide for running integration tests with real API calls

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

This is a personal project with no support commitment. See [SUPPORT.md](SUPPORT.md).

Ideas, suggestions and feedback are welcome as [GitHub Issues](https://github.com/GTStagg/eyas-mcp/issues/new/choose). Code contributions and outside pull requests aren't accepted; see [CONTRIBUTING](.github/CONTRIBUTING.md).
