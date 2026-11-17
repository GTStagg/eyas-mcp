<!-- meta:title eyas-mcp -->
<!-- meta:description Connect AI assistants to the CrowdStrike Falcon platform via the Model Context Protocol. -->
<!-- frontmatter:index sidebar hidden:true -->
<!-- frontmatter:overview sidebar label:"Overview" -->
<!-- meta:link-base /eyas-mcp/ -->

eyas-mcp connects AI assistants to the CrowdStrike Falcon platform through the [Model Context Protocol](https://modelcontextprotocol.io)<!-- link:external -->.

This gives tools like Claude Desktop, VS Code, Gemini CLI, and custom agents direct access to your Falcon environment — enabling AI-powered threat investigation, detection triage, and security operations.

## What can your AI do with Falcon?

<!-- component:card-grid -->
| Title | Description |
|-------|-------------|
| [Investigate Threats](modules/detections.md) | Search detections by severity, time range, hostname, or MITRE ATT&CK technique. |
| [Query Your Fleet](modules/hosts.md) | Find hosts by platform, sensor version, network segment, or containment status, and see their IP and login history. |
| [Hunt Vulnerabilities](modules/spotlight.md) | Pull Spotlight CVE data with ExPRT ratings and remediation priorities, and each host's installed patches. |
| [Research Adversaries](modules/intel.md) | Look up threat actors, indicators, reports, CVE exploitation, malware families, and YARA and Snort rule sets. |
| [Detonate Samples](modules/sandbox.md) | Submit files and URLs to Falcon Sandbox and read what they did. |
| [Scan for Malware](modules/on-demand-scans.md) | Run on-demand scans on hosts and review what they found. |
| [Audit Console Activity](modules/audit-log.md) | See who logged in, changed API clients, or edited policies, and when. |
| [Review Access](modules/users.md) | See who holds which Falcon roles and what each role permits. |
| [Monitor Cloud Posture](modules/cloud.md) | Search CSPM assets, container images, and Kubernetes workloads. |
| [Assess Identity Risk](modules/idp.md) | Investigate entities, analyze timelines, and map relationships. |
| [Execute CQL Queries](modules/ngsiem.md) | Run searches against CrowdStrike Next-Gen SIEM. |
| [Manage IOCs](modules/ioc.md) | Search, create, and remove custom indicators of compromise. |
| [Audit Firewall Rules](modules/firewall.md) | Search and manage Falcon firewall rule groups. |
<!-- /component:card-grid -->

Plus Real Time Response, Case Management, Scheduled Reports, Shield, and more — [see all modules](modules/overview.md). For what eyas-mcp has added since its import from falcon-mcp v0.20.2, see [What eyas-mcp Adds](capabilities.md).

Ready to get started? Follow the [quickstart guide](getting-started/quickstart.md) to connect your first AI assistant in under 5 minutes.
