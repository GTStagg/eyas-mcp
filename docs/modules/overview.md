<!-- meta:title Module Overview -->
<!-- meta:description Overview of all available Falcon MCP modules with API scopes. -->
<!-- meta:section modules -->
<!-- meta:link-base /eyas-mcp/ -->
<!-- frontmatter:sidebar order:0 -->

The Falcon MCP Server provides the following modules. Each module requires specific CrowdStrike API scopes.

| Module | API Scopes | Description |
|--------|-------------------|-------------|
| [AgentWorks](agentworks.md) | `Charlotte AI Agent Definition:read`, `Charlotte AI Agent Definition:write` | Calling, listing, and observing CrowdStrike AgentWorks (agentic-studio) Charlotte AI agents and their execution traces |
| [Case Management](cases.md) | `Case Templates:read`, `Cases:read`, `Cases:write` | Managing CrowdStrike cases, including searching, creating, updating, and managing evidence and tags |
| [Cloud Security](cloud.md) | `Cloud Groups V2:read`, `Cloud Security API Assets:read`, `Cloud Security API Detections:read`, `Cloud Security API Risks:read`, `Cloud Security Policies:read`, `Falcon Container Image:read`, `Cloud Security Policies:write` | Accessing and analyzing CrowdStrike Falcon cloud resources like Kubernetes & Containers Inventory, Images Vulnerabilities, Cloud Assets, IOM Findings, CSPM Suppression Rules, Cloud Risks, Cloud Groups, and Cloud Insights |
| [Correlation Rules](correlationrules.md) | `Correlation Rules:read`, `Correlation Rules:write` | Correlation Rules module for CrowdStrike Falcon. |
| [Custom IOA](custom-ioa.md) | `Custom IOA Rules:read`, `Custom IOA Rules:write` | Searching, creating, updating, and deleting Custom IOA (Indicators of Attack) behavioral rules and rule groups using Falcon Custom IOA Service Collection endpoints |
| [Data Security](data-security.md) | `Data Protection:read`, `Data Protection:write` | Provides access to Data Security configuration data — classifications, policies, content patterns, cloud/local applications, enterprise accounts, web locations, sensitivity labels, and file types — so an LLM can inspect, create, and update Data Security rule definitions |
| [Detections](detections.md) | `Alerts:read`, `Alerts:write` | Accessing and analyzing CrowdStrike Falcon detections |
| [Discover](discover.md) | `Assets:read` | Accessing and managing CrowdStrike Falcon Discover applications, managed assets, unmanaged assets, and accounts |
| [Exclusions](exclusions.md) | `IOA Exclusions:read`, `Machine Learning Exclusions:read`, `Sensor Visibility Exclusions:read`, `IOA Exclusions:write`, `Machine Learning Exclusions:write`, `Sensor Visibility Exclusions:write` | This module provides a unified set of tools for managing CrowdStrike exclusions across four types — IOA, Machine Learning, Sensor Visibility, and Certificate-Based — behind a single `exclusion_type` discriminator |
| [Firewall Management](firewall.md) | `Firewall Management:read`, `Firewall Management:write` | Searching and managing firewall rules and rule groups |
| [Fusion SOAR](fusion.md) | `Workflows:read`, `Workflows:write` | Searching Fusion SOAR workflow definitions and executions, reading what an execution produced, and running an on-demand workflow |
| [Guardian](guardian.md) | `AIDR:read` | Provides tools for querying AI agent inventory and activity data |
| [Host Groups](host-groups.md) | `Host Groups:read`, `Hosts:read`, `Host Groups:write` | Searching, creating, updating, and deleting CrowdStrike Falcon host groups, as well as managing group membership |
| [Hosts](hosts.md) | `Hosts:read`, `Hosts:write` | Accessing and managing CrowdStrike Falcon hosts/devices |
| [Hunting](hunting.md) | `CAO Hunting:read` | Searching and reading CrowdStrike's published hunting content: hunting guides (narrative investigation runbooks) and hunting queries (runnable detection and hunting logic, which the API calls intelligence queries) |
| [Identity Protection](idp.md) | `Alerts:read`, `Hosts:read`, `Identity Protection Assessment:read`, `Identity Protection Detections:read`, `Identity Protection Entities:read`, `Identity Protection Policy Rules:read`, `Identity Protection Timeline:read`, `Identity Protection GraphQL:write` | Accessing CrowdStrike Falcon Identity Protection capabilities |
| [Intel](intel.md) | `Actors (Falcon Intelligence):read`, `Indicators (Falcon Intelligence):read`, `Reports (Falcon Intelligence):read` | Accessing and analyzing CrowdStrike Falcon intelligence data |
| [IOC](ioc.md) | `IOC Management:read`, `IOC Management:write` | Searching, creating, and deleting custom IOCs using Falcon IOC Service Collection endpoints |
| [MalQuery](malquery.md) | `MalQuery:read` | Searching CrowdStrike's MalQuery malware corpus and checking quota usage |
| [NGSIEM](ngsiem.md) | `NGSIEM:read`, `NGSIEM:write` | Running search queries against CrowdStrike's Next-Gen SIEM via the asynchronous job-based search API, read-only tools for inspecting its ingest pipeline (data connections, parsers, and lookup files), a process-tree reconstruction built on that search API, and an offline lookup of CQL query functions |
| [Policies](policies.md) | `Content Update Policies:read`, `Device Control Policies:read`, `Firewall Management:read`, `Prevention Policies:read`, `Response Policies:read`, `Sensor Update Policies:read`, `Content Update Policies:write`, `Device Control Policies:write`, `Firewall Management:write`, `Prevention Policies:write`, `Response Policies:write`, `Sensor Update Policies:write` | This module provides a unified set of tools for managing CrowdStrike host-based policies across all six policy types — prevention, sensor_update, firewall, device_control, response, and content_update — behind a single `policy_type` discriminator |
| [Quarantine](quarantine.md) | `Quarantined Files:read`, `Quarantined Files:write` | Investigating quarantined files and applying quarantine actions during triage and remediation workflows |
| [Recon](recon.md) | `Monitoring rules (Falcon Intelligence Recon):read` | Searching Falcon Intelligence Recon notifications, monitoring rules, and exposed-data records |
| [Real Time Response](rtr.md) | `Hosts:read`, `Real time response:read`, `real-time-response-audit:read`, `Real time response (admin):write`, `Real time response:write` | Initiating and inspecting RTR sessions, for executing read-only RTR commands during host investigations, and for managing and running scripts from the tenant's custom RTR script library |
| [Scheduled Reports](scheduled-reports.md) | `Scheduled Reports:read` | Accessing and managing CrowdStrike Falcon scheduled reports and scheduled searches |
| [Sensor Usage](sensor-usage.md) | `Sensor Usage:read` | Accessing CrowdStrike Falcon sensor usage data |
| [Serverless](serverless.md) | `Falcon Container Image:read` | Accessing and managing CrowdStrike Falcon Serverless Vulnerabilities |
| [Shield](shield.md) | `SaaS Security:read`, `SaaS Security:write` | Shield module for CrowdStrike Falcon. |
| [Spotlight](spotlight.md) | `Vulnerabilities:read` | Accessing and managing CrowdStrike Falcon Spotlight vulnerabilities |
| [Threat Graph](threatgraph.md) | `Threatgraph:read` | This module provides read-only tools for looking up vertices and walking edges in CrowdStrike Falcon Threat Graph |
| [Zero Trust Assessment](zero-trust-assessment.md) | `Zero Trust Assessment:read` | Retrieving Zero Trust Assessment posture scores and sensor and OS hardening signals for hosts |
