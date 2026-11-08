<!-- meta:title Quick Start -->
<!-- meta:description Get up and running with the Falcon MCP Server in 5 minutes. -->
<!-- meta:section getting-started -->
<!-- meta:link-base /eyas-mcp/ -->

This guide gets you from zero to a working Falcon MCP Server connection in 5 minutes.

## Step 1: Get API Credentials

1. Log into your CrowdStrike console
2. Navigate to **Support > API Clients and Keys**
3. Click **Add new API client** and configure:
   - Give it a name (e.g., "Falcon MCP Server")
   - Enable at minimum: `Hosts:read`, `Alerts:read`
4. Save your **Client ID**, **Client Secret**, and **Base URL**

## Step 2: Install

```bash
uv tool install git+https://github.com/GTStagg/eyas-mcp.git
```

Or run without installing:

```bash
uvx --from git+https://github.com/GTStagg/eyas-mcp.git eyas-mcp --help
```

## Step 3: Configure Credentials

Create a `.env` file in your working directory:

```bash
FALCON_CLIENT_ID=your-client-id
FALCON_CLIENT_SECRET=your-client-secret
FALCON_BASE_URL=https://api.crowdstrike.com
```

## Step 4: Connect to Your Editor

Add to your editor's MCP configuration (e.g., Claude Desktop's `claude_desktop_config.json`):

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

## Step 5: Verify the Connection

In your AI assistant, ask:

> "Check connectivity to the Falcon API"

The server will call `falcon_check_connectivity` and confirm the connection.

> "List all enabled modules"

You should see all modules listed.

## Next Steps

- [CLI Commands](../usage/cli.md) — all command-line options
- [Client Integration](../usage/editor-integration.md) — config examples for popular clients
- [Building Your Own Integration](../usage/building-integrations.md) — what an app or agent can rely on
- [Module Overview](../modules/overview.md) — explore available tools
