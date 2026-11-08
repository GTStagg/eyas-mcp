<!-- meta:title Client Integration -->
<!-- meta:description Connect eyas-mcp to Claude, OpenAI, Gemini, GitHub Copilot, Cursor and other MCP clients. -->
<!-- meta:section usage -->
<!-- meta:link-base /eyas-mcp/ -->

eyas-mcp works with any MCP client. This page shows how to connect the common ones. To build your own application or agent on it, see [Building Your Own Integration](building-integrations.md).

Every example installs eyas-mcp straight from GitHub with [`uvx`](https://docs.astral.sh/uv/). Replace `<id>`, `<secret>`, `<url>` and `<key>` with your own values, and add `@<commit>` to the Git URL to pin a version. Each client documents its own config format, and they change often, so the client's documentation link is included with each example. These were checked against them in November 2026.

The server needs three environment variables: `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET` and `FALCON_BASE_URL` (see [API Credentials](../getting-started/credentials.md)). Add `--read-only` to the arguments of any example to expose only tools that can't change tenant state, or `--modules` to limit which modules load. See [CLI Commands](cli.md).

## Running the server over HTTP

Most examples start eyas-mcp as a local subprocess over stdio. Clients that connect to a URL instead, including a shared team server and OpenAI's hosted tools, need eyas-mcp running over streamable HTTP:

```bash
eyas-mcp --transport streamable-http --host 0.0.0.0 --port 8000 --api-key <key>
```

The endpoint is `http://your-host:8000/mcp`, and clients send the key in an `x-api-key` header. `--host 0.0.0.0` exposes the server on the network, so always set `--api-key` with it, and put TLS in front for anything beyond the local machine. Omit both for local-only use on the default loopback bind. See [HTTP Transport Security](../getting-started/configuration.md#http-transport-security).

An older SSE transport is also available with `--transport sse`, at `http://your-host:8000/sse`.

## Claude Desktop

Docs: [Connect to local MCP servers](https://modelcontextprotocol.io/quickstart/user)

Open the config file from Settings, then Developer, then Edit Config. It lives at:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "eyas-mcp": {
      "command": "uvx",
      "args": [
        "--env-file", "/path/to/.env",
        "--from", "git+https://github.com/GTStagg/eyas-mcp.git",
        "eyas-mcp"
      ]
    }
  }
}
```

`--env-file` is a `uvx` option and must come before `--from`. To pass credentials directly instead, drop it and add an `env` block:

```json
{
  "mcpServers": {
    "eyas-mcp": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/GTStagg/eyas-mcp.git", "eyas-mcp"],
      "env": {
        "FALCON_CLIENT_ID": "<id>",
        "FALCON_CLIENT_SECRET": "<secret>",
        "FALCON_BASE_URL": "<url>"
      }
    }
  }
}
```

Claude Desktop may not inherit your shell's `PATH`. If it can't find `uvx`, use its full path as `command`.

## Claude Code

Docs: [Connect Claude Code to tools via MCP](https://code.claude.com/docs/en/mcp)

```bash
claude mcp add --scope project --transport stdio \
  -e FALCON_CLIENT_ID=<id> -e FALCON_CLIENT_SECRET=<secret> -e FALCON_BASE_URL=<url> \
  eyas-mcp -- uvx --from git+https://github.com/GTStagg/eyas-mcp.git eyas-mcp
```

`--scope` is `local` (the default), `project` (writes a shared `.mcp.json`) or `user`. Keep another option such as `--transport stdio` between the last `-e` and the server name, or the name is read as another variable.

A project `.mcp.json` can read credentials from the environment instead of storing them:

```json
{
  "mcpServers": {
    "eyas-mcp": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/GTStagg/eyas-mcp.git", "eyas-mcp"],
      "env": {
        "FALCON_CLIENT_ID": "${FALCON_CLIENT_ID}",
        "FALCON_CLIENT_SECRET": "${FALCON_CLIENT_SECRET}",
        "FALCON_BASE_URL": "${FALCON_BASE_URL}"
      }
    }
  }
}
```

To connect to a server running over HTTP:

```bash
claude mcp add --transport http eyas-mcp http://localhost:8000/mcp --header "x-api-key: <key>"
```

## VS Code with GitHub Copilot

Docs: [MCP configuration reference](https://code.visualstudio.com/docs/copilot/reference/mcp-configuration)

Add `.vscode/mcp.json` to your workspace. This format prompts for secrets and can read a `.env` file:

```json
{
  "inputs": [
    {"type": "promptString", "id": "falcon-secret", "description": "Falcon client secret", "password": true}
  ],
  "servers": {
    "eyas-mcp": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "git+https://github.com/GTStagg/eyas-mcp.git", "eyas-mcp"],
      "envFile": "${workspaceFolder}/.env",
      "env": {"FALCON_CLIENT_SECRET": "${input:falcon-secret}"}
    }
  }
}
```

For a server over HTTP, add an entry with `"type": "http"`, `"url": "http://localhost:8000/mcp"` and `"headers": {"x-api-key": "${input:eyas-key}"}`, with a matching `promptString` input.

VS Code is moving toward portable config files: a workspace-root `.mcp.json` with a top-level `mcpServers` key (currently behind the `chat.mcp.workspaceRootConfig.enabled` setting), and a Copilot user file at `~/.copilot/mcp-config.json`. Those use the same `mcpServers` shape as Claude Code, support `${NAME}` environment references, and don't support `envFile` or `inputs`. `.vscode/mcp.json` still works.

## Cursor

Docs: [Model Context Protocol](https://cursor.com/docs/context/mcp)

Use `.cursor/mcp.json` in a project, or `~/.cursor/mcp.json` for every project:

```json
{
  "mcpServers": {
    "eyas-mcp": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "git+https://github.com/GTStagg/eyas-mcp.git", "eyas-mcp"],
      "envFile": "${workspaceFolder}/.env"
    },
    "eyas-mcp-http": {
      "url": "http://localhost:8000/mcp",
      "headers": {"x-api-key": "${env:EYAS_MCP_API_KEY}"}
    }
  }
}
```

## Gemini CLI

Docs: [MCP servers with the Gemini CLI](https://geminicli.com/docs/tools/mcp-server/)

Use `~/.gemini/settings.json`, or `.gemini/settings.json` in a project:

```json
{
  "mcpServers": {
    "eyas-mcp": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/GTStagg/eyas-mcp.git", "eyas-mcp"],
      "env": {
        "FALCON_CLIENT_ID": "$FALCON_CLIENT_ID",
        "FALCON_CLIENT_SECRET": "$FALCON_CLIENT_SECRET",
        "FALCON_BASE_URL": "$FALCON_BASE_URL"
      },
      "timeout": 600000
    },
    "eyas-mcp-http": {
      "httpUrl": "http://localhost:8000/mcp",
      "headers": {"x-api-key": "$EYAS_MCP_API_KEY"}
    }
  }
}
```

Use `httpUrl` for streamable HTTP. In the Gemini CLI, `url` means the older SSE transport. `includeTools` and `excludeTools` can narrow the tool list further.

## OpenAI Codex CLI

Docs: [MCP in Codex](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)

Add to `~/.codex/config.toml`:

```toml
[mcp_servers.eyas-mcp]
command = "uvx"
args = ["--from", "git+https://github.com/GTStagg/eyas-mcp.git", "eyas-mcp"]
env_vars = ["FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_BASE_URL"]
startup_timeout_sec = 30

[mcp_servers.eyas-mcp-http]
url = "http://localhost:8000/mcp"
env_http_headers = { "x-api-key" = "EYAS_MCP_API_KEY" }
```

`env_vars` forwards those variables from your shell, and `env_http_headers` reads the header value from the named environment variable. The first start builds eyas-mcp from Git, so allow a longer `startup_timeout_sec` than the 10-second default.

## OpenAI Agents SDK

Docs: [MCP in the Agents SDK](https://openai.github.io/openai-agents-python/mcp/)

```python
import asyncio
import os

from agents import Agent, Runner
from agents.mcp import MCPServerStdio


async def main() -> None:
    async with MCPServerStdio(
        name="eyas-mcp",
        params={
            "command": "uvx",
            "args": ["--from", "git+https://github.com/GTStagg/eyas-mcp.git", "eyas-mcp", "--read-only"],
            "env": {**os.environ},  # must include FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, FALCON_BASE_URL
        },
        client_session_timeout_seconds=60,
        cache_tools_list=True,
    ) as falcon:
        agent = Agent(name="Falcon analyst", mcp_servers=[falcon])
        result = await Runner.run(agent, "How many Windows hosts are in Falcon?")
        print(result.final_output)


asyncio.run(main())
```

For a server over HTTP, use `MCPServerStreamableHttp` with `params={"url": "http://localhost:8000/mcp", "headers": {"x-api-key": os.environ["EYAS_MCP_API_KEY"]}}`. The default session timeout is 5 seconds, which is short for Falcon calls, so raise `client_session_timeout_seconds`.

## OpenAI Responses API

Docs: [Connectors and MCP servers](https://developers.openai.com/api/docs/guides/tools-connectors-mcp)

OpenAI calls a remote MCP server from its own infrastructure, so eyas-mcp must run over streamable HTTP at an address reachable from the internet, behind HTTPS and with `--api-key` set:

```python
tools = [{
    "type": "mcp",
    "server_label": "eyas_mcp",
    "server_url": "https://eyas.example.com/mcp",
    "headers": {"x-api-key": "<key>"},
    "require_approval": "always",
    "allowed_tools": ["falcon_search_detections", "falcon_search_hosts"],
}]
```

`require_approval` can be `"always"`, `"never"`, or `{"never": {"tool_names": [...]}}`, so you can let read-only tools run while every other call waits for approval. `allowed_tools` limits what the model sees. For a server on a private network, OpenAI's Secure MCP Tunnel (`tunnel_id`) is an alternative to a public URL. Consider running this deployment with `--read-only`.

## Cline (VS Code)

Add to your Cline MCP settings:

```json
{
  "mcpServers": {
    "eyas-mcp": {
      "command": "uvx",
      "args": [
        "--env-file", "/path/to/.env",
        "--from", "git+https://github.com/GTStagg/eyas-mcp.git",
        "eyas-mcp"
      ]
    }
  }
}
```

## Docker

Any client that runs a command can run eyas-mcp from a locally built image instead of `uvx` (see [Docker](../deployment/docker.md)). The `-i` flag is required for stdio:

```json
{
  "mcpServers": {
    "eyas-mcp": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--env-file", "/full/path/to/.env", "eyas-mcp:latest"]
    }
  }
}
```
