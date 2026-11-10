<!-- meta:title MCP Config -->
<!-- meta:description MCP configuration file examples for connecting to eyas-mcp. -->
<!-- meta:section examples -->
<!-- meta:link-base /eyas-mcp/ -->

The `examples/mcp_config.json` file shows all three transport configurations in a single file.

## All Transport Configurations

```json
{
  "servers": [
    {
      "name": "falcon-stdio",
      "transport": {
        "type": "stdio",
        "command": "python -m falcon_mcp.server"
      }
    },
    {
      "name": "falcon-sse",
      "transport": {
        "type": "sse",
        "url": "http://127.0.0.1:8000/sse"
      }
    },
    {
      "name": "falcon-streamable-http",
      "transport": {
        "type": "streamable-http",
        "url": "http://127.0.0.1:8000/mcp"
      }
    }
  ]
}
```

## Claude Desktop Configuration

For Claude Desktop, the config format uses `mcpServers`. Place this in `claude_desktop_config.json`:

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

## Selecting Modules

Limit which modules are loaded to reduce tool count:

```json
{
  "mcpServers": {
    "eyas-mcp": {
      "command": "uvx",
      "args": [
        "--env-file", "/path/to/.env",
        "--from",
        "git+https://github.com/GTStagg/eyas-mcp.git",
        "eyas-mcp",
        "--modules", "detections,intel,hosts"
      ]
    }
  }
}
```

## Remote HTTP Server

If running the server on a remote host or in Docker, send the API key you configured with `--api-key`
in the `x-api-key` header:

```json
{
  "mcpServers": {
    "eyas-mcp-remote": {
      "type": "streamable-http",
      "url": "http://your-server:8000/mcp",
      "headers": {
        "x-api-key": "your-api-key"
      }
    }
  }
}
```

Only drop the `headers` block when the endpoint is unauthenticated — for example a loopback-only
server, or one behind a managed runtime (AWS Bedrock AgentCore, Google Cloud Run) whose ingress you've
confirmed rejects unauthenticated requests:

```json
{
  "mcpServers": {
    "eyas-mcp-remote": {
      "type": "streamable-http",
      "url": "http://your-server:8000/mcp"
    }
  }
}
```

See [Transport Methods](../usage/transports.md) for more details on each transport type and client compatibility.
