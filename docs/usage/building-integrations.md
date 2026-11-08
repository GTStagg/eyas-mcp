<!-- meta:title Building Your Own Integration -->
<!-- meta:description What an application, agent or assistant can rely on when it builds on eyas-mcp. -->
<!-- meta:section usage -->
<!-- meta:link-base /eyas-mcp/ -->

eyas-mcp is meant to be the Falcon layer under whatever your organization builds: an internal security assistant, an agent in your own app, or an off-the-shelf client such as Claude, ChatGPT, Gemini or GitHub Copilot. This page covers what any MCP client can rely on, so your integration can decide what to show, what to ask a person about, and what to block.

For ready-made client configurations, see [Client Integration](editor-integration.md).

## Pick a transport

| You are building | Use | Why |
|---|---|---|
| A desktop assistant or IDE integration on one machine | `stdio` (default) | The client starts the server as a subprocess. Nothing listens on the network. |
| A shared service, a web app backend, or an agent platform | `streamable-http` | One server answers many clients over HTTP at `/mcp`. |
| A client that only speaks the older HTTP transport | `sse` | Kept for compatibility. Prefer `streamable-http`. |

Over HTTP, set `--api-key` (or `FALCON_MCP_API_KEY`) whenever the port is reachable beyond the local host. Clients then send the key in an `x-api-key` header. Without it, anyone who can reach the port can drive the server with your Falcon credentials. Put TLS in front of the server (a reverse proxy or your platform's load balancer) for anything off the local machine. See [Transports](transports.md) and [HTTP Transport Security](../getting-started/configuration.md#http-transport-security).

## Decide which tools to expose

The server can be narrowed at startup, so a client never sees tools it shouldn't use:

- `--read-only` registers only tools that can't change tenant state.
- `--modules` enables whole modules, for example `--modules detections,hosts,intel`.
- `--tools` adds individual tools by name, and `--exclude-tools` withholds them.
- `--dynamic` exposes three discovery tools instead of every tool, which keeps the tool list small for models with limited context. See [Dynamic Mode](dynamic-mode.md).

Grant the Falcon API client only the scopes the enabled tools need. Each module's page in [`docs/modules`](../modules/overview.md) lists the scopes per tool. A tool called without its scope returns an error naming the missing scopes rather than failing silently.

## Gate actions with tool annotations

Every tool carries MCP [tool annotations](https://modelcontextprotocol.io/specification/2025-06-18/server/tools), and they are the server's safety contract. The test suite checks each tool's hints against the Falcon operations its code actually reaches.

| Annotation | Meaning in eyas-mcp | Suggested client behaviour |
|---|---|---|
| `readOnlyHint: true` | Only reads. Never changes tenant state. | Run without asking. |
| `readOnlyHint: false`, `destructiveHint: false` | Changes state in a way that can be undone or is additive, such as creating a disabled rule or starting an RTR session. | Ask a person to approve, showing the tool name and arguments. |
| `readOnlyHint: false`, `destructiveHint: true` | Deletes data or disrupts hosts, such as deleting a policy or network-containing a host. | Always ask, and make the consequence explicit in the prompt. |
| `idempotentHint: true` | Repeating the same call has no further effect. | Safe to retry after a timeout. |
| `openWorldHint: true` | Talks to the Falcon API. | Expect network latency and API errors. |

Build approval around the hints rather than a list of tool names, so new tools are gated correctly the day they appear. If you also keep your own list, treat any tool with `readOnlyHint: false` that isn't on it as needing approval.

## Read results

Tools return JSON as text content, one object per call.

**Searches** return a page of results:

```json
{
  "results": [{"device_id": "…", "hostname": "…"}],
  "pagination": {"total": 1925, "offset": 0, "limit": 10, "next": null},
  "filter_used": "platform_name:'Windows'"
}
```

`pagination.total` is `null` when the Falcon API doesn't report a count, so you can tell "unknown" from zero. `next` holds the cursor for the next page when the API uses one.

**Errors** come back as an object with an `error` message, plus `details` from the API and, when a permission is missing, `required_scopes` and a `resolution`:

```json
{
  "error": "Failed to search hosts: Permission denied. …",
  "details": {"status_code": 403, "body": {"errors": [{"message": "access denied"}]}},
  "required_scopes": ["Hosts:read"],
  "resolution": "This operation requires the following API scopes: Hosts:read. …"
}
```

**A rejected FQL filter** returns the API's error together with the guide for writing that tool's filters, so a model can correct itself and retry:

```json
{
  "results": [{"error": "…"}],
  "filter_used": "hostname:bad'",
  "fql_guide": "…",
  "hint": "Filter error occurred. Review the FQL guide above to correct your query syntax."
}
```

A filter error never includes `pagination`, so `pagination` is a reliable way to tell a page of results from anything else.

## Use the guide resources

Tools that take an FQL filter publish a matching guide as an MCP resource, at a URI such as `falcon://hosts/search/fql-guide`. Every guide URI ends in `-guide`. Load the relevant guide into the model's context before it writes filters, or expose resources so the model can read them itself. Guides carry no tenant data, so they stay available even when filtering withholds their tool.

## Connect from your own code

Any MCP SDK works. A minimal Python client using the official [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk), with read-only tools only:

```python
import asyncio
import json

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

server = StdioServerParameters(
    command="uvx",
    args=[
        "--env-file", "/path/to/.env",
        "--from", "git+https://github.com/GTStagg/eyas-mcp.git",
        "eyas-mcp", "--read-only",
    ],
)


async def main() -> None:
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            needs_approval = [
                t.name for t in tools.tools
                if not (t.annotations and t.annotations.readOnlyHint)
            ]
            print(f"{len(tools.tools)} tools, {len(needs_approval)} need approval")

            result = await session.call_tool(
                "falcon_search_hosts", {"filter": "platform_name:'Windows'", "limit": 5}
            )
            page = json.loads(result.content[0].text)
            print(page["pagination"]["total"], "Windows hosts")


asyncio.run(main())
```

To reach a shared HTTP deployment instead, use the SDK's streamable HTTP client with the server's `/mcp` URL and an `x-api-key` header.

## Pin what you deploy

eyas-mcp is installed from this GitHub repository and isn't published to a package index or container registry. Pin a commit so an upgrade is a deliberate change: `git+https://github.com/GTStagg/eyas-mcp.git@<commit>` with `uvx` or `pip`, or `docker build https://github.com/GTStagg/eyas-mcp.git#<commit>` for an image. Tool names are kept stable, so prompts and approval lists keep working across upgrades.
