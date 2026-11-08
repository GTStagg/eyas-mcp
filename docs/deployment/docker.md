<!-- meta:title Docker -->
<!-- meta:description Build and run eyas-mcp in a Docker container. -->
<!-- meta:section deployment -->
<!-- meta:link-base /eyas-mcp/ -->

eyas-mcp isn't published to a container registry. Build the image from this repository, then run it locally.

## Building the Image

From a clone of this repository:

```bash
docker build -t eyas-mcp:latest .
```

Or build straight from GitHub without cloning:

```bash
docker build -t eyas-mcp:latest https://github.com/GTStagg/eyas-mcp.git#main
```

To pin a specific commit, build from it and tag the image to match:

```bash
docker build -t eyas-mcp:<commit> https://github.com/GTStagg/eyas-mcp.git#<commit>
```

## Running the Image

Run with stdio transport (requires -i flag):

```bash
docker run -i --rm --env-file /path/to/.env eyas-mcp:latest
```

Run with SSE transport:

```bash
docker run --rm -p 8000:8000 --env-file /path/to/.env \
  eyas-mcp:latest --transport sse --host 0.0.0.0
```

Run with streamable-http transport:

```bash
docker run --rm -p 8000:8000 --env-file /path/to/.env \
  eyas-mcp:latest --transport streamable-http --host 0.0.0.0
```

Run with custom port:

```bash
docker run --rm -p 8080:8080 --env-file /path/to/.env \
  eyas-mcp:latest --transport streamable-http --host 0.0.0.0 --port 8080
```

Run with specific modules (stdio transport):

```bash
docker run -i --rm --env-file /path/to/.env \
  eyas-mcp:latest --modules detections,spotlight,idp
```

Use an image you built from a pinned commit:

```bash
docker run -i --rm --env-file /path/to/.env \
  eyas-mcp:<commit>
```

## Using Individual Environment Variables

Instead of a `.env` file, pass variables directly:

```bash
docker run -i --rm \
  -e FALCON_CLIENT_ID=your_client_id \
  -e FALCON_CLIENT_SECRET=your_secret \
  -e FALCON_BASE_URL=https://api.crowdstrike.com \
  eyas-mcp:latest
```

> [!NOTE]
> When using HTTP transports in Docker, always set `--host 0.0.0.0` so the server accepts connections
> from outside the container. This binds to all interfaces *inside* the container; what the endpoint is
> actually reachable from is controlled by how you publish the port (`-p`), the container network, and
> any load balancer in front of it.
>
> The `-i` flag is required when using the default stdio transport.

The HTTP transports have no authentication by default. Whenever the published port is reachable beyond
the local host, set `--api-key` (or the `FALCON_MCP_API_KEY` environment variable) so callers must send
a matching `x-api-key` header, otherwise anyone who can reach the port can drive the server with your
CrowdStrike credentials:

```bash
docker run --rm -p 8000:8000 --env-file /path/to/.env \
  eyas-mcp:latest \
  --transport streamable-http --host 0.0.0.0 --api-key your-secret-key
```

See [HTTP Transport Security](../getting-started/configuration.md#http-transport-security).

## MCP Client Configuration

To use the Docker image with Claude Desktop or similar clients, add to your MCP config:

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
