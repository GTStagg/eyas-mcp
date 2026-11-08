<!-- meta:title Installation -->
<!-- meta:description Install the Falcon MCP Server using uv or pip. -->
<!-- meta:section getting-started -->
<!-- meta:link-base /eyas-mcp/ -->

## Prerequisites

- Python 3.11 or higher
- [`uv`](https://docs.astral.sh/uv/) or pip
- CrowdStrike Falcon API credentials ([see API Credentials](credentials.md))

## Install using uv

```bash
uv tool install git+https://github.com/GTStagg/eyas-mcp.git
```

The repository is private, so your git credentials need access to it. If you use the GitHub CLI, `gh auth setup-git` configures them.

## Install using pip

```bash
pip install git+https://github.com/GTStagg/eyas-mcp.git
```

> [!TIP]
> If `eyas-mcp` isn't found after installation, update your shell `PATH`.

## Run without installing

You can run the server directly without a permanent install using `uvx`:

```bash
uvx --from git+https://github.com/GTStagg/eyas-mcp.git eyas-mcp
```

This is the recommended approach for editor integrations.

> [!NOTE]
> If you just want to interact with eyas-mcp via an agent chat interface rather than running the server yourself, see the [Deployment](../deployment/docker.md) options.
