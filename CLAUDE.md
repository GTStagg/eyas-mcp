# eyas-mcp

Private, independent MCP server for the CrowdStrike Falcon platform, built on FalconPy. This repository is the single home for Falcon MCP work. See `NOTICE.md` for its origin.

## Independence from CrowdStrike's repository

- Never push, open pull requests or issues, comment on, or cross-reference CrowdStrike's `falcon-mcp` repository, including `owner/repo#123` references in commits or PRs.
- The `upstream` remote is fetch-only, with its push URL set to `no_push`. Use it only to analyze diffs for security and patch fixes: `git diff d766b1abaf38a2e668828a57a7a881f82f94be83 upstream/main` (upstream v0.20.2, the import point).
- This repository's history starts from a single clean commit. Never push upstream history, upstream tags, or any branch built on them to `origin`: upstream's history contains a tenant identifier that must stay out of this repository.
- Review upstream changes and apply them yourself. Don't merge `upstream` branches wholesale.
- Pass `--repo GTStagg/eyas-mcp` to every `gh` command.
- Don't add `falcon-mcp` as a dependency. New references to it belong only in historical notes.

## Distribution

eyas-mcp is installed only from this GitHub repository. Never publish it to PyPI or any other package index, or add a release workflow that does.

## Keep these names

The `falcon_mcp` package, `FALCON_MCP_*` variables and `falcon_*` tool names stay as they are, so upstream diffs stay readable and existing prompts keep working. Only outward identity uses `eyas-mcp`.

## Tool safety

Any MCP client may drive this server, so a tool's annotations are its safety contract. Every tool that changes tenant state must declare `readOnlyHint=False` and an accurate `destructiveHint`. New write tools must respect `--read-only`.

`_add_tool` defaults to read-only, so a forgotten annotation looks safe. `tests/test_tool_safety.py` catches that by checking each tool's hints against the Falcon operations it reaches. Add to its reviewed list of reads only after confirming the operation can't change tenant state.

Never interpolate tool arguments into GraphQL queries. Use `json.dumps` for strings, and validate enums, because they're written unquoted.

## Development

`uv` may not be on PATH on Windows. Use the repo's `.venv`.

- Tests: `.venv/Scripts/python -m pytest -q`
- Lint: `.venv/Scripts/python -m ruff check .`
- Dependencies: `.venv/Scripts/python -m uv lock`
- Module docs: `.venv/Scripts/python scripts/generate_module_docs.py`, then commit the result. CI fails when `docs/modules` is stale.
- Integration tests need a real tenant: `pytest --run-integration tests/integration/`

Modules in `falcon_mcp/modules/` are discovered automatically. See `docs/development/module-development.md`.

Commits follow Conventional Commits. Work on a branch and merge through a PR.
