<!-- meta:title Google Cloud -->
<!-- meta:description Deploy the Falcon MCP Server on Google Cloud Run or Vertex AI Agent Engine. -->
<!-- meta:section deployment -->
<!-- meta:link-base /eyas-mcp/ -->

> [!NOTE]
> This guide uses the prebuilt Google ADK agent in [`examples/adk`](https://github.com/GTStagg/eyas-mcp/tree/main/examples/adk), which installs eyas-mcp from this GitHub repository. The example was inherited at the time of the import and hasn't been re-run end to end since.

This guide covers running the Falcon MCP Server with the prebuilt Google ADK agent locally, on Cloud Run, or on Vertex AI Agent Engine.

## Prerequisites

- Python 3.11+, `gcloud` CLI, and `git` installed
- Google Cloud project with billing enabled
- CrowdStrike API credentials

## Running Locally

```bash
git clone https://github.com/GTStagg/eyas-mcp.git
cd eyas-mcp/examples/adk
cp falcon_agent/env.properties falcon_agent/.env
```

Fill in the Falcon and Google Cloud values in `falcon_agent/.env`, then install the dependencies and start the ADK web UI:

<!-- component:tabs -->
#### pip

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r falcon_agent/requirements.txt
adk web
```

#### uv

```bash
uv venv
. .venv/bin/activate
uv pip install -r falcon_agent/requirements.txt
adk web
```
<!-- /component:tabs -->

Access the agent at `http://localhost:8000`. The [example's README](https://github.com/GTStagg/eyas-mcp/tree/main/examples/adk#setting-up-and-running-locally-5-minutes) has the full list of settings.

> [!CAUTION]
> Do not use curly braces (`{variable}`) in the `FALCON_AGENT_PROMPT` value. Google ADK interprets `{name}` patterns as context variables, which causes `Context variable not found` errors at runtime.

## Deploying to Cloud Run

Make sure the required [APIs are enabled](https://cloud.google.com/run/docs/quickstarts/build-and-deploy/deploy-python-service#before-you-begin) on your GCP project, then deploy with the ADK CLI from `examples/adk`:

```bash
adk deploy cloud_run --project <PROJECT_ID> --region <REGION> falcon_agent/
```

Keep IAM authentication on. If you're asked whether to allow unauthenticated invocations, answer **N**. The agent holds your CrowdStrike credentials, so an unauthenticated service lets anyone who finds the URL use them. After deploying, confirm that a request without credentials is rejected:

```bash
curl -s -o /dev/null -w "%{http_code}
" https://<SERVICE_URL>/
# Expect 403
```

Grant access to your team:

1. Cloud Run > Services > your service > Permissions
2. Add Principal > assign `Cloud Run Invoker` role

Team members can then reach the service through an authenticated local proxy:

```bash
gcloud run services proxy <SERVICE_NAME> --project <PROJECT_ID> --region <REGION>
```

The service is then available at `http://localhost:8080`.

## Deploying to Vertex AI Agent Engine

From `examples/adk`:

```bash
adk deploy agent_engine --region <REGION> --display_name falcon_adk_agent falcon_agent/
```

The [example's README](https://github.com/GTStagg/eyas-mcp/tree/main/examples/adk#deploying-to-agent-runtime-and-using-as-gemini-enterprise-app-agent) covers updating a deployed agent and making it available as a Gemini Enterprise agent.

## FQL Guide Resources

The agent is configured with `use_mcp_resources=True`, enabling ADK's MCP resource support. The Falcon MCP Server exposes FQL guide resources (e.g., `falcon://detections/search/fql-guide`) that the agent fetches on demand via the auto-discovered `load_mcp_resource` tool, providing accurate Falcon query construction without embedding all FQL documentation in the system prompt.

## Performance Optimization

Control `MAX_PREV_USER_INTERACTIONS` in your `.env` to limit conversation history sent to the LLM (recommended: 5). This reduces costs while maintaining useful context.
