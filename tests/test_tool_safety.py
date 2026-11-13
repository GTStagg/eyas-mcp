"""Contract tests for tool safety annotations.

Any MCP client may drive this server, and `--read-only` trusts readOnlyHint, so these
tests check each tool's hints against the Falcon operations its code actually reaches.
`BaseModule._add_tool` defaults to read-only annotations, which makes a forgotten
annotation on a write tool look safe. The checks here are what catch that.
"""

import inspect
import re
import unittest
from unittest.mock import MagicMock, patch

from falconpy._endpoint import api_endpoints
from mcp.server.fastmcp import FastMCP

from falcon_mcp import registry
from falcon_mcp.dynamic import DynamicMode
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.modules.custom_ioa import CustomIOAModule
from falcon_mcp.server import FalconMCPServer
from falcon_mcp.tool_filter import ToolPolicy

HTTP_VERBS = {endpoint[0]: endpoint[1] for endpoint in api_endpoints}

# Falcon operations that use a non-GET verb to read. Each entry was reviewed by hand:
# add one only after confirming the operation can't change tenant state.
READS_USING_WRITE_VERBS = frozenset(
    {
        "AggregateAlerts",
        "AggregateAllowList",
        "AggregateBlockList",
        "AggregateCases",
        "AggregateEscalations",
        "AggregateNotificationsExposedDataRecordsV1",
        "AggregateNotificationsV1",
        "AggregateRemediations",
        "GetCaseActivityByIds",
        "GetCaseEntitiesByIDs",
        "GetQuarantineFiles",
        "GetSensorDetails",
        "PostAggregatesAlertsV2",
        "PostDeviceDetailsV2",
        "PostEntitiesAlertsV2",
        "PostMalQueryExactSearchV1",
        "PreviewRuleV1",
        "RTR_AggregateSessions",
        "RTR_ListSessions",
        "StartSearchV1",
        "StopSearchV1",
        "aggregates_access_tags_post_v1",
        "aggregates_file_details_post_v1",
        "aggregates_notification_groups_post_v2",
        "aggregates_slas_post_v1",
        "aggregates_templates_post_v1",
        "api_preempt_proxy_post_graphql",
        "entities_cases_post_v2",
    }
)

# Tools that answer from data shipped with the server and never call Falcon.
LOCAL_ONLY_TOOLS = frozenset({"falcon_lookup_cql_function"})

# These modules build `METHOD,/route` overrides instead of naming FalconPy operations.
OVERRIDE_ONLY_MODULES = frozenset({"agentworks", "guardian"})

# A name like this promises a change, so it must never carry a read-only hint.
WRITE_NAME = re.compile(
    r"falcon_(add|create|delete|dismiss|execute|init|invoke|launch|manage|perform|pulse"
    r"|remove|run|set|update)_"
)


def _modules() -> dict[str, type[BaseModule]]:
    registry.discover_modules()
    return dict(registry.AVAILABLE_MODULES)


def _tools():
    """Yield (module name, module class, tool) for every registered tool."""
    for name, cls in sorted(_modules().items()):
        server = FastMCP("safety")
        cls(MagicMock()).register_tools(server)
        for tool in server._tool_manager._tools.values():
            yield name, cls, tool


def _traced_source(fn, cls, seen) -> str:
    """Return the source of `fn` plus every helper it calls on its own class."""
    fn = inspect.unwrap(fn)
    if fn in seen:
        return ""
    seen.add(fn)
    source = inspect.getsource(fn)
    traced = [source]
    for attr in set(re.findall(r"\b(?:self|cls)\.(\w+)", source)):
        target = inspect.getattr_static(cls, attr, None)
        if isinstance(target, (staticmethod, classmethod)):
            target = target.__func__
        if inspect.isfunction(target) and not hasattr(BaseModule, attr):
            traced.append(_traced_source(target, cls, seen))
    return "\n".join(traced)


def _operations(tool, cls) -> dict[str, str]:
    """Map each Falcon operation a tool can reach to its HTTP verb."""
    source = _traced_source(tool.fn, cls, set())
    module = inspect.getmodule(inspect.unwrap(tool.fn))

    names = set(re.findall(r'["\'](\w+)["\']', source))
    for constant in set(re.findall(r"\b(_?[A-Z][A-Z0-9_]+)\b", source)):
        value = getattr(module, constant, None)
        if isinstance(value, str):
            names.add(value)

    # Modules that share one table pick an operation with a key such as ["query"].
    keys = set(re.findall(r'\["(\w+)"\]', source))
    for entry in getattr(cls, "_OPERATIONS", {}).values():
        names.update(value for key, value in entry.items() if key in keys)

    operations = {
        name: HTTP_VERBS[name] for name in names if isinstance(name, str) and name in HTTP_VERBS
    }
    for verb in re.findall(r'f?["\'](POST|PATCH|PUT|DELETE),', source):
        operations[f"override:{verb}"] = verb
    return operations


class TestToolHintsMatchOperations(unittest.TestCase):
    """A tool's hints must agree with what its code does."""

    @classmethod
    def setUpClass(cls):
        cls.tools = list(_tools())

    def test_tracing_resolves_operations(self):
        """Guard the checks below against silently resolving nothing."""
        by_name = {tool.name: (module_cls, tool) for _, module_cls, tool in self.tools}

        cls_, tool = by_name["falcon_create_policy"]
        self.assertIn("createPreventionPolicies", _operations(tool, cls_))

        cls_, tool = by_name["falcon_search_policies"]
        operations = _operations(tool, cls_)
        self.assertIn("queryPreventionPolicies", operations)
        self.assertNotIn("createPreventionPolicies", operations)

        for module, cls_, tool in self.tools:
            if (
                module not in OVERRIDE_ONLY_MODULES
                and tool.name.startswith("falcon_")
                and tool.name not in LOCAL_ONLY_TOOLS
            ):
                with self.subTest(tool=tool.name):
                    self.assertTrue(_operations(tool, cls_), "no operation resolved")

    def test_read_only_tools_reach_only_read_operations(self):
        for _, cls, tool in self.tools:
            if tool.annotations.readOnlyHint is not True:
                continue
            with self.subTest(tool=tool.name):
                writes = {
                    name
                    for name, verb in _operations(tool, cls).items()
                    if verb != "GET" and name not in READS_USING_WRITE_VERBS
                }
                self.assertEqual(writes, set(), "marked read-only but reaches a write")

    def test_override_only_read_modules_issue_get(self):
        """Tracing can't name these routes, so check the verbs they build instead."""
        for module, cls, tool in self.tools:
            if module == "guardian":
                with self.subTest(tool=tool.name):
                    self.assertIs(tool.annotations.readOnlyHint, True)
                    self.assertNotIn("override:POST", _operations(tool, cls))

    def test_write_names_are_not_marked_read_only(self):
        for _, _, tool in self.tools:
            if WRITE_NAME.match(tool.name):
                with self.subTest(tool=tool.name):
                    self.assertIs(tool.annotations.readOnlyHint, False)

    def test_write_tools_state_every_hint(self):
        for _, _, tool in self.tools:
            if tool.annotations.readOnlyHint is not True:
                with self.subTest(tool=tool.name):
                    self.assertIs(tool.annotations.readOnlyHint, False)
                    self.assertIsNotNone(tool.annotations.destructiveHint)
                    self.assertIsNotNone(tool.annotations.idempotentHint)

    def test_reviewed_reads_are_real_operations(self):
        """A renamed operation must not leave a stale entry on the reviewed list."""
        self.assertEqual(READS_USING_WRITE_VERBS - set(HTTP_VERBS), set())


class TestCustomIoaCreateStaysInert(unittest.TestCase):
    """create_ioa_rule is non-destructive only because new rules start disabled."""

    def test_create_body_cannot_enable_a_rule(self):
        parameters = inspect.signature(CustomIOAModule.create_ioa_rule).parameters
        self.assertNotIn("enabled", parameters)


@patch("falcon_mcp.server.FalconClient")
class TestReadOnlySurface(unittest.TestCase):
    """--read-only must hold across every module and in dynamic mode."""

    def test_read_only_server_exposes_no_write_tools(self, mock_client):
        mock_client.return_value.authenticate.return_value = True
        server = FalconMCPServer(enabled_modules=set(_modules()), read_only=True)

        tools = server.server._tool_manager._tools.values()
        self.assertTrue(tools)
        for tool in tools:
            with self.subTest(tool=tool.name):
                self.assertIs(tool.annotations.readOnlyHint, True)

    def test_dynamic_execute_refuses_write_tools_when_read_only(self, _mock_client):
        client = MagicMock()
        modules = {name: cls(client) for name, cls in _modules().items()}
        dynamic = DynamicMode(modules, MagicMock(), ToolPolicy(read_only=True))

        write_tools = sorted(
            tool.name for _, _, tool in _tools() if tool.annotations.readOnlyHint is not True
        )
        self.assertTrue(write_tools)
        for name in write_tools:
            with self.subTest(tool=name):
                self.assertIsNone(dynamic.catalog.get(name))
                self.assertIsNotNone(dynamic.catalog.withholding_rule(name))


if __name__ == "__main__":
    unittest.main()
