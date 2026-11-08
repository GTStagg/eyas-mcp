"""Tests for scripts/falcon_coverage.py."""

import contextlib
import io
import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

# Ensure project root is on sys.path so the script can be imported
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import falcon_coverage  # noqa: E402
from scripts.falcon_coverage import (  # noqa: E402
    BASELINE_PATH,
    SOURCE_ROOT,
    Coverage,
    Endpoint,
    Usage,
    change_lines,
    compare,
    group_lines,
    load_baseline,
    load_installed,
    main,
    operation_lines,
    override_lines,
    scan_source,
    summary_lines,
    write_baseline,
)

ALERTS_GET = Endpoint("GetAlerts", "GET", "/alerts/queries/alerts/v1")
ALERTS_POST = Endpoint("PostAlerts", "POST", "/alerts/entities/alerts/v1")
HOSTS_GET = Endpoint("get_hosts", "GET", "/devices/entities/devices/v1")
HOSTS_ALIAS = Endpoint("get-hosts", "GET", "/devices/entities/devices/v1")


def usage(names=None, overrides=None) -> Usage:
    result = Usage()
    result.names.update(names or {})
    result.overrides.update(overrides or {})
    return result


class TestCompare(unittest.TestCase):
    """Baseline comparison."""

    def test_identical_tables_have_no_changes(self):
        self.assertFalse(compare([ALERTS_GET], [ALERTS_GET]))

    def test_reports_added_and_removed(self):
        changes = compare([ALERTS_GET], [HOSTS_GET])
        self.assertEqual(changes.added, [HOSTS_GET])
        self.assertEqual(changes.removed, [ALERTS_GET])
        self.assertEqual(changes.changed, {})

    def test_reports_changed_route_and_verb_once(self):
        moved = Endpoint("GetAlerts", "POST", "/alerts/queries/alerts/v2")
        changes = compare([ALERTS_GET], [moved])
        self.assertEqual(changes.added, [])
        self.assertEqual(changes.removed, [])
        self.assertEqual(changes.changed, {"GetAlerts": ([ALERTS_GET], [moved])})

    def test_name_with_several_routes_is_compared_as_a_set(self):
        first = Endpoint("GetAccount", "GET", "/a/v1")
        second = Endpoint("GetAccount", "GET", "/b/v1")
        self.assertFalse(compare([first, second], [second, first]))
        self.assertIn("GetAccount", compare([first], [first, second]).changed)

    def test_repeated_rows_do_not_count_as_changes(self):
        self.assertFalse(compare([ALERTS_GET, ALERTS_GET], [ALERTS_GET]))


class TestBaselineFile(unittest.TestCase):
    """Baseline format."""

    def test_round_trip_is_sorted_and_deduplicated(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            write_baseline(path, "9.9.9", [HOSTS_GET, ALERTS_GET, HOSTS_GET])
            version, endpoints = load_baseline(path)
            self.assertEqual(version, "9.9.9")
            self.assertEqual(endpoints, sorted([ALERTS_GET, HOSTS_GET]))
            self.assertNotIn(b"\r\n", path.read_bytes())

    def test_each_operation_gets_its_own_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            write_baseline(path, "9.9.9", [ALERTS_GET, HOSTS_GET])
            rows = [line for line in path.read_text().splitlines() if '["' in line]
            self.assertEqual(len(rows), 2)

    def test_committed_baseline_is_valid(self):
        version, endpoints = load_baseline(BASELINE_PATH)
        self.assertTrue(version)
        self.assertEqual(endpoints, sorted(set(endpoints)))
        self.assertTrue(all(row.route.startswith("/") for row in endpoints))
        json.loads(BASELINE_PATH.read_text(encoding="utf-8"))


class SourceTree(unittest.TestCase):
    """Scan a temporary falcon_mcp/ tree."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def write(self, name: str, source: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(source), encoding="utf-8")


class TestNameScan(SourceTree):
    """Operation names in the source."""

    def test_finds_exact_string_literals(self):
        self.write("modules/alerts.py", 'OPERATION = "GetAlerts"\n')
        self.assertEqual(
            dict(scan_source(self.root, {"GetAlerts"}).names), {"GetAlerts": {"alerts"}}
        )

    def test_ignores_comments_and_longer_text(self):
        self.write(
            "modules/policies.py",
            """
            # GetAlerts is intentionally not called.
            MESSAGE = "GetAlerts failed"
            """,
        )
        self.assertFalse(scan_source(self.root, {"GetAlerts"}).names)

    def test_scope_table_is_not_usage(self):
        self.write("common/api_scopes.py", 'SCOPES = {"GetAlerts": ["Alerts:read"]}\n')
        self.assertFalse(scan_source(self.root, {"GetAlerts"}).names)

    def test_labels_nested_modules(self):
        self.write("modules/cloud/cloud_iom.py", 'OPERATION = "GetAlerts"\n')
        self.assertEqual(
            scan_source(self.root, {"GetAlerts"}).names["GetAlerts"], {"cloud/cloud_iom"}
        )


class TestOverrideScan(SourceTree):
    """`override=` routes in the source."""

    def overrides(self):
        return scan_source(self.root, set())

    def test_literal_override(self):
        self.write(
            "modules/iom.py",
            'client.command("Label", override="DELETE,/cloud-policies/entities/rules/v1")\n',
        )
        self.assertEqual(
            dict(self.overrides().overrides),
            {"iom": {("DELETE", "/cloud-policies/entities/rules/v1")}},
        )

    def test_guardian_shape_uses_constants_through_a_parameter(self):
        self.write(
            "modules/guardian.py",
            """
            _AGENTS = "/aidr/queries/agents/v1"
            _TOOLS = "/aidr/queries/tools/v1"

            def request(route):
                client.command("label", override=f"GET,{route}")

            request(_AGENTS)
            """,
        )
        self.assertEqual(
            self.overrides().overrides["guardian"],
            {("GET", "/aidr/queries/agents/v1"), ("GET", "/aidr/queries/tools/v1")},
        )

    def test_agentworks_shape_keeps_each_route_with_its_own_verb(self):
        self.write(
            "modules/agentworks.py",
            """
            def fetch(query_route, get_route):
                client.command("q", override=f"GET,{query_route}")
                client.command("g", override=f"GET,{get_route}")

            def send(invoke_route):
                client.command("i", override=f"POST,{invoke_route}")

            fetch(query_route="/studio/queries/agents/v2", get_route="/studio/entities/agents/v2")
            invoke_route = "/studio/entities/invocations/v1"
            send(invoke_route=invoke_route)
            """,
        )
        self.assertEqual(
            self.overrides().overrides["agentworks"],
            {
                ("GET", "/studio/queries/agents/v2"),
                ("GET", "/studio/entities/agents/v2"),
                ("POST", "/studio/entities/invocations/v1"),
            },
        )

    def test_unrelated_route_literals_without_override_are_ignored(self):
        self.write("client.py", 'TOKEN_ROUTE = "/oauth2/token/v1"\n')
        self.assertFalse(self.overrides().overrides)

    def test_override_it_cannot_read_is_reported(self):
        self.write(
            "modules/odd.py",
            """
            client.command("a", override=build_override())
            client.command("b", override=f"GET,/base/{suffix}")
            """,
        )
        result = self.overrides()
        self.assertFalse(result.overrides["odd"])
        self.assertEqual(len(result.unresolved), 2)
        self.assertIn("build_override()", result.unresolved[0])

    def test_template_with_no_known_route_is_reported(self):
        self.write("modules/odd.py", 'client.command("a", override=f"GET,{route}")\n')
        self.assertIn("has no known route", self.overrides().unresolved[0])


class TestCoverage(unittest.TestCase):
    """Marks for each table row."""

    def test_name_override_alias_and_unused(self):
        table = [ALERTS_GET, ALERTS_POST, HOSTS_GET, HOSTS_ALIAS]
        coverage = Coverage(
            table,
            usage(
                names={"GetAlerts": {"alerts"}, "get_hosts": {"hosts"}},
                overrides={"iom": {ALERTS_POST.pair}},
            ),
        )
        self.assertEqual(coverage.mark(ALERTS_GET), "n")
        self.assertEqual(coverage.mark(ALERTS_POST), "o")
        self.assertEqual(coverage.mark(HOSTS_GET), "n")
        self.assertEqual(coverage.mark(HOSTS_ALIAS), "a")
        self.assertEqual(coverage.used_by(HOSTS_ALIAS), ["hosts"])
        self.assertEqual(Coverage(table, usage()).mark(ALERTS_GET), " ")

    def test_name_with_several_routes_reaches_only_the_first_row(self):
        first = Endpoint("GetAccount", "GET", "/a/v1")
        second = Endpoint("GetAccount", "GET", "/b/v1")
        coverage = Coverage([first, second], usage(names={"GetAccount": {"cloud"}}))
        self.assertEqual(coverage.mark(first), "n")
        self.assertEqual(coverage.mark(second), " ")

    def test_summary_counts_endpoints_not_names(self):
        table = [ALERTS_GET, HOSTS_GET, HOSTS_ALIAS]
        coverage = Coverage(table, usage(names={"get_hosts": {"hosts"}}))
        lines = summary_lines("9.9.9", table, coverage)
        self.assertIn("2 endpoints, 3 operation names, 2 route groups", lines[0])
        self.assertIn("reaches 1 of 2 endpoints, in 1 of 2 route groups", lines[1])


class TestReport(unittest.TestCase):
    """Report sections."""

    def test_no_changes(self):
        coverage = Coverage([ALERTS_GET], usage())
        lines = change_lines("1.0", "1.0", compare([ALERTS_GET], [ALERTS_GET]), coverage)
        self.assertEqual(lines[-1], "  None.")

    def test_added_operations_show_what_is_not_covered(self):
        table = [ALERTS_GET, HOSTS_GET]
        coverage = Coverage(table, usage(names={"GetAlerts": {"alerts"}}))
        text = "\n".join(change_lines("1.0", "1.1", compare([], table), coverage))
        self.assertIn("Added: 2 (1 not used yet)", text)
        self.assertIn("[ ] GET    /devices/entities/devices/v1  get_hosts", text)

    def test_removed_operation_still_in_use_is_flagged(self):
        coverage = Coverage([], usage(names={"GetAlerts": {"alerts"}}))
        changes = compare([ALERTS_GET, HOSTS_GET], [])
        text = "\n".join(change_lines("1.0", "1.1", changes, coverage))
        self.assertIn("Removed: 2 (1 still used, fix these first)", text)
        self.assertIn("[!] GET    /alerts/queries/alerts/v1  GetAlerts  (alerts)", text)
        self.assertIn("[ ] GET    /devices/entities/devices/v1  get_hosts", text)

    def test_changed_operation_in_use_is_flagged_with_old_and_new(self):
        moved = Endpoint("GetAlerts", "GET", "/alerts/queries/alerts/v2")
        coverage = Coverage([moved], usage(names={"GetAlerts": {"alerts"}}))
        lines = change_lines("1.0", "1.1", compare([ALERTS_GET], [moved]), coverage)
        self.assertIn("  [!] GetAlerts  (alerts)", lines)
        self.assertIn("      - GET    /alerts/queries/alerts/v1", lines)
        self.assertIn("      + GET    /alerts/queries/alerts/v2", lines)

    def test_override_routes_are_named_and_unknown_ones_stand_out(self):
        coverage = Coverage(
            [ALERTS_GET],
            usage(overrides={"guardian": {ALERTS_GET.pair, ("GET", "/aidr/queries/gone/v1")}}),
        )
        text = "\n".join(override_lines([ALERTS_GET], coverage))
        self.assertIn("guardian: 2 routes, 1 not in FalconPy's table", text)
        self.assertIn("/alerts/queries/alerts/v1  GetAlerts", text)
        self.assertIn("/aidr/queries/gone/v1  NOT IN FALCONPY", text)

    def test_unresolved_overrides_are_shown(self):
        result = usage()
        result.unresolved.append("odd:3: build_override()")
        text = "\n".join(override_lines([], Coverage([], result)))
        self.assertIn("odd:3: build_override()", text)

    def test_groups_count_each_endpoint_once(self):
        table = [ALERTS_GET, ALERTS_POST, HOSTS_GET, HOSTS_ALIAS]
        coverage = Coverage(table, usage(names={"GetAlerts": {"alerts"}}))
        lines = group_lines(table, coverage)
        self.assertIn("  alerts     1 /   2", lines)
        self.assertIn("  devices    0 /   1", lines)

    def test_operations_filter_by_group_and_unused(self):
        table = [ALERTS_GET, ALERTS_POST, HOSTS_GET]
        coverage = Coverage(table, usage(names={"GetAlerts": {"alerts"}}))
        text = "\n".join(operation_lines(table, coverage, ["alerts"], unused_only=True))
        self.assertIn("PostAlerts", text)
        self.assertNotIn("GetAlerts", text)
        self.assertNotIn("get_hosts", text)


class TestMain(unittest.TestCase):
    """Command line."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.baseline = Path(tmp.name) / "baseline.json"

    def run_main(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["--baseline", str(self.baseline), *argv])
        return code, out.getvalue(), err.getvalue()

    def test_missing_baseline_says_what_to_do(self):
        code, _, err = self.run_main()
        self.assertEqual(code, 2)
        self.assertIn("--update-baseline", err)

    def test_unknown_group_is_an_error(self):
        self.assertEqual(self.run_main("--update-baseline")[0], 0)
        code, _, err = self.run_main("--group", "no-such-group")
        self.assertEqual(code, 2)
        self.assertIn("no-such-group", err)

    def test_fresh_baseline_has_no_changes_and_finds_override_modules(self):
        self.run_main("--update-baseline")
        code, out, _ = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn("  None.", out)
        for module in ("agentworks", "guardian", "cloud/cloud_iom"):
            self.assertIn(f"\n{module}: ", out)
        self.assertNotIn("couldn't resolve", out)
        self.assertNotIn("NOT IN FALCONPY", out)
        out.encode("ascii")

    def test_upgrade_shows_new_and_removed_operations(self):
        version, endpoints = load_installed()
        write_baseline(self.baseline, "0.0.1", endpoints)
        new = Endpoint("brandNewOperationV1", "GET", "/brand-new/queries/things/v1")
        used = Endpoint("GetQueriesAlertsV2", "GET", "/alerts/queries/alerts/v2")
        self.assertIn(used, endpoints)
        upgraded = [row for row in endpoints if row != used] + [new]
        with patch.object(falcon_coverage, "load_installed", return_value=("9.9.9", upgraded)):
            _, out, _ = self.run_main()
        self.assertIn(f"[ ] GET    {new.route}  {new.operation}", out)
        self.assertIn("Removed: 1 (1 still used, fix these first)", out)
        self.assertIn(f"[!] GET    {used.route}  {used.operation}  (detections, idp)", out)

    def test_group_list_marks_guardian_routes_as_override(self):
        self.run_main("--update-baseline")
        _, out, _ = self.run_main("--group", "aidr")
        self.assertIn("[o] GET    /aidr/queries/agents/v1  queryAgentsV1  (guardian)", out)
        self.assertNotIn("Route groups", out)

    def test_needs_no_network_or_credentials(self):
        self.run_main("--update-baseline")
        forbidden = AssertionError("network used")
        with patch("socket.socket", side_effect=forbidden):
            with patch.dict("os.environ", clear=False) as env:
                for key in ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET"):
                    env.pop(key, None)
                self.assertEqual(self.run_main("--list")[0], 0)


class TestRealSource(unittest.TestCase):
    """Guard the scan against silently resolving nothing."""

    @classmethod
    def setUpClass(cls):
        _, cls.endpoints = load_installed()
        names = {endpoint.operation for endpoint in cls.endpoints}
        cls.usage = scan_source(SOURCE_ROOT, names)

    def test_every_override_in_the_source_is_resolved(self):
        self.assertEqual(self.usage.unresolved, [])

    def test_agentworks_invoke_routes_are_the_only_post_overrides_there(self):
        posts = {route for verb, route in self.usage.overrides["agentworks"] if verb == "POST"}
        self.assertEqual(
            posts,
            {
                "/agentic-studio/entities/agent-invocations/v1",
                "/agentic-studio/entities/agent-version-invocations/v1",
            },
        )

    def test_guardian_stays_read_only(self):
        self.assertEqual({verb for verb, _ in self.usage.overrides["guardian"]}, {"GET"})


if __name__ == "__main__":
    unittest.main()
