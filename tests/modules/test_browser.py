"""
Tests for the Browser (Seraphic Enterprise Browser) module.
"""

import json
import unittest

from mcp.types import ToolAnnotations

from falcon_mcp.modules.browser import BrowserModule
from tests.modules.utils.test_modules import TestModules

AGENT = "0b5c8f1e-2d3a-4c6b-9e7f-1a2b3c4d5e6f"
AGENT2 = "1c6d9f2e-3e4b-4d7c-8f80-2b3c4d5e6f70"
HOST_ID = "f" * 64


def _ok(resources, total=None, status=200, errors=None):
    body = {"resources": resources, "errors": errors or []}
    if total is not None:
        body["meta"] = {"pagination": {"offset": 0, "limit": 20, "total": total}}
    return {"status_code": status, "body": body}


def _bad(message, status=400):
    return {"status_code": status, "body": {"resources": [], "errors": [{"message": message}]}}


SEARCH_DEFAULTS = {
    "hostname": None,
    "username": None,
    "email": None,
    "host_id": None,
    "browser": None,
    "status": None,
    "protection_type": None,
    "os_name": None,
    "last_seen_after": None,
    "last_seen_before": None,
    "first_seen_after": None,
    "first_seen_before": None,
    "search": None,
    "sort_by": "last_seen",
    "sort_order": "desc",
    "limit": 50,
    "offset": 0,
}


class TestBrowserModule(TestModules):
    """Test cases for the Browser module."""

    def setUp(self):
        self.setup_module(BrowserModule)

    def _search(self, **kwargs):
        return self.module.search_browser_agents(**{**SEARCH_DEFAULTS, **kwargs})

    def test_register_tools(self):
        self.assert_tools_registered(
            [
                "falcon_search_browser_agents",
                "falcon_get_browser_agents",
                "falcon_search_browser_rules",
                "falcon_get_browser_rules",
                "falcon_get_browser_extension_analysis",
                "falcon_get_browser_tenant_settings",
                "falcon_activate_browser_agents",
                "falcon_deactivate_browser_agents",
                "falcon_run_browser_agent_tasks",
                "falcon_search_browser_destination_groups",
                "falcon_get_browser_destination_groups",
                "falcon_search_browser_data_profiles",
                "falcon_get_browser_data_profiles",
                "falcon_create_browser_destination_group",
                "falcon_update_browser_destination_group",
                "falcon_delete_browser_destination_group",
                "falcon_create_browser_data_profile",
                "falcon_update_browser_data_profile",
                "falcon_delete_browser_data_profile",
                "falcon_set_browser_rule_status",
                "falcon_update_browser_rule_extensions",
            ]
        )

    def test_write_annotations(self):
        self.module.register_tools(self.mock_server)
        for name, destructive, idempotent in (
            ("falcon_activate_browser_agents", False, True),
            ("falcon_deactivate_browser_agents", False, True),
            ("falcon_run_browser_agent_tasks", True, False),
            ("falcon_create_browser_destination_group", False, False),
            ("falcon_update_browser_destination_group", True, True),
            ("falcon_delete_browser_destination_group", True, True),
            ("falcon_create_browser_data_profile", False, False),
            ("falcon_update_browser_data_profile", True, True),
            ("falcon_delete_browser_data_profile", True, True),
            ("falcon_set_browser_rule_status", True, True),
            ("falcon_update_browser_rule_extensions", True, True),
        ):
            with self.subTest(tool=name):
                self.assert_tool_annotations(
                    name,
                    ToolAnnotations(
                        readOnlyHint=False,
                        destructiveHint=destructive,
                        idempotentHint=idempotent,
                        openWorldHint=True,
                    ),
                )

    # --- agent search ----------------------------------------------------------

    def test_search_agents_builds_structured_filter_and_sort(self):
        self.mock_client.command.return_value = _ok(
            [{"items": [{"id": AGENT}, {"id": AGENT2}], "total": 15}], total=15
        )
        result = self._search(
            hostname=" Desk ",
            status="active",
            browser="chrome",
            host_id=HOST_ID.upper(),
            last_seen_after="2026-11-01T00:00:00Z",
            sort_by="hostname",
            sort_order="asc",
            limit=10,
            offset=20,
            search="ali",
        )
        operation, = self.mock_client.command.call_args.args
        body = self.mock_client.command.call_args.kwargs["body"]
        self.assertEqual(operation, "CombinedQueryAgents")
        self.assertEqual(
            body,
            {
                "limit": 10,
                "skip": 20,
                "sort": [{"field": "hostname", "order": "ASC"}],
                "filter": {
                    "hostname": ["Desk"],
                    "application_name": ["chrome"],
                    "status": ["active"],
                    "host_id": [HOST_ID],
                    "last_seen": {"start": "2026-11-01T00:00:00Z", "end": "2100-01-01T00:00:00Z"},
                },
                "search": "ali",
            },
        )
        self.assertEqual([a["id"] for a in result["results"]], [AGENT, AGENT2])
        self.assertEqual(result["pagination"]["total"], 15)
        self.assertEqual(result["pagination"]["offset"], 20)

    def test_search_agents_fills_open_end_of_a_window(self):
        self.mock_client.command.return_value = _ok([{"items": [], "total": 0}], total=0)
        self._search(first_seen_before="2026-11-01T00:00:00Z")
        body = self.mock_client.command.call_args.kwargs["body"]
        self.assertEqual(
            body["filter"], {"first_seen": {"start": "1970-01-01T00:00:00Z", "end": "2026-11-01T00:00:00Z"}}
        )

    def test_search_agents_without_filters_sends_no_filter(self):
        self.mock_client.command.return_value = _ok([{"items": [], "total": 0}], total=0)
        result = self._search()
        body = self.mock_client.command.call_args.kwargs["body"]
        self.assertNotIn("filter", body)
        self.assertEqual(body["sort"], [{"field": "last_seen", "order": "DESC"}])
        self.assertEqual(result["results"], [])

    def test_search_agents_protection_type_uses_id_query(self):
        self.mock_client.command.side_effect = [
            _ok([AGENT2, AGENT], total=2),
            _ok([{"id": AGENT}, {"id": AGENT2}]),
        ]
        result = self._search(protection_type="Seraphic Workspace")
        first, second = self.mock_client.command.call_args_list
        self.assertEqual(first.args[0], "QueryAgents")
        self.assertEqual(first.kwargs["body"]["filter"], {"protection_type": ["Seraphic Workspace"]})
        self.assertEqual(second.args[0], "GetAgents")
        self.assertEqual(second.kwargs["parameters"], {"ids": [AGENT2, AGENT]})
        self.assertEqual([a["id"] for a in result["results"]], [AGENT2, AGENT])
        self.assertEqual(result["pagination"]["total"], 2)

    def test_search_agents_rejects_bad_timestamp_and_host_id(self):
        result = self._search(first_seen_before="yesterday")
        self.assertIn("ISO 8601", result["error"])
        result = self._search(first_seen_after="2026-11-01")
        self.assertIn("ISO 8601", result["error"])
        result = self._search(host_id="a" * 32)
        self.assertIn("64-character", result["error"])
        result = self._search(hostname="a\nb")
        self.assertIn("control characters", result["error"])
        self.mock_client.command.assert_not_called()

    def test_search_agents_passes_api_errors(self):
        self.mock_client.command.return_value = _bad("limit must not be greater than 2500")
        result = self._search()
        self.assertIn("limit must not be greater than 2500", result["error"])

    # --- get agents ------------------------------------------------------------

    def test_get_agents_reports_not_found(self):
        self.mock_client.command.return_value = _ok(
            [{"id": AGENT}], errors=[{"message": f"Agent {AGENT2} not found"}]
        )
        result = self.module.get_browser_agents(ids=[AGENT, AGENT2.upper(), AGENT])
        self.assertEqual(
            self.mock_client.command.call_args.kwargs["parameters"], {"ids": [AGENT, AGENT2.upper()]}
        )
        self.assertEqual(result["found"], [{"id": AGENT}])
        self.assertEqual(result["not_found"], [AGENT2.upper()])

    def test_get_agents_validates_ids(self):
        result = self.module.get_browser_agents(ids=["not-a-uuid"])
        self.assertIn("Invalid agent ID", result["error"])
        result = self.module.get_browser_agents(ids=[])
        self.assertIn("at least one", result["error"])
        self.mock_client.command.assert_not_called()

    # --- rules -----------------------------------------------------------------

    def test_search_rules_queries_category_and_fetches_in_batches(self):
        ids = list(range(1, 151))
        self.mock_client.command.side_effect = [
            _ok(ids, total=150),
            _ok([{"id": i} for i in ids[:100]]),
            _ok([{"id": i} for i in ids[100:]]),
        ]
        result = self.module.search_browser_rules(category="dlp", search=" upload ", limit=200)
        query, first, second = self.mock_client.command.call_args_list
        self.assertEqual(query.args[0], "QueryRulesMixin0")
        self.assertEqual(query.kwargs["parameters"], {"category": "dlp"})
        self.assertEqual(query.kwargs["body"], {"limit": 200, "search": "upload"})
        self.assertEqual(first.kwargs["parameters"]["ids"], [str(i) for i in ids[:100]])
        self.assertEqual(second.kwargs["parameters"]["ids"], [str(i) for i in ids[100:]])
        self.assertEqual(len(result["results"]), 150)
        self.assertEqual(result["pagination"]["total"], 150)

    def test_search_rules_with_no_matches_skips_get(self):
        self.mock_client.command.return_value = _ok([], total=0)
        result = self.module.search_browser_rules(category="privacy", search=None, limit=100)
        self.assertEqual(self.mock_client.command.call_count, 1)
        self.assertEqual(result["results"], [])

    def test_get_rules_reports_not_found(self):
        self.mock_client.command.return_value = _ok(
            [{"id": 7}], errors=[{"message": "999: Rule not found"}]
        )
        result = self.module.get_browser_rules(ids=["7", 999])
        self.assertEqual(self.mock_client.command.call_args.kwargs["parameters"], {"ids": ["7", "999"]})
        self.assertEqual(result["found"], [{"id": 7}])
        self.assertEqual(result["not_found"], ["999"])

    def test_get_rules_validates_ids(self):
        result = self.module.get_browser_rules(ids=["abc"])
        self.assertIn("Invalid rule ID", result["error"])
        self.mock_client.command.assert_not_called()

    # --- extension analysis ----------------------------------------------------

    def test_extension_analysis_is_trimmed(self):
        record = {
            "id": "a" * 32,
            "name": "Example",
            "store": "google",
            "version": "1.0",
            "usersCount": 1000,
            "establishedPublisher": True,
            "description": "d" * 2000,
            "risk_score": {"score": 18, "description": "Low risk."},
            "permissions": ["storage", "tabs"],
            "manifest": {
                "manifest_version": 3,
                "host_permissions": ["<all_urls>"],
                "content_scripts": [{"matches": ["https://*/*"]}, {"matches": ["https://*/*"]}],
                "icons": {"16": "x"},
            },
            "analysisSummary": {
                "containsObfuscatedCode": False,
                "invokedNativeAPIs": ["eval"],
                "vulnerabilities": [],
                "functionsNames": ["f"] * 5000,
                "data": {"urls": ["https://example.com"] * 3000, "emails": ["x@example.com"], "ips": []},
            },
            "analysisResults": {
                "retireJS": [],
                "intel": [
                    {"file": "a.js", "results": {"apiKeys": ["k"], "jwt": []}},
                    {"file": "b.js", "results": {"apiKeys": ["k"], "jwt": ["t"]}},
                ],
                "code": [{"file": "a.js", "results": {"obfuscationTypes": ["hex"]}}],
                "suspicious_domains": [
                    {
                        "domain": "example.net",
                        "classifications": ["Ads"],
                        "isMalicious": False,
                        "isTrusted": True,
                        "typosquatting": {"isTyposquatting": False, "similarDomains": []},
                        "info": {"isIP": False},
                        "source": "code",
                    }
                ],
            },
            "history": [{"id": "a" * 32, "version": str(i), "risk_score": 18} for i in range(30)],
        }
        self.mock_client.command.return_value = _ok([record])
        result = self.module.get_browser_extension_analysis(store="google", extension_id=" " + "a" * 32)
        self.assertEqual(
            self.mock_client.command.call_args.kwargs["parameters"], {"store": "google", "id": "a" * 32}
        )
        self.assertEqual(result["risk_score"]["score"], 18)
        self.assertEqual(len(result["description"]), 500)
        self.assertEqual(result["manifest"]["content_script_matches"], ["https://*/*"])
        self.assertNotIn("icons", result["manifest"])
        self.assertEqual(result["code_analysis"]["indicator_counts"]["urls"], 3000)
        self.assertNotIn("functionsNames", json.dumps(result))
        self.assertEqual(result["findings"]["files_with_secrets"], {"apiKeys": 2, "jwt": 1})
        self.assertEqual(result["findings"]["obfuscation_types"], ["hex"])
        self.assertEqual(result["findings"]["suspicious_domains"][0]["domain"], "example.net")
        self.assertNotIn("info", result["findings"]["suspicious_domains"][0])
        self.assertEqual(len(result["risk_history"]), 20)
        self.assertLess(len(json.dumps(result)), 5000)

    def test_extension_analysis_not_ready(self):
        self.mock_client.command.return_value = _ok(
            [{"status": "started analysis", "message": "Analysis has started.", "id": "x", "runningAt": "t"}]
        )
        result = self.module.get_browser_extension_analysis(store="apple", extension_id="12345")
        self.assertEqual(result["analysis_status"], "started analysis")
        self.assertIn("again", result["hint"])

    def test_extension_analysis_not_in_store(self):
        self.mock_client.command.return_value = _ok(
            [{"failureReason": "EXTENSION_NOT_IN_STORE", "id": "x", "analysisSummary": {}, "history": []}]
        )
        result = self.module.get_browser_extension_analysis(store="google", extension_id="x" * 32)
        self.assertEqual(result["failure_reason"], "EXTENSION_NOT_IN_STORE")

    def test_extension_analysis_validates_id(self):
        result = self.module.get_browser_extension_analysis(store="google", extension_id="a b")
        self.assertIn("Invalid extension_id", result["error"])
        self.mock_client.command.assert_not_called()

    # --- tenant settings -------------------------------------------------------

    def test_tenant_settings_reports_logo_presence_only(self):
        self.mock_client.command.return_value = _ok(
            [{"id": 1, "logo": "data:image/png;base64,AAAA", "small_logo": None, "session_timeout": 30}]
        )
        result = self.module.get_browser_tenant_settings()
        self.assertEqual(self.mock_client.command.call_args.args, ("GetTenantSettings",))
        self.assertEqual(result, {"id": 1, "logo": True, "small_logo": False, "session_timeout": 30})

    # --- writes ----------------------------------------------------------------

    def test_activate_and_deactivate_send_ids(self):
        self.mock_client.command.return_value = _ok([])
        for method, operation in (
            (self.module.activate_browser_agents, "ActivateAgents"),
            (self.module.deactivate_browser_agents, "DeactivateAgents"),
        ):
            with self.subTest(operation=operation):
                method(ids=[AGENT, AGENT])
                self.assertEqual(self.mock_client.command.call_args.args, (operation,))
                self.assertEqual(self.mock_client.command.call_args.kwargs, {"body": {"ids": [AGENT]}})

    def test_activation_validates_ids(self):
        result = self.module.deactivate_browser_agents(ids=["x"])
        self.assertIn("Invalid agent ID", result["error"])
        result = self.module.activate_browser_agents(ids=[AGENT] * 1 + [f"{i:08x}-0000-4000-8000-000000000000" for i in range(100)])
        self.assertIn("At most 100", result["error"])
        self.mock_client.command.assert_not_called()

    def test_run_tasks_builds_body(self):
        self.mock_client.command.return_value = {"status_code": 202, "body": {"resources": [], "errors": []}}
        self.module.run_browser_agent_tasks(
            agent_id=AGENT, actions=["remove_browsing_data", "close_all_windows", "remove_browsing_data"], ttl_hours=24
        )
        self.assertEqual(self.mock_client.command.call_args.args, ("ApplyAgentTasks",))
        self.assertEqual(
            self.mock_client.command.call_args.kwargs,
            {
                "parameters": {"agent_id": AGENT},
                "body": {
                    "actions": [
                        {"action": "remove_browsing_data", "args": []},
                        {"action": "close_all_windows", "args": []},
                    ],
                    "ttlHours": 24,
                },
            },
        )

    def test_run_tasks_validates_input(self):
        result = self.module.run_browser_agent_tasks(agent_id="x", actions=["close_all_windows"], ttl_hours=72)
        self.assertIn("Invalid agent ID", result["error"])
        result = self.module.run_browser_agent_tasks(agent_id=AGENT, actions=["dispatch_notification"], ttl_hours=72)
        self.assertIn("Unsupported task", result["error"])
        result = self.module.run_browser_agent_tasks(agent_id=AGENT, actions=[], ttl_hours=72)
        self.assertIn("at least one task", result["error"])
        self.mock_client.command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
