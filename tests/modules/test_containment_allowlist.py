"""
Tests for the network containment allowlist tools in the hosts module.
"""

import unittest

from mcp.types import ToolAnnotations

from falcon_mcp.modules.hosts import HostsModule, _allowlist_rule_problem
from tests.modules.utils.test_modules import TestModules

DNS = {"id": "containment|dns|10.0.0.53", "context": "containment", "type": "ip_dns", "rule": "10.0.0.53", "label": "DNS"}
NET = {"id": "containment|10.20.0.0/16", "context": "containment", "type": "ip_range", "rule": "10.20.0.0/16", "label": "Net"}
SITE = {
    "id": "containment|updates.example.com",
    "context": "containment",
    "type": "fqdn",
    "rule": "updates.example.com",
    "label": "Patches",
    "options": {"allow_subdomain": True},
}


def _ok(resources, status=200):
    return {"status_code": status, "body": {"resources": resources, "errors": []}}


class TestContainmentAllowlist(TestModules):
    def setUp(self):
        self.setup_module(HostsModule)

    def _existing(self, rules):
        """Route the list calls to `rules`; record every other call."""
        self.writes = []

        def route(op, **kwargs):
            if op == "QueryContainmentAllowlistRules":
                return _ok([r["id"] for r in rules])
            if op == "GetContainmentAllowlistRules":
                wanted = kwargs["parameters"]["ids"]
                return _ok([r for r in rules if r["id"] in wanted])
            self.writes.append((op, kwargs))
            return _ok([{"id": "new"}])

        self.mock_client.command.side_effect = route

    def test_annotations(self):
        self.module.register_tools(self.mock_server)
        for name, destructive in (
            ("falcon_create_containment_allowlist_rules", False),
            ("falcon_update_containment_allowlist_labels", False),
            ("falcon_delete_containment_allowlist_rules", True),
        ):
            with self.subTest(tool=name):
                self.assert_tool_annotations(
                    name,
                    ToolAnnotations(
                        readOnlyHint=False,
                        destructiveHint=destructive,
                        idempotentHint=True,
                        openWorldHint=True,
                    ),
                )

    def test_rule_checks(self):
        valid = [("ip_range", "10.20.0.0/16"), ("ip_range", "2001:db8::/32"), ("ip_range", "10.0.0.5"),
                 ("ip_dns", "10.0.0.53"), ("fqdn", "updates.example.com")]
        for rule_type, value in valid:
            with self.subTest(rule=value):
                self.assertIsNone(_allowlist_rule_problem(rule_type, value, False))
        invalid = [("ip_range", "10.0.0.0/33", False), ("ip_dns", "10.0.0.0/24", False),
                   ("fqdn", "not a domain", False), ("fqdn", "localhost", False),
                   ("ip_range", "10.0.0.1", True), ("ipv4", "10.0.0.1", False)]
        for rule_type, value, subdomains in invalid:
            with self.subTest(rule=value, type=rule_type):
                self.assertIsNotNone(_allowlist_rule_problem(rule_type, value, subdomains))

    def test_search_filters_by_type_and_counts(self):
        self._existing([SITE, NET, DNS])

        result = self.module.search_containment_allowlist(rule_type="ip_range")

        query = self.mock_client.command.call_args_list[0]
        self.assertEqual(query[1]["parameters"], {"filter": "context:'containment'"})
        self.assertEqual([r["rule"] for r in result["results"]], ["10.20.0.0/16"])
        self.assertEqual(result["counts"], {"ip_range": 1, "ip_dns": 1, "fqdn": 1})

    def test_search_with_no_rules(self):
        self._existing([])
        result = self.module.search_containment_allowlist(rule_type=None)
        self.assertEqual(result["results"], [])
        self.assertEqual(self.mock_client.command.call_count, 1)

    def test_create_sends_dns_first_and_skips_existing(self):
        self._existing([NET])

        result = self.module.create_containment_allowlist_rules(
            rules=[
                {"type": "fqdn", "rule": "updates.example.com", "label": "Patches", "allow_subdomains": True},
                {"type": "ip_dns", "rule": "10.0.0.53", "label": "DNS"},
                {"type": "ip_range", "rule": "10.20.0.0/16", "label": "Net again"},
            ]
        )

        self.assertEqual(len(self.writes), 1)
        op, kwargs = self.writes[0]
        self.assertEqual(op, "CreateContainmentAllowlistRules")
        self.assertEqual(
            kwargs["body"]["rules"],
            [
                {"context": "containment", "type": "ip_dns", "rule": "10.0.0.53", "label": "DNS"},
                {
                    "context": "containment",
                    "type": "fqdn",
                    "rule": "updates.example.com",
                    "label": "Patches",
                    "options": {"allow_subdomain": True},
                },
            ],
        )
        self.assertEqual([r["rule"] for r in result["already_present"]], ["10.20.0.0/16"])

    def test_create_fqdn_without_dns_is_refused(self):
        self._existing([NET])
        result = self.module.create_containment_allowlist_rules(
            rules=[{"type": "fqdn", "rule": "updates.example.com", "label": "Patches"}]
        )
        self.assertIn("ip_dns", result["error"])
        self.assertEqual(self.writes, [])

    def test_create_only_existing_rules_writes_nothing(self):
        self._existing([NET])
        result = self.module.create_containment_allowlist_rules(
            rules=[{"type": "ip_range", "rule": "10.20.0.0/16", "label": "Net"}]
        )
        self.assertEqual(result["added"], [])
        self.assertEqual(self.writes, [])

    def test_create_input_checks(self):
        cases = [
            [],
            [{"type": "ip_range", "rule": "nope", "label": "x"}],
            [{"type": "ip_range", "rule": "10.0.0.1", "label": ""}],
            [{"type": "ip_range", "rule": "10.0.0.1", "label": "a\nb"}],
            ["not an object"],
            [{"type": "ip_range", "rule": "10.0.0.1", "label": "x"}] * 51,
        ]
        for index, rules in enumerate(cases):
            with self.subTest(case=index):
                self.mock_client.command.reset_mock()
                self.assertIn("error", self.module.create_containment_allowlist_rules(rules=rules))
                self.mock_client.command.assert_not_called()

    def test_update_sends_the_full_rule_with_the_new_label(self):
        self._existing([SITE, DNS])

        self.module.update_containment_allowlist_labels(
            updates=[{"id": SITE["id"], "label": " Patch server "}]
        )

        op, kwargs = self.writes[0]
        self.assertEqual(op, "UpdateContainmentAllowlistRules")
        self.assertEqual(
            kwargs["body"]["rules"],
            [
                {
                    "id": SITE["id"],
                    "context": "containment",
                    "type": "fqdn",
                    "rule": "updates.example.com",
                    "options": {"allow_subdomain": True},
                    "label": "Patch server",
                }
            ],
        )

    def test_update_unknown_id(self):
        self._existing([DNS])
        result = self.module.update_containment_allowlist_labels(updates=[{"id": "nope", "label": "x"}])
        self.assertIn("no allowlist rule", result["error"])
        self.assertEqual(self.writes, [])

    def test_delete_one_call_per_id(self):
        self._existing([NET, DNS])

        result = self.module.delete_containment_allowlist_rules(ids=[NET["id"], DNS["id"]])

        self.assertEqual(
            [w[1]["parameters"] for w in self.writes],
            [{"ids": NET["id"]}, {"ids": DNS["id"]}],
        )
        self.assertEqual(result["deleted"], [NET["id"], DNS["id"]])

    def test_delete_last_dns_while_domains_remain_is_refused(self):
        self._existing([DNS, SITE])
        result = self.module.delete_containment_allowlist_rules(ids=[DNS["id"]])
        self.assertIn("last DNS", result["error"])
        self.assertEqual(self.writes, [])

    def test_delete_dns_with_its_domains_is_allowed(self):
        self._existing([DNS, SITE])
        result = self.module.delete_containment_allowlist_rules(ids=[DNS["id"], SITE["id"]])
        self.assertEqual(len(result["deleted"]), 2)

    def test_delete_unknown_id_and_failures(self):
        self._existing([NET])
        result = self.module.delete_containment_allowlist_rules(ids=["nope"])
        self.assertIn("No allowlist rule", result["error"])
        self.assertEqual(self.writes, [])

        def route(op, **kwargs):
            if op == "QueryContainmentAllowlistRules":
                return _ok([NET["id"]])
            if op == "GetContainmentAllowlistRules":
                return _ok([NET])
            return {"status_code": 403, "body": {"errors": [{"message": "access denied"}]}}

        self.mock_client.command.side_effect = route
        result = self.module.delete_containment_allowlist_rules(ids=[NET["id"]])
        self.assertEqual(result["deleted"], [])
        self.assertEqual(result["failed"][0]["error"]["required_scopes"], ["Network Containment Allowlist:write"])


if __name__ == "__main__":
    unittest.main()
