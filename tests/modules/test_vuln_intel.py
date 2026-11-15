"""
Tests for installed patches (Spotlight) and CVE intel, malware families and rule sets (Intel).
"""

import unittest

from falcon_mcp.modules.intel import IntelModule, _trim_cve, _trim_malware
from falcon_mcp.modules.spotlight import SpotlightModule
from tests.modules.utils.test_modules import TestModules


def _ok(resources, total=None, after=None):
    body = {"resources": resources, "errors": []}
    if total is not None or after is not None:
        body["meta"] = {"pagination": {"offset": 0, "limit": 10, "total": total, "after": after}}
    return {"status_code": 200, "body": body}


class TestInstalledPatches(TestModules):
    def setUp(self):
        self.setup_module(SpotlightModule)

    def test_installed_patches(self):
        self.mock_client.command.return_value = _ok(
            [{"aid": "a", "reboot_required": True, "installed_patches": [{"id": "KB1", "status": "Installed"}]}],
            total=106,
            after="cursor",
        )

        result = self.module.get_installed_patches(
            filter="reboot_required:true", limit=20, after=None, sort="hostname|asc"
        )

        call = self.mock_client.command.call_args
        self.assertEqual(call[0][0], "combinedQueryInstalledPatches")
        self.assertEqual(call[1]["parameters"]["filter"], "reboot_required:true")
        self.assertEqual(result["pagination"]["total"], 106)
        self.assertEqual(result["pagination"]["next"], "cursor")
        self.assertEqual(result["results"][0]["installed_patches"][0]["id"], "KB1")

    def test_bad_filter_returns_the_guide(self):
        self.mock_client.command.return_value = {
            "status_code": 400,
            "body": {"errors": [{"message": "invalid filter"}]},
        }
        result = self.module.get_installed_patches(filter="nope", limit=20, after=None, sort=None)
        self.assertIn("fql_guide", str(result))


class TestIntelAdditions(TestModules):
    def setUp(self):
        self.setup_module(IntelModule)

    def test_cve_search_trims_long_lists(self):
        record = {
            "cve": "CVE-2021-44228",
            "exploit_status": "ActivelyUsed",
            "affected_products": [{"vendor": "v", "product": str(i)} for i in range(92)],
            "related_reports": [{"serial_id": str(i)} for i in range(63)],
        }
        self.mock_client.command.side_effect = [_ok(["CVE-2021-44228"], total=1), _ok([record])]

        result = self.module.search_intel_vulnerabilities(
            filter="cve:'CVE-2021-44228'", q=None, limit=10, offset=None, sort="publish_date|desc"
        )

        query, details = self.mock_client.command.call_args_list
        self.assertEqual(query[0][0], "QueryVulnerabilities")
        self.assertEqual(details[0][0], "GetVulnerabilities")
        self.assertEqual(details[1]["body"], {"ids": ["CVE-2021-44228"]})
        cve = result["results"][0]
        self.assertEqual(len(cve["affected_products"]), 25)
        self.assertEqual(cve["affected_products_total"], 92)
        self.assertEqual(len(cve["related_reports"]), 20)
        self.assertEqual(cve["related_reports_total"], 63)

    def test_trim_leaves_short_lists_alone(self):
        record = {"cve": "x", "affected_products": [{}], "related_reports": []}
        self.assertEqual(_trim_cve(record), record)

    def test_trim_malware(self):
        record = {
            "name": "Emotet",
            "rich_text_description": "<p>x</p>",
            "description": "x",
            "reports": [{"report_id": str(i)} for i in range(200)],
            "mitre": [
                {"attack_id": "TA0002_T1059", "technique_id": "T1059", "technique_name": "Command",
                 "tactic_id": "TA0002", "tactic_name": "Execution", "reports": [{}] * 9},
                {"attack_id": "TA0002_T1059", "technique_id": "T1059", "reports": []},
            ],
        }
        trimmed = _trim_malware(record, 5000)
        self.assertEqual(len(trimmed["reports"]), 10)
        self.assertEqual(trimmed["reports_total"], 200)
        self.assertEqual(
            trimmed["mitre"],
            [{"technique_id": "T1059", "technique_name": "Command", "tactic_id": "TA0002", "tactic_name": "Execution"}],
        )
        self.assertNotIn("rich_text_description", trimmed)

    def test_malware_search(self):
        self.mock_client.command.return_value = _ok([{"id": "Threat:x", "name": "Emotet"}], total=26)
        result = self.module.search_malware_families(
            q="emotet", names=None, limit=10, offset=None, max_text_chars=5000
        )
        call = self.mock_client.command.call_args
        self.assertEqual(call[0][0], "QueryMalwareEntities")
        self.assertEqual(call[1]["parameters"]["q"], "emotet")
        self.assertEqual(result["pagination"]["total"], 26)

    def test_malware_by_exact_names(self):
        self.mock_client.command.return_value = _ok([{"id": "Threat:x", "name": "Emotet"}], total=1)

        result = self.module.search_malware_families(
            q=None, names=["Emotet", "Made Up", "Emotet"], limit=10, offset=None, max_text_chars=5000
        )

        params = self.mock_client.command.call_args[1]["parameters"]
        self.assertEqual(params["filter"], "name:'Emotet',name:'Made Up'")
        self.assertEqual(params["limit"], 2)
        self.assertEqual(result["not_found"], ["Made Up"])
        self.assertIn("q", result["hint"])

    def test_malware_input_checks(self):
        for kwargs in ({"q": None, "names": None}, {"q": None, "names": ["it's"]}):
            with self.subTest(kwargs=kwargs):
                result = self.module.search_malware_families(
                    limit=10, offset=None, max_text_chars=5000, **kwargs
                )
                self.assertIn("error", result[0])
        self.mock_client.command.assert_not_called()

    def test_malware_forbidden_names_the_scope(self):
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied, scope not permitted"}]},
        }
        result = self.module.search_malware_families(
            q="emotet", names=None, limit=10, offset=None, max_text_chars=5000
        )
        self.assertEqual(result[0]["required_scopes"], ["Malware Families (Falcon Intelligence):read"])

    def test_rule_search(self):
        self.mock_client.command.side_effect = [
            _ok([2, 1], total=2),
            _ok(
                [
                    {"id": 1, "name": "b", "description": "d", "rich_text_description": "<p>d</p>"},
                    {"id": 2, "name": "a", "description": "d"},
                ]
            ),
        ]

        result = self.module.search_intel_rules(
            rule_type="yara-master", q="ransomware", tags=None, limit=10, offset=None,
            sort="created_date|desc",
        )

        query = self.mock_client.command.call_args_list[0]
        self.assertEqual(query[0][0], "QueryIntelRuleIds")
        self.assertEqual(query[1]["parameters"]["type"], "yara-master")
        self.assertEqual([r["id"] for r in result["results"]], [2, 1])
        self.assertNotIn("rich_text_description", result["results"][1])


if __name__ == "__main__":
    unittest.main()
