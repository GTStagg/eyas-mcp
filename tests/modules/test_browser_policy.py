"""
Tests for the Browser module's destination group, sensitive data profile and rule write tools.
"""

import unittest

from falcon_mcp.modules.browser import BrowserModule
from tests.modules.utils.test_modules import TestModules

GROUP = "3f2a9c4e-8b1d-4e6f-9a2b-7c5d0e1f2a3b"
PROFILE = "4a3b0d5f-9c2e-4f70-8b3c-8d6e1f2a3b4c"


def _ok(resources, total=None, errors=None, status=200):
    body = {"resources": resources, "errors": errors or []}
    if total is not None:
        body["meta"] = {"pagination": {"offset": 0, "limit": 20, "total": total}}
    return {"status_code": status, "body": body}


def _bad(message, status=400):
    return {"status_code": status, "body": {"resources": [], "errors": [{"message": message}]}}


def _group(**overrides):
    group = {
        "id": GROUP,
        "name": "Approved AI tools",
        "default": False,
        "domains": ["a.example.com", "*.b.example.com"],
        "singleIps": ["198.51.100.0/24"],
        "countries": [],
        "classification": [],
        "linked_rules": 0,
    }
    group.update(overrides)
    return group


def _profile(regexes=None, related=None):
    return {
        "sensitive_data_profile": {
            "id": PROFILE,
            "name": "Internal IDs",
            "custom_regex": regexes if regexes is not None else [{"name": "emp", "regex": "E\\d{6}", "threshold": 1}],
            "predefined_piis": [],
        },
        "related_rules": related or [],
    }


SEARCH = {
    "name": None,
    "description": None,
    "created_by": None,
    "search": None,
    "sort_by": "name",
    "sort_order": "asc",
    "limit": 100,
    "offset": 0,
}

GROUP_UPDATE = {
    "name": None,
    "description": None,
    "add_domains": None,
    "remove_domains": None,
    "add_single_ips": None,
    "remove_single_ips": None,
    "add_countries": None,
    "remove_countries": None,
    "add_classifications": None,
    "remove_classifications": None,
}


class TestBrowserPolicyTools(TestModules):
    """Destination groups, sensitive data profiles and rule writes."""

    def setUp(self):
        self.setup_module(BrowserModule)

    # --- reads -----------------------------------------------------------------

    def test_search_groups_builds_body_and_drops_null_ids(self):
        self.mock_client.command.side_effect = [
            _ok([GROUP, None], total=1),
            _ok([_group()]),
        ]
        result = self.module.search_browser_destination_groups(
            **{**SEARCH, "name": " AI ", "created_by": "Seraphic", "sort_by": "linked_rules", "sort_order": "desc"}
        )
        query, get = self.mock_client.command.call_args_list
        self.assertEqual(query.args[0], "QueryDestinationGroups")
        self.assertEqual(
            query.kwargs["body"],
            {
                "limit": 100,
                "skip": 0,
                "sort": [{"field": "linked_rules", "order": "DESC"}],
                "filter": {"name": ["AI"], "created_by": ["Seraphic"]},
            },
        )
        self.assertEqual(get.args[0], "GetDestinationGroups")
        self.assertEqual(get.kwargs["parameters"], {"ids": [GROUP]})
        self.assertEqual(result["results"][0]["id"], GROUP)
        self.assertEqual(result["pagination"]["total"], 1)

    def test_search_profiles_flattens_records(self):
        self.mock_client.command.side_effect = [
            _ok([PROFILE], total=1),
            _ok([_profile(related=[{"id": 7, "name": "dlp"}])]),
        ]
        result = self.module.search_browser_data_profiles(**{**SEARCH, "search": "ids"})
        self.assertEqual(self.mock_client.command.call_args_list[0].args[0], "QuerySensitiveDataProfiles")
        record = result["results"][0]
        self.assertEqual(record["id"], PROFILE)
        self.assertEqual(record["related_rules"], [{"id": 7, "name": "dlp"}])
        self.assertNotIn("sensitive_data_profile", record)

    def test_get_profiles_flattens_and_reports_not_found(self):
        other = "5b4c1e60-0d3f-4081-9c4d-9e7f2a3b4c5d"
        self.mock_client.command.return_value = _ok(
            [_profile()], errors=[{"message": f"{other}: Sensitive data profile not found"}]
        )
        result = self.module.get_browser_data_profiles(ids=[PROFILE, other])
        self.assertEqual(result["found"][0]["id"], PROFILE)
        self.assertEqual(result["not_found"], [other])

    def test_get_groups_validates_ids(self):
        result = self.module.get_browser_destination_groups(ids=["x"])
        self.assertIn("Invalid destination group ID", result["error"])
        self.mock_client.command.assert_not_called()

    # --- destination group writes ---------------------------------------------

    def test_create_group_body(self):
        self.mock_client.command.return_value = _ok([_group()])
        self.module.create_browser_destination_group(
            name=" Vendors ",
            description="File-sharing vendors",
            domains=["files.example.com", "*.cdn.example.com", "files.example.com", "https://app.example.com/share*"],
            single_ips=["203.0.113.7", "198.51.100.0/24"],
            countries=["cn"],
            classifications=["File Sharing"],
        )
        self.assertEqual(self.mock_client.command.call_args.args, ("CreateDestinationGroup",))
        self.assertEqual(
            self.mock_client.command.call_args.kwargs["body"],
            {
                "name": "Vendors",
                "description": "File-sharing vendors",
                "domains": ["files.example.com", "*.cdn.example.com", "https://app.example.com/share*"],
                "singleIps": ["203.0.113.7", "198.51.100.0/24"],
                "countries": ["CN"],
                "classification": ["File Sharing"],
            },
        )

    def test_create_group_validates(self):
        for kwargs, message in (
            ({"domains": ["not a domain"]}, "Invalid entry in domains"),
            ({"domains": ["nodot"]}, "Invalid entry in domains"),
            ({"single_ips": ["300.1.1.1"]}, "Invalid entry in single_ips"),
            ({"countries": ["CHN"]}, "Invalid entry in countries"),
            ({}, "at least one of"),
        ):
            with self.subTest(kwargs=kwargs):
                args = {"name": "x", "description": None, "domains": None, "single_ips": None,
                        "countries": None, "classifications": None, **kwargs}
                result = self.module.create_browser_destination_group(**args)
                self.assertIn(message, result["error"])
        self.mock_client.command.assert_not_called()

    def test_update_group_merges_additions_and_removals(self):
        self.mock_client.command.side_effect = [_ok([_group()]), _ok([_group()])]
        self.module.update_browser_destination_group(
            id=GROUP,
            **{**GROUP_UPDATE, "add_domains": ["c.example.com", "A.example.com"], "remove_domains": ["a.example.com"],
               "remove_single_ips": ["198.51.100.0/24"]},
        )
        get, patch = self.mock_client.command.call_args_list
        self.assertEqual(get.args[0], "GetDestinationGroups")
        self.assertEqual(patch.args[0], "UpdateDestinationGroup")
        self.assertEqual(patch.kwargs["parameters"], {"id": GROUP})
        self.assertEqual(
            patch.kwargs["body"],
            {"domains": ["*.b.example.com", "c.example.com", "A.example.com"], "singleIps": []},
        )

    def test_update_group_with_no_effect_sends_nothing(self):
        self.mock_client.command.return_value = _ok([_group()])
        result = self.module.update_browser_destination_group(
            id=GROUP, **{**GROUP_UPDATE, "add_domains": ["a.example.com"]}
        )
        self.assertFalse(result["changed"])
        self.assertEqual(self.mock_client.command.call_count, 1)

    def test_update_group_refuses_builtin_and_missing(self):
        self.mock_client.command.return_value = _ok([_group(default=True)])
        result = self.module.update_browser_destination_group(id=GROUP, **{**GROUP_UPDATE, "name": "x"})
        self.assertIn("built-in", result["error"])
        self.mock_client.command.return_value = _ok([], errors=[{"message": "not found"}])
        result = self.module.update_browser_destination_group(id=GROUP, **{**GROUP_UPDATE, "name": "x"})
        self.assertIn("No destination group", result["error"])

    def test_update_group_needs_a_change(self):
        result = self.module.update_browser_destination_group(id=GROUP, **GROUP_UPDATE)
        self.assertIn("Give a new name", result["error"])
        self.mock_client.command.assert_not_called()

    def test_delete_group_checks_before_deleting(self):
        self.mock_client.command.return_value = _ok([_group(linked_rules=3)])
        result = self.module.delete_browser_destination_group(id=GROUP)
        self.assertIn("3 rule(s) still use", result["error"])
        self.mock_client.command.return_value = _ok([_group(default=True)])
        result = self.module.delete_browser_destination_group(id=GROUP)
        self.assertIn("built-in", result["error"])
        self.assertEqual(self.mock_client.command.call_count, 2)

        self.mock_client.command.reset_mock()
        self.mock_client.command.side_effect = [_ok([_group()]), _ok([])]
        self.module.delete_browser_destination_group(id=GROUP)
        delete = self.mock_client.command.call_args_list[1]
        self.assertEqual(delete.args, ("DeleteDestinationGroup",))
        self.assertEqual(delete.kwargs, {"parameters": {"id": GROUP}})

    # --- sensitive data profile writes ----------------------------------------

    def test_create_profile_body_and_validation(self):
        self.mock_client.command.return_value = _ok([])
        self.module.create_browser_data_profile(
            name="Internal IDs",
            custom_regex=[{"name": "emp", "regex": "E\\d{6}"}, {"name": "proj", "regex": "P-[0-9]+", "threshold": 3}],
            description=None,
            apply_exact_match=True,
        )
        self.assertEqual(self.mock_client.command.call_args.args, ("CreateSensitiveDataProfile",))
        self.assertEqual(
            self.mock_client.command.call_args.kwargs["body"],
            {
                "name": "Internal IDs",
                "custom_regex": [
                    {"name": "emp", "regex": "E\\d{6}", "threshold": 1},
                    {"name": "proj", "regex": "P-[0-9]+", "threshold": 3},
                ],
                "apply_exact_match": True,
            },
        )
        self.mock_client.command.reset_mock()
        for regexes, message in (
            ([{"name": "bad", "regex": "("}], "doesn't compile"),
            ([{"name": "t", "regex": "x", "threshold": 0}], "threshold"),
            ([], "at least one"),
        ):
            with self.subTest(regexes=regexes):
                result = self.module.create_browser_data_profile(
                    name="ok", custom_regex=regexes, description=None, apply_exact_match=None
                )
                self.assertIn(message, result["error"])
        result = self.module.create_browser_data_profile(
            name="x", custom_regex=[{"name": "a", "regex": "a"}], description=None, apply_exact_match=None
        )
        self.assertIn("2-200", result["error"])
        self.mock_client.command.assert_not_called()

    def test_update_profile_replaces_and_removes_by_name(self):
        current = [
            {"name": "emp", "regex": "E\\d{6}", "threshold": 1},
            {"name": "old", "regex": "O\\d+", "threshold": 2},
        ]
        self.mock_client.command.side_effect = [_ok([_profile(current)]), _ok([])]
        self.module.update_browser_data_profile(
            id=PROFILE,
            name=None,
            description=None,
            add_custom_regex=[{"name": "emp", "regex": "E\\d{7}"}, {"name": "new", "regex": "N\\d+"}],
            remove_custom_regex=["old"],
            apply_exact_match=None,
        )
        get, patch = self.mock_client.command.call_args_list
        self.assertEqual(get.args[0], "GetSensitiveDataProfiles")
        self.assertEqual(patch.args[0], "UpdateSensitiveDataProfile")
        self.assertEqual(
            patch.kwargs["body"],
            {"custom_regex": [{"name": "emp", "regex": "E\\d{7}", "threshold": 1},
                              {"name": "new", "regex": "N\\d+", "threshold": 1}]},
        )

    def test_update_profile_rejects_unknown_names_and_empty_result(self):
        self.mock_client.command.return_value = _ok([_profile()])
        result = self.module.update_browser_data_profile(
            id=PROFILE, name=None, description=None, add_custom_regex=None,
            remove_custom_regex=["missing"], apply_exact_match=None,
        )
        self.assertIn("no custom regex named", result["error"])
        result = self.module.update_browser_data_profile(
            id=PROFILE, name=None, description=None, add_custom_regex=None,
            remove_custom_regex=["emp"], apply_exact_match=None,
        )
        self.assertIn("nothing to detect", result["error"])

    def test_update_profile_rename_only_skips_the_read(self):
        self.mock_client.command.return_value = _ok([])
        self.module.update_browser_data_profile(
            id=PROFILE, name="Renamed", description=None, add_custom_regex=None,
            remove_custom_regex=None, apply_exact_match=False,
        )
        self.assertEqual(self.mock_client.command.call_count, 1)
        self.assertEqual(
            self.mock_client.command.call_args.kwargs["body"], {"name": "Renamed", "apply_exact_match": False}
        )

    def test_delete_profile_refuses_one_in_use(self):
        self.mock_client.command.return_value = _ok([_profile(related=[{"id": 1, "displayName": "Block uploads"}])])
        result = self.module.delete_browser_data_profile(id=PROFILE)
        self.assertIn("Block uploads", result["error"])
        self.assertEqual(self.mock_client.command.call_count, 1)

        self.mock_client.command.reset_mock()
        self.mock_client.command.side_effect = [_ok([_profile()]), _ok([])]
        self.module.delete_browser_data_profile(id=PROFILE)
        self.assertEqual(self.mock_client.command.call_args.args, ("DeleteSensitiveDataProfile",))
        self.assertEqual(self.mock_client.command.call_args.kwargs, {"parameters": {"id": PROFILE}})

    # --- rule writes -----------------------------------------------------------

    def test_set_rule_status(self):
        self.mock_client.command.return_value = _ok([{"id": 7, "status": "inactive"}])
        result = self.module.set_browser_rule_status(id="7", status="inactive")
        self.assertFalse(result["changed"])
        self.assertEqual(self.mock_client.command.call_count, 1)

        self.mock_client.command.reset_mock()
        self.mock_client.command.side_effect = [_ok([{"id": 7, "status": "inactive"}]), _ok([])]
        self.module.set_browser_rule_status(id="7", status="active")
        patch = self.mock_client.command.call_args
        self.assertEqual(patch.args, ("UpdateRuleMixin0",))
        self.assertEqual(patch.kwargs, {"parameters": {"id": "7"}, "body": {"status": "active"}})

    def test_rule_extensions_send_one_call_per_kind(self):
        self.mock_client.command.side_effect = [
            _ok([{"id": 9, "category": "extensions"}]),
            _ok([]),
            _ok([]),
        ]
        result = self.module.update_browser_rule_extensions(
            id="9",
            add_extension_ids=["a" * 32],
            remove_extension_ids=None,
            add_extension_names=None,
            remove_extension_names=["Old Tool"],
        )
        _, first, second = self.mock_client.command.call_args_list
        self.assertEqual(first.kwargs["body"], {"addExtensionIds": ["a" * 32]})
        self.assertEqual(second.kwargs["body"], {"removeExtensionNames": ["Old Tool"]})
        self.assertEqual(result["applied"], ["add_extension_ids", "remove_extension_names"])

    def test_rule_extensions_stop_at_first_failure(self):
        self.mock_client.command.side_effect = [
            _ok([{"id": 9, "category": "extensions"}]),
            _ok([]),
            _bad("bad extension"),
        ]
        result = self.module.update_browser_rule_extensions(
            id="9",
            add_extension_ids=["a" * 32],
            remove_extension_ids=["b" * 32],
            add_extension_names=["New"],
            remove_extension_names=None,
        )
        self.assertIn("bad extension", result["error"])
        self.assertEqual(result["applied"], ["add_extension_ids"])
        self.assertEqual(result["not_applied"], ["remove_extension_ids", "add_extension_names"])
        self.assertEqual(self.mock_client.command.call_count, 3)

    def test_rule_extensions_need_an_extensions_rule(self):
        self.mock_client.command.return_value = _ok([{"id": 9, "category": "dlp"}])
        result = self.module.update_browser_rule_extensions(
            id="9", add_extension_ids=["a" * 32], remove_extension_ids=None,
            add_extension_names=None, remove_extension_names=None,
        )
        self.assertIn("extensions category", result["error"])
        self.assertEqual(self.mock_client.command.call_count, 1)

    def test_rule_writes_validate_ids(self):
        result = self.module.set_browser_rule_status(id="abc", status="active")
        self.assertIn("Invalid rule ID", result["error"])
        result = self.module.update_browser_rule_extensions(
            id="9", add_extension_ids=["bad id"], remove_extension_ids=None,
            add_extension_names=None, remove_extension_names=None,
        )
        self.assertIn("Invalid entry", result["error"])
        self.mock_client.command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
