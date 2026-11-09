"""
Tests for the Host Groups module.
"""

import time
import unittest
from unittest.mock import patch

from mcp.types import ToolAnnotations

from falcon_mcp.modules.base import READ_ONLY_ANNOTATIONS
from falcon_mcp.modules.host_groups import HostGroupsModule
from tests.modules.utils.test_modules import TestModules


class TestHostGroupsModule(TestModules):
    """Test cases for the Host Groups module."""

    def setUp(self):
        """Set up test fixtures."""
        self.setup_module(HostGroupsModule)

    def test_register_tools(self):
        """Test registering tools with the server."""
        expected_tools = [
            "falcon_search_host_groups",
            "falcon_search_host_group_members",
            "falcon_get_host_group_membership",
            "falcon_create_host_group",
            "falcon_update_host_group",
            "falcon_delete_host_groups",
            "falcon_perform_host_group_action",
        ]
        self.assert_tools_registered(expected_tools)

    def test_register_resources(self):
        """Test registering resources with the server."""
        expected_resources = [
            "falcon_search_host_groups_fql_guide",
        ]
        self.assert_resources_registered(expected_resources)

    def test_search_host_groups_success(self):
        """Test searching host groups returns full details in a single call."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {
                "meta": {"pagination": {"offset": 0, "limit": 100, "total": 2}},
                "resources": [
                    {
                        "id": "group-1",
                        "name": "Production Servers",
                        "group_type": "static",
                    },
                    {
                        "id": "group-2",
                        "name": "Windows Dynamic",
                        "group_type": "dynamic",
                    },
                ]
            },
        }

        result = self.module.search_host_groups(
            filter="group_type:'static'",
            limit=100,
            offset=0,
            sort="name.asc",
        )

        self.assertEqual(self.mock_client.command.call_count, 1)
        call_args = self.mock_client.command.call_args
        self.assertEqual(call_args[0][0], "queryCombinedHostGroups")
        self.assertEqual(call_args[1]["parameters"]["filter"], "group_type:'static'")
        self.assertEqual(call_args[1]["parameters"]["sort"], "name.asc")

        self.assertIn("results", result)
        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(result["results"][0]["id"], "group-1")
        self.assertEqual(result["pagination"]["total"], 2)

    def test_search_host_groups_empty_results_returns_fql_guide(self):
        """Test host group search empty results return clean empty response."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }

        result = self.module.search_host_groups(filter="name:'nonexistent'")

        self.assertIsInstance(result, dict)
        self.assertEqual(result["results"], [])
        self.assertIsNone(result["pagination"]["total"])
        self.assertEqual(result["filter_used"], "name:'nonexistent'")
        self.assertNotIn("fql_guide", result)

    def test_search_host_groups_error_returns_fql_guide(self):
        """Test host group search errors include FQL guide context."""
        self.mock_client.command.return_value = {
            "status_code": 400,
            "body": {"errors": [{"message": "Invalid filter"}]},
        }

        result = self.module.search_host_groups(filter="bad filter")

        self.assertIsInstance(result, dict)
        self.assertIn("results", result)
        self.assertEqual(len(result["results"]), 1)
        self.assertIn("error", result["results"][0])
        self.assertIn("fql_guide", result)

    def test_search_host_group_members_success(self):
        """Test searching host group members returns full host details."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {
                "meta": {"pagination": {"offset": 0, "limit": 100, "total": 2}},
                "resources": [
                    {"device_id": "device-1", "hostname": "PC-1"},
                    {"device_id": "device-2", "hostname": "PC-2"},
                ]
            },
        }

        result = self.module.search_host_group_members(
            id="group-1",
            filter="platform_name:'Windows'",
            limit=100,
            offset=0,
            sort="hostname.asc",
        )

        self.assertEqual(self.mock_client.command.call_count, 1)
        call_args = self.mock_client.command.call_args
        self.assertEqual(call_args[0][0], "queryCombinedGroupMembers")
        self.assertEqual(call_args[1]["parameters"]["id"], "group-1")
        self.assertEqual(
            call_args[1]["parameters"]["filter"], "platform_name:'Windows'"
        )

        self.assertIn("results", result)
        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(result["results"][0]["device_id"], "device-1")
        self.assertEqual(result["pagination"]["total"], 2)

    def test_search_host_group_members_error(self):
        """Test member search error returns wrapped error."""
        self.mock_client.command.return_value = {
            "status_code": 404,
            "body": {"errors": [{"message": "Group not found"}]},
        }

        result = self.module.search_host_group_members(
            id="bad-group", filter=None, limit=100, offset=None, sort=None
        )

        self.assertEqual(len(result), 1)
        self.assertIn("error", result[0])

    def test_create_host_group_static_success(self):
        """Test creating a static host group."""
        self.mock_client.command.return_value = {
            "status_code": 201,
            "body": {
                "resources": [
                    {"id": "group-1", "name": "Critical Servers", "group_type": "static"}
                ]
            },
        }

        result = self.module.create_host_group(
            name="Critical Servers",
            group_type="static",
            description="Important hosts",
            assignment_rule=None,
        )

        self.mock_client.command.assert_called_once_with(
            "createHostGroups",
            body={
                "resources": [
                    {
                        "name": "Critical Servers",
                        "group_type": "static",
                        "description": "Important hosts",
                    }
                ]
            },
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["id"], "group-1")

    def test_create_host_group_dynamic_with_assignment_rule(self):
        """Test creating a dynamic host group includes assignment_rule."""
        self.mock_client.command.return_value = {
            "status_code": 201,
            "body": {"resources": [{"id": "group-2", "group_type": "dynamic"}]},
        }

        self.module.create_host_group(
            name="Windows Dynamic",
            group_type="dynamic",
            description=None,
            assignment_rule="platform_name:'Windows'",
        )

        call_args = self.mock_client.command.call_args
        resource = call_args[1]["body"]["resources"][0]
        self.assertEqual(resource["assignment_rule"], "platform_name:'Windows'")
        self.assertNotIn("description", resource)

    def test_update_host_group_success(self):
        """Test updating a host group."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"id": "group-1", "name": "Renamed"}]},
        }

        result = self.module.update_host_group(
            id="group-1",
            name="Renamed",
            description=None,
            assignment_rule=None,
        )

        self.mock_client.command.assert_called_once_with(
            "updateHostGroups",
            body={"resources": [{"id": "group-1", "name": "Renamed"}]},
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "Renamed")

    def test_delete_host_groups_success(self):
        """Test deleting host groups sends IDs as query params."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": ["group-1"]},
        }

        result = self.module.delete_host_groups(ids=["group-1", "group-2"])

        self.mock_client.command.assert_called_once_with(
            "deleteHostGroups",
            parameters={"ids": ["group-1", "group-2"]},
        )
        self.assertIsInstance(result, list)

    def test_delete_host_groups_validation_error(self):
        """Test delete_host_groups requires ids."""
        result = self.module.delete_host_groups(ids=[])

        self.assertEqual(len(result), 1)
        self.assertIn("error", result[0])
        self.mock_client.command.assert_not_called()

    def test_perform_host_group_action_add_hosts(self):
        """Test adding hosts to a group sends action_name and body correctly."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"id": "group-1"}]},
        }

        result = self.module.perform_host_group_action(
            action_name="add-hosts",
            ids=["group-1"],
            filter="platform_name:'Windows'",
        )

        self.mock_client.command.assert_called_once_with(
            "performGroupAction",
            parameters={"action_name": "add-hosts"},
            body={
                "ids": ["group-1"],
                "action_parameters": [
                    {"name": "filter", "value": "platform_name:'Windows'"}
                ],
            },
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["id"], "group-1")

    def test_perform_host_group_action_remove_hosts(self):
        """Test removing hosts from a group passes remove-hosts action."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"id": "group-1"}]},
        }

        self.module.perform_host_group_action(
            action_name="remove-hosts",
            ids=["group-1"],
            filter="device_id:['dev-1']",
        )

        call_args = self.mock_client.command.call_args
        self.assertEqual(call_args[1]["parameters"]["action_name"], "remove-hosts")

    # Security validation tests

    def test_search_host_groups_with_special_characters_in_filter(self):
        """Test that special characters in filter are passed through safely."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }

        filter_with_special = "name:*';DROP TABLE--*"
        self.module.search_host_groups(filter=filter_with_special)

        call_args = self.mock_client.command.call_args
        self.assertEqual(call_args[1]["parameters"]["filter"], filter_with_special)

    def test_create_host_group_permission_error(self):
        """Test create_host_group with 403 permission error returns error response."""
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Access denied, authorization failed"}]},
        }

        result = self.module.create_host_group(
            name="Test",
            group_type="static",
            description=None,
            assignment_rule=None,
        )

        self.assertEqual(len(result), 1)
        self.assertIn("error", result[0])

    def test_delete_host_groups_permission_error(self):
        """Test delete_host_groups with 403 permission error returns error response."""
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Access denied, authorization failed"}]},
        }

        result = self.module.delete_host_groups(ids=["group-1"])

        self.assertEqual(len(result), 1)
        self.assertIn("error", result[0])

    # Annotation tests

    def test_search_tools_have_read_only_annotations(self):
        """Test that search tools are registered with read-only annotations."""
        self.module.register_tools(self.mock_server)
        self.assert_tool_annotations(
            "falcon_search_host_groups", READ_ONLY_ANNOTATIONS
        )
        self.assert_tool_annotations(
            "falcon_search_host_group_members", READ_ONLY_ANNOTATIONS
        )

    def test_mutating_tools_have_correct_annotations(self):
        """Test that mutating tools carry the correct annotations."""
        self.module.register_tools(self.mock_server)

        non_destructive = ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=True,
        )
        self.assert_tool_annotations("falcon_create_host_group", non_destructive)

        # update_host_group can rewrite a dynamic group's assignment_rule and
        # perform_host_group_action can remove hosts, so both move hosts out of
        # groups (and their policies) rather than only adding.
        destructive_mutating = ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=True,
        )
        self.assert_tool_annotations("falcon_update_host_group", destructive_mutating)
        self.assert_tool_annotations(
            "falcon_perform_host_group_action", destructive_mutating
        )

        self.assert_tool_annotations(
            "falcon_delete_host_groups",
            ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )


    # ==========================================
    # get_host_group_membership
    # ==========================================

    def test_get_host_group_membership_resolves_groups(self):
        """Group IDs from the device record are hydrated with getHostGroups."""
        self.mock_client.command.side_effect = [
            {
                "status_code": 200,
                "body": {
                    "resources": [
                        {
                            "device_id": "aid-1",
                            "hostname": "WS01",
                            "groups": ["group-2", "group-1"],
                        }
                    ]
                },
            },
            {
                "status_code": 200,
                "body": {
                    "resources": [
                        {"id": "group-1", "name": "Windows", "group_type": "dynamic"},
                        {"id": "group-2", "name": "Pilot", "group_type": "static"},
                    ]
                },
            },
        ]

        result = self.module.get_host_group_membership(device_id=" aid-1 ")

        device_call, groups_call = self.mock_client.command.call_args_list
        self.assertEqual(device_call.args[0], "PostDeviceDetailsV2")
        self.assertEqual(device_call.kwargs["body"], {"ids": ["aid-1"]})
        self.assertEqual(groups_call.args[0], "getHostGroups")
        self.assertEqual(groups_call.kwargs["parameters"], {"ids": ["group-2", "group-1"]})

        self.assertEqual(result["device_id"], "aid-1")
        self.assertEqual(result["hostname"], "WS01")
        self.assertEqual(result["count"], 2)
        self.assertEqual([g["id"] for g in result["results"]], ["group-2", "group-1"])
        self.assertNotIn("unresolved_group_ids", result)

    def test_get_host_group_membership_no_groups(self):
        """A host in no groups returns an empty list without a second call."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"device_id": "aid-1", "hostname": "WS01", "groups": []}]},
        }

        result = self.module.get_host_group_membership(device_id="aid-1")

        self.assertEqual(self.mock_client.command.call_count, 1)
        self.assertEqual(result["results"], [])
        self.assertEqual(result["count"], 0)

    def test_get_host_group_membership_reports_unresolved_groups(self):
        """Group IDs that no longer resolve are listed rather than silently dropped."""
        self.mock_client.command.side_effect = [
            {
                "status_code": 200,
                "body": {"resources": [{"device_id": "aid-1", "groups": ["group-1", "gone"]}]},
            },
            {
                "status_code": 200,
                "body": {"resources": [{"id": "group-1", "name": "Windows"}]},
            },
        ]

        result = self.module.get_host_group_membership(device_id="aid-1")

        self.assertEqual(result["count"], 1)
        self.assertEqual(result["unresolved_group_ids"], ["gone"])

    def test_get_host_group_membership_unknown_device(self):
        """An unknown device ID is an error, not an empty membership."""
        self.mock_client.command.return_value = {"status_code": 200, "body": {"resources": []}}

        result = self.module.get_host_group_membership(device_id="missing")

        self.assertIn("No host found", result[0]["error"])

    def test_get_host_group_membership_requires_device_id(self):
        """A blank device ID stops before any API call."""
        result = self.module.get_host_group_membership(device_id="  ")

        self.assertIn("error", result[0])
        self.mock_client.command.assert_not_called()

    def test_get_host_group_membership_device_error(self):
        """A failed device lookup is surfaced."""
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied"}]},
        }

        result = self.module.get_host_group_membership(device_id="aid-1")

        self.assertIn("error", result[0])
        self.assertEqual(self.mock_client.command.call_count, 1)

    def test_get_host_group_membership_groups_error(self):
        """A failed group lookup is surfaced."""
        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {"resources": [{"device_id": "aid-1", "groups": ["g"]}]}},
            {"status_code": 403, "body": {"errors": [{"message": "access denied"}]}},
        ]

        result = self.module.get_host_group_membership(device_id="aid-1")

        self.assertIn("error", result[0])

    def test_get_host_group_membership_is_read_only(self):
        """The membership lookup is registered with read-only annotations."""
        self.module.register_tools(self.mock_server)
        self.assert_tool_annotations("falcon_get_host_group_membership", READ_ONLY_ANNOTATIONS)


AID = "a" * 32


class TestHostGroupMembershipVerify(TestModules):
    """verify modes on falcon_get_host_group_membership check groups one by one."""

    def setUp(self):
        self.setup_module(HostGroupsModule)

    def _wire(self, record_groups, members, static_groups=(), all_groups=(), failing=None):
        """Route client.command by operation, since checks run in parallel."""
        failing = failing or {}

        def command(operation, parameters=None, body=None, **_):
            if operation == "PostDeviceDetailsV2":
                return {
                    "status_code": 200,
                    "body": {"resources": [{"device_id": AID, "hostname": "WS-1", "groups": list(record_groups)}]},
                }
            if operation == "queryHostGroups":
                ids = list(static_groups) if parameters.get("filter") else list(all_groups)
                return {"status_code": 200, "body": {"resources": ids, "meta": {"pagination": {"total": len(ids)}}}}
            if operation == "queryGroupMembers":
                group_id = parameters["id"]
                self.assertEqual(parameters["filter"], f"device_id:'{AID}'")
                if group_id in failing:
                    return failing[group_id]
                return {"status_code": 200, "body": {"resources": [AID] if group_id in members else []}}
            if operation == "getHostGroups":
                return {"status_code": 200, "body": {"resources": [{"id": g} for g in parameters["ids"]]}}
            raise AssertionError(f"unexpected operation {operation}")

        self.mock_client.command.side_effect = command

    def test_none_is_the_default_and_checks_nothing(self):
        self._wire(["g1", "g2"], members={"g1"})
        result = self.module.get_host_group_membership(device_id=AID)
        self.assertEqual([g["id"] for g in result["results"]], ["g1", "g2"])
        self.assertNotIn("verification", result)
        operations = {c[0][0] for c in self.mock_client.command.call_args_list}
        self.assertNotIn("queryGroupMembers", operations)

    def test_record_drops_stale_groups(self):
        self._wire(["g1", "g2", "g3"], members={"g1", "g3"})
        result = self.module.get_host_group_membership(device_id=AID, verify="record")
        self.assertEqual([g["id"] for g in result["results"]], ["g1", "g3"])
        verification = result["verification"]
        self.assertEqual(verification["mode"], "record")
        self.assertEqual(verification["groups_checked"], 3)
        self.assertEqual(verification["stale_record_group_ids"], ["g2"])
        self.assertEqual(verification["missing_from_record_group_ids"], [])

    def test_static_finds_groups_missing_from_the_record(self):
        self._wire(["g1"], members={"g1", "s2"}, static_groups=["s1", "s2"])
        result = self.module.get_host_group_membership(device_id=AID, verify="static")
        self.assertEqual([g["id"] for g in result["results"]], ["g1", "s2"])
        self.assertEqual(result["verification"]["missing_from_record_group_ids"], ["s2"])
        self.assertEqual(result["verification"]["groups_checked"], 3)
        list_call = next(c for c in self.mock_client.command.call_args_list if c[0][0] == "queryHostGroups")
        self.assertEqual(list_call[1]["parameters"]["filter"], "group_type:'static',group_type:'staticByID'")

    def test_all_checks_every_group(self):
        self._wire([], members={"d9"}, all_groups=["s1", "d9"])
        result = self.module.get_host_group_membership(device_id=AID, verify="all")
        self.assertEqual([g["id"] for g in result["results"]], ["d9"])

    def test_any_failed_check_fails_the_whole_call(self):
        for failure in (
            {"status_code": 403, "body": {"errors": [{"code": 403, "message": "access denied"}]}},
            {"status_code": 500, "body": {"errors": [{"code": 500, "message": "upstream"}]}},
            {"status_code": 429, "body": {"errors": [{"code": 429, "message": "rate limited"}]}},
        ):
            with self.subTest(status=failure["status_code"]):
                self._wire(["g1", "g2"], members={"g1"}, failing={"g2": failure})
                result = self.module.get_host_group_membership(device_id=AID, verify="record")
                self.assertIsInstance(result, list)
                self.assertIn("g2", result[0]["error"])

    def test_transport_exception_fails_the_whole_call(self):
        self._wire(["g1", "g2"], members={"g1"})
        wired = self.mock_client.command.side_effect

        def command(operation, parameters=None, **kwargs):
            if operation == "queryGroupMembers" and parameters["id"] == "g2":
                raise ConnectionError("reset by peer")
            return wired(operation, parameters=parameters, **kwargs)

        self.mock_client.command.side_effect = command
        result = self.module.get_host_group_membership(device_id=AID, verify="record")
        self.assertIsInstance(result, list)
        self.assertIn("g2", result[0]["error"])

    def test_deleted_group_is_reported_not_failed(self):
        gone = {"status_code": 404, "body": {"errors": [{"code": 404, "message": "Group not found"}]}}
        self._wire(["g1", "g2"], members={"g1"}, failing={"g2": gone})
        result = self.module.get_host_group_membership(device_id=AID, verify="record")
        self.assertEqual([g["id"] for g in result["results"]], ["g1"])
        self.assertEqual(result["verification"]["deleted_group_ids"], ["g2"])

    @patch("falcon_mcp.modules.host_groups.MEMBERSHIP_CHECK_BUDGET_SECONDS", 0)
    def test_budget_exhausted_fails_the_call(self):
        self._wire(["g1", "g2"], members={"g1"})
        wired = self.mock_client.command.side_effect

        def slow(operation, **kwargs):
            if operation == "queryGroupMembers":
                time.sleep(0.2)
            return wired(operation, **kwargs)

        self.mock_client.command.side_effect = slow
        result = self.module.get_host_group_membership(device_id=AID, verify="record")
        self.assertIsInstance(result, list)
        self.assertIn("budget", result[0]["error"])

    def test_verify_needs_a_real_device_id(self):
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"device_id": "x' or '1", "groups": ["g1"]}]},
        }
        result = self.module.get_host_group_membership(device_id="x' or '1", verify="record")
        self.assertIsInstance(result, list)
        self.assertIn("error", result[0])
        operations = [c[0][0] for c in self.mock_client.command.call_args_list]
        self.assertNotIn("queryGroupMembers", operations)


if __name__ == "__main__":
    unittest.main()
