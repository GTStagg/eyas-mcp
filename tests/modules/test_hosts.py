"""
Tests for the Hosts module.
"""

import unittest

from mcp.types import ToolAnnotations

from falcon_mcp.modules.hosts import HostsModule
from falcon_mcp.resources.hosts import SEARCH_HOSTS_FQL_DOCUMENTATION
from tests.modules.utils.test_modules import TestModules


class TestHostsModule(TestModules):
    """Test cases for the Hosts module."""

    def setUp(self):
        """Set up test fixtures."""
        self.setup_module(HostsModule)

    def test_register_tools(self):
        """Test registering tools with the server."""
        expected_tools = [
            "falcon_search_hosts",
            "falcon_get_host_details",
            "falcon_manage_host_grouping_tags",
            "falcon_contain_hosts",
            "falcon_lift_host_containment",
            "falcon_get_host_online_state",
            "falcon_get_host_network_history",
            "falcon_get_host_login_history",
            "falcon_search_hidden_hosts",
            "falcon_hide_hosts",
            "falcon_unhide_hosts",
            "falcon_delete_hosts",
            "falcon_search_containment_allowlist",
            "falcon_create_containment_allowlist_rules",
            "falcon_update_containment_allowlist_labels",
            "falcon_delete_containment_allowlist_rules",
        ]
        self.assert_tools_registered(expected_tools)

    def test_host_context_annotations(self):
        """Reads are read-only; hiding and deleting are destructive, unhiding is not."""
        self.module.register_tools(self.mock_server)
        for name in (
            "falcon_get_host_online_state",
            "falcon_get_host_network_history",
            "falcon_get_host_login_history",
            "falcon_search_hidden_hosts",
        ):
            with self.subTest(tool=name):
                self.assertIs(self._annotations(name).readOnlyHint, True)
        for name, destructive in (
            ("falcon_hide_hosts", True),
            ("falcon_unhide_hosts", False),
            ("falcon_delete_hosts", True),
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

    def _annotations(self, name):
        for call in self.mock_server.add_tool.call_args_list:
            if call.kwargs.get("name") == name:
                return call.kwargs["annotations"]
        raise AssertionError(f"{name} not registered")

    def test_contain_hosts_annotations(self):
        """Containment cuts hosts off the network, so it is destructive."""
        self.module.register_tools(self.mock_server)
        self.assert_tool_annotations(
            "falcon_contain_hosts",
            ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

    def test_lift_host_containment_annotations(self):
        """Lifting containment restores access: a write, but not destructive."""
        self.module.register_tools(self.mock_server)
        self.assert_tool_annotations(
            "falcon_lift_host_containment",
            ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

    def test_manage_host_grouping_tags_annotations(self):
        """The tag tool is mutating but safe to retry (set semantics)."""
        self.module.register_tools(self.mock_server)
        self.assert_tool_annotations(
            "falcon_manage_host_grouping_tags",
            ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

    def test_register_resources(self):
        """Test registering resources with the server."""
        expected_resources = [
            "falcon_search_hosts_fql_guide",
        ]
        self.assert_resources_registered(expected_resources)

    def test_search_hosts(self):
        """Test searching for hosts."""
        # Setup mock responses for both API calls
        query_response = {
            "status_code": 200,
            "body": {
                "resources": ["device1", "device2"],
                "meta": {"pagination": {"offset": 0, "limit": 100, "total": 2}},
            },
        }
        details_response = {
            "status_code": 200,
            "body": {"resources": [
                {"device_id": "device1", "hostname": "host1", "platform_name": "Windows"},
                {"device_id": "device2", "hostname": "host2", "platform_name": "Windows"},
            ]},
        }
        self.mock_client.command.side_effect = [query_response, details_response]

        # Call search_hosts
        result = self.module.search_hosts(filter="platform_name:'Windows'", limit=50)

        # Verify first call uses the new base method with correct parameters
        first_call = self.mock_client.command.call_args_list[0]
        self.assertEqual(first_call[0][0], "QueryDevicesByFilter")  # operation name
        self.assertEqual(first_call[1]["parameters"]["filter"], "platform_name:'Windows'")
        self.assertEqual(first_call[1]["parameters"]["limit"], 50)

        # Verify second call for device details
        second_call = self.mock_client.command.call_args_list[1]
        self.assertEqual(second_call[0][0], "PostDeviceDetailsV2")
        self.assertEqual(second_call[1]["body"]["ids"], ["device1", "device2"])

        # Verify result envelope
        self.assertIn("results", result)
        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(result["results"][0]["device_id"], "device1")
        self.assertEqual(result["results"][1]["device_id"], "device2")
        self.assertEqual(result["pagination"]["total"], 2)

    def test_search_hosts_with_details(self):
        """Test searching for hosts with details."""
        # Setup mock responses
        query_response = {
            "status_code": 200,
            "body": {
                "resources": ["device1", "device2"],
                "meta": {"pagination": {"offset": 0, "limit": 100, "total": 2}},
            },
        }
        details_response = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "device_id": "device1",
                        "hostname": "TEST-HOST-1",
                        "platform_name": "Windows",
                    },
                    {
                        "device_id": "device2",
                        "hostname": "TEST-HOST-2",
                        "platform_name": "Linux",
                    },
                ]
            },
        }
        self.mock_client.command.side_effect = [query_response, details_response]

        # Call search_hosts
        result = self.module.search_hosts(filter="platform_name:'Windows'", limit=50)

        # Verify client commands were called correctly
        self.assertEqual(self.mock_client.command.call_count, 2)

        # Check that the first call was to QueryDevicesByFilter with the right filter and limit
        first_call = self.mock_client.command.call_args_list[0]
        self.assertEqual(first_call[0][0], "QueryDevicesByFilter")
        self.assertEqual(
            first_call[1]["parameters"]["filter"], "platform_name:'Windows'"
        )
        self.assertEqual(first_call[1]["parameters"]["limit"], 50)
        self.mock_client.command.assert_any_call(
            "PostDeviceDetailsV2", body={"ids": ["device1", "device2"]}
        )

        # Verify result envelope
        self.assertIn("results", result)
        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(result["results"][0]["device_id"], "device1")
        self.assertEqual(result["results"][1]["device_id"], "device2")
        self.assertEqual(result["pagination"]["total"], 2)

    def test_search_hosts_error(self):
        """Test searching for hosts with a filter error returns the FQL guide."""
        # Setup mock response with error
        mock_response = {
            "status_code": 400,
            "body": {"errors": [{"message": "Invalid filter"}]},
        }
        self.mock_client.command.return_value = mock_response

        # Call search_hosts
        result = self.module.search_hosts(filter="invalid_filter")

        # Verify result contains the error wrapped alongside the FQL guide and hint
        self.assertIsInstance(result, dict)
        self.assertIn("results", result)
        self.assertIn("error", result["results"][0])
        self.assertIn("fql_guide", result)
        self.assertEqual(result["fql_guide"], SEARCH_HOSTS_FQL_DOCUMENTATION)
        self.assertIn("hint", result)
        self.assertEqual(result["filter_used"], "invalid_filter")

    def test_search_hosts_no_results(self):
        """Test searching for hosts with no results."""
        # Setup mock response with empty resources
        mock_response = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"offset": 0, "limit": 100, "total": 0}}}}
        self.mock_client.command.return_value = mock_response

        # Call search_hosts
        result = self.module.search_hosts(filter="hostname:'NONEXISTENT'")

        # Verify result is empty envelope
        self.assertIsInstance(result, dict)
        self.assertEqual(result["results"], [])
        self.assertIn("pagination", result)
        # Only one API call should be made (QueryDevicesByFilter)
        self.assertEqual(self.mock_client.command.call_count, 1)

    def test_search_hosts_with_all_parameters(self):
        """Test searching for hosts with all parameters."""
        # Setup mock response with empty resources
        mock_response = {"status_code": 200, "body": {"resources": []}}
        self.mock_client.command.return_value = mock_response

        # Call search_hosts with all parameters
        result = self.module.search_hosts(
            filter="platform_name:'Linux'", limit=25, offset=10, sort="hostname.desc"
        )

        # Verify API call with all parameters
        self.mock_client.command.assert_called_once_with(
            "QueryDevicesByFilter",
            parameters={
                "filter": "platform_name:'Linux'",
                "limit": 25,
                "offset": 10,
                "sort": "hostname.desc",
            },
        )

        # Verify result
        self.assertIsInstance(result, dict)
        self.assertEqual(result["results"], [])
        self.assertIn("pagination", result)

    def test_search_hosts_reorders_to_match_sorted_ids(self):
        """When PostDeviceDetailsV2 returns devices out of order, the result is
        reordered to match the sorted ID order from QueryDevicesByFilter.

        Live API validated: the details endpoint preserves order today, so this
        guards against regressions and future endpoint behavior changes. Entities
        carry their ID in the ``device_id`` field.
        """
        query_response = {
            "status_code": 200,
            "body": {"resources": ["device2", "device1"]},
        }
        details_response = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"device_id": "device1", "hostname": "alpha"},
                    {"device_id": "device2", "hostname": "bravo"},
                ]
            },
        }
        self.mock_client.command.side_effect = [query_response, details_response]

        result = self.module.search_hosts(sort="last_seen.desc")

        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(result["results"][0]["device_id"], "device2")
        self.assertEqual(result["results"][1]["device_id"], "device1")

    def test_get_host_details(self):
        """Test getting host details."""
        # Setup mock response
        mock_response = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "device_id": "device1",
                        "hostname": "TEST-HOST-1",
                        "platform_name": "Windows",
                    }
                ]
            },
        }
        self.mock_client.command.return_value = mock_response

        # Call get_host_details
        result = self.module.get_host_details(["device1"])

        # Verify client command was called correctly
        self.mock_client.command.assert_called_once_with(
            "PostDeviceDetailsV2", body={"ids": ["device1"]}
        )

        # Verify result
        expected_result = [
            {
                "device_id": "device1",
                "hostname": "TEST-HOST-1",
                "platform_name": "Windows",
            }
        ]
        self.assertEqual(result, expected_result)

    def test_get_host_details_multiple_ids(self):
        """Test getting host details for multiple IDs."""
        # Setup mock response
        mock_response = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "device_id": "device1",
                        "hostname": "TEST-HOST-1",
                        "platform_name": "Windows",
                    },
                    {
                        "device_id": "device2",
                        "hostname": "TEST-HOST-2",
                        "platform_name": "Linux",
                    },
                ]
            },
        }
        self.mock_client.command.return_value = mock_response

        # Call get_host_details
        result = self.module.get_host_details(["device1", "device2"])

        # Verify client command was called correctly
        self.mock_client.command.assert_called_once_with(
            "PostDeviceDetailsV2", body={"ids": ["device1", "device2"]}
        )

        # Verify result
        expected_result = [
            {
                "device_id": "device1",
                "hostname": "TEST-HOST-1",
                "platform_name": "Windows",
            },
            {
                "device_id": "device2",
                "hostname": "TEST-HOST-2",
                "platform_name": "Linux",
            },
        ]
        self.assertEqual(result, expected_result)

    def test_get_host_details_not_found(self):
        """Test getting host details for non-existent host."""
        # Setup mock response with empty resources
        mock_response = {"status_code": 200, "body": {"resources": []}}
        self.mock_client.command.return_value = mock_response

        # Call get_host_details
        result = self.module.get_host_details(["nonexistent"])

        # For empty resources, handle_api_response returns the default_result (empty list)
        self.assertEqual(result, [])

    def test_get_host_details_error(self):
        """Test getting host details with API error."""
        # Setup mock response with error
        mock_response = {
            "status_code": 404,
            "body": {"errors": [{"message": "Device not found"}]},
        }
        self.mock_client.command.return_value = mock_response

        # Call get_host_details
        result = self.module.get_host_details(["invalid-id"])

        # Verify result contains error
        self.assertIsInstance(result, dict)
        self.assertIn("error", result)
        self.assertIn("details", result)

    def test_get_host_details_empty_list(self):
        """Test getting host details with empty ID list."""
        # Call get_host_details with empty list
        result = self.module.get_host_details([])

        # Should return empty list without making API call
        self.assertEqual(result, [])
        self.mock_client.command.assert_not_called()

    def test_search_hosts_windows_platform(self):
        """Test searching for Windows hosts."""
        # Setup mock responses
        query_response = {
            "status_code": 200,
            "body": {
                "resources": ["win-host-1", "win-host-2"],
                "meta": {"pagination": {"offset": 0, "limit": 100, "total": 2}},
            },
        }
        details_response = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "device_id": "win-host-1",
                        "platform_name": "Windows",
                        "hostname": "WIN-01",
                    },
                    {
                        "device_id": "win-host-2",
                        "platform_name": "Windows",
                        "hostname": "WIN-02",
                    },
                ]
            },
        }
        self.mock_client.command.side_effect = [query_response, details_response]

        # Call search_hosts
        result = self.module.search_hosts(filter="platform_name:'Windows'")

        # Verify result envelope
        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(result["results"][0]["platform_name"], "Windows")
        self.assertEqual(result["results"][1]["platform_name"], "Windows")

        # Verify filter was applied correctly
        first_call = self.mock_client.command.call_args_list[0]
        self.assertEqual(
            first_call[1]["parameters"]["filter"], "platform_name:'Windows'"
        )

    def test_search_hosts_linux_platform(self):
        """Test searching for Linux hosts."""
        # Setup mock responses
        query_response = {
            "status_code": 200,
            "body": {
                "resources": ["linux-host-1"],
                "meta": {"pagination": {"offset": 0, "limit": 100, "total": 1}},
            },
        }
        details_response = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "device_id": "linux-host-1",
                        "platform_name": "Linux",
                        "hostname": "LINUX-01",
                    }
                ]
            },
        }
        self.mock_client.command.side_effect = [query_response, details_response]

        # Call search_hosts
        result = self.module.search_hosts(filter="platform_name:'Linux'")

        # Verify result envelope
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["platform_name"], "Linux")

        # Verify filter was applied correctly
        first_call = self.mock_client.command.call_args_list[0]
        self.assertEqual(first_call[1]["parameters"]["filter"], "platform_name:'Linux'")

    def test_search_hosts_mac_platform_no_results(self):
        """Test searching for Mac hosts with no results."""
        # Setup mock response with empty resources
        mock_response = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"offset": 0, "limit": 100, "total": 0}}}}
        self.mock_client.command.return_value = mock_response

        # Call search_hosts
        result = self.module.search_hosts(filter="platform_name:'Mac'")

        # Verify result envelope
        self.assertEqual(len(result["results"]), 0)

        # Verify filter was applied correctly
        first_call = self.mock_client.command.call_args_list[0]
        self.assertEqual(first_call[1]["parameters"]["filter"], "platform_name:'Mac'")

    # ----------------------------------------------------------------- #
    # manage_host_grouping_tags
    # ----------------------------------------------------------------- #
    def _tag_success_response(self):
        return {
            "status_code": 202,
            "body": {"resources": [{"device_id": "device1", "updated": True}]},
        }

    def test_manage_host_grouping_tags_add(self):
        """Add sends the Uber-class body shape: action/device_ids/tags."""
        self.mock_client.command.return_value = self._tag_success_response()

        result = self.module.manage_host_grouping_tags(
            ids=["device1"],
            action="add",
            tags=["FalconGroupingTags/Quarantined"],
        )

        self.mock_client.command.assert_called_once_with(
            "UpdateDeviceTags",
            body={
                "action": "add",
                "device_ids": ["device1"],
                "tags": ["FalconGroupingTags/Quarantined"],
            },
        )
        self.assertEqual(result, [{"device_id": "device1", "updated": True}])

    def test_manage_host_grouping_tags_remove(self):
        """Remove passes action through unchanged."""
        self.mock_client.command.return_value = self._tag_success_response()

        self.module.manage_host_grouping_tags(
            ids=["device1", "device2"],
            action="remove",
            tags=["FalconGroupingTags/Quarantined"],
        )

        body = self.mock_client.command.call_args[1]["body"]
        self.assertEqual(body["action"], "remove")
        self.assertEqual(body["device_ids"], ["device1", "device2"])

    def test_manage_host_grouping_tags_normalizes_bare_tags(self):
        """Bare tag names get the FalconGroupingTags/ prefix added."""
        self.mock_client.command.return_value = self._tag_success_response()

        self.module.manage_host_grouping_tags(
            ids=["device1"],
            action="add",
            tags=["Quarantined", "FalconGroupingTags/IR-2026-07"],
        )

        body = self.mock_client.command.call_args[1]["body"]
        self.assertEqual(
            body["tags"],
            ["FalconGroupingTags/Quarantined", "FalconGroupingTags/IR-2026-07"],
        )

    def test_manage_host_grouping_tags_strips_whitespace(self):
        """Surrounding whitespace is trimmed before prefixing."""
        self.mock_client.command.return_value = self._tag_success_response()

        self.module.manage_host_grouping_tags(
            ids=["device1"], action="add", tags=["  Quarantined  "]
        )

        body = self.mock_client.command.call_args[1]["body"]
        self.assertEqual(body["tags"], ["FalconGroupingTags/Quarantined"])

    def test_manage_host_grouping_tags_rejects_sensor_tags(self):
        """Sensor grouping tags are read-only and must not be silently re-prefixed."""
        result = self.module.manage_host_grouping_tags(
            ids=["device1"],
            action="add",
            tags=["SensorGroupingTags/Production"],
        )

        self.assertIsInstance(result, list)
        self.assertIn("error", result[0])
        self.assertIn("SensorGroupingTags/Production", result[0]["error"])
        self.mock_client.command.assert_not_called()

    def test_manage_host_grouping_tags_rejects_miscased_sensor_tags(self):
        """The sensor guard is case-insensitive.

        Matching the prefix exactly would let 'sensorgroupingtags/x' through to be
        prefixed into 'FalconGroupingTags/sensorgroupingtags/x' — a tag the API
        accepts, so the junk lands on the host instead of erroring.
        """
        for spelling in (
            "sensorgroupingtags/Production",
            "SENSORGROUPINGTAGS/Production",
            "SensorGroupingtags/Production",
        ):
            with self.subTest(spelling=spelling):
                self.mock_client.command.reset_mock()
                result = self.module.manage_host_grouping_tags(
                    ids=["device1"], action="add", tags=[spelling]
                )

                self.assertIn("error", result[0])
                self.mock_client.command.assert_not_called()

    def test_manage_host_grouping_tags_canonicalizes_miscased_prefix(self):
        """A miscased grouping prefix is rewritten to canonical casing.

        The API compares the prefix exactly and 400s on anything else, so passing
        it through unchanged fails and blindly prepending doubles it up. Only
        rewriting the prefix reaches the tag the caller meant. The tag name after
        the prefix keeps its casing, which the API is case-sensitive about.
        """
        self.mock_client.command.return_value = self._tag_success_response()

        self.module.manage_host_grouping_tags(
            ids=["device1"],
            action="add",
            tags=[
                "falcongroupingtags/Quarantined",
                "FALCONGROUPINGTAGS/IR-2026-07",
                "FalconGroupingTags/Already-Fine",
            ],
        )

        body = self.mock_client.command.call_args[1]["body"]
        self.assertEqual(
            body["tags"],
            [
                "FalconGroupingTags/Quarantined",
                "FalconGroupingTags/IR-2026-07",
                "FalconGroupingTags/Already-Fine",
            ],
        )

    def test_manage_host_grouping_tags_rejects_too_many_ids(self):
        """Over 5000 device IDs is a 400 from the API; catch it before the call."""
        result = self.module.manage_host_grouping_tags(
            ids=[f"device{i}" for i in range(5001)],
            action="add",
            tags=["Quarantined"],
        )

        self.assertIn("error", result[0])
        self.assertIn("5000", result[0]["error"])
        self.mock_client.command.assert_not_called()

    def test_manage_host_grouping_tags_rejects_too_many_tags(self):
        """Over 50 tags in one call returns an opaque 500 with nothing applied."""
        result = self.module.manage_host_grouping_tags(
            ids=["device1"],
            action="add",
            tags=[f"bulk-{i}" for i in range(51)],
        )

        self.assertIn("error", result[0])
        self.assertIn("50", result[0]["error"])
        self.mock_client.command.assert_not_called()

    def test_manage_host_grouping_tags_rejects_invalid_action(self):
        """Only add and remove are valid actions."""
        result = self.module.manage_host_grouping_tags(
            ids=["device1"], action="update", tags=["Quarantined"]
        )

        self.assertIn("error", result[0])
        self.mock_client.command.assert_not_called()

    def test_manage_host_grouping_tags_rejects_empty_ids(self):
        """An empty id list would PATCH nothing; fail loudly instead."""
        result = self.module.manage_host_grouping_tags(
            ids=[], action="add", tags=["Quarantined"]
        )

        self.assertIn("error", result[0])
        self.mock_client.command.assert_not_called()

    def test_manage_host_grouping_tags_rejects_empty_tags(self):
        """An empty tag list would report success while changing nothing."""
        result = self.module.manage_host_grouping_tags(
            ids=["device1"], action="add", tags=[]
        )

        self.assertIn("error", result[0])
        self.mock_client.command.assert_not_called()

    def test_manage_host_grouping_tags_rejects_blank_tag(self):
        """A whitespace-only tag normalizes to a bare prefix; reject it."""
        result = self.module.manage_host_grouping_tags(
            ids=["device1"], action="add", tags=["   "]
        )

        self.assertIn("error", result[0])
        self.mock_client.command.assert_not_called()

    def test_manage_host_grouping_tags_api_error(self):
        """API failures come back in the module's standard error shape."""
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied"}]},
        }

        result = self.module.manage_host_grouping_tags(
            ids=["device1"], action="add", tags=["Quarantined"]
        )

        self.assertIn("error", result[0])
        self.assertIn("required_scopes", result[0])

    # ----------------------------------------------------------------- #
    # contain_hosts / lift_host_containment
    # ----------------------------------------------------------------- #
    AID_1 = "a" * 32
    AID_2 = "0123456789abcdef0123456789abcdef"

    def _action_response(self, ids, status_code=202, errors=None):
        return {
            "status_code": status_code,
            "body": {
                "resources": [{"id": i, "path": ""} for i in ids],
                "errors": errors or [],
            },
        }

    def test_contain_hosts_request_shape(self):
        """action_name goes in the query string and the IDs in the body."""
        self.mock_client.command.return_value = self._action_response([self.AID_1, self.AID_2])

        result = self.module.contain_hosts(ids=[self.AID_1, self.AID_2])

        self.mock_client.command.assert_called_once_with(
            "PerformActionV2",
            parameters={"action_name": "contain"},
            body={"ids": [self.AID_1, self.AID_2]},
        )
        self.assertEqual(result["action"], "contain")
        self.assertEqual(result["succeeded_ids"], [self.AID_1, self.AID_2])
        self.assertEqual(len(result["resources"]), 2)
        self.assertNotIn("partial_failure", result)

    def test_lift_host_containment_request_shape(self):
        """Lifting uses the lift_containment action on the same operation."""
        self.mock_client.command.return_value = self._action_response([self.AID_1])

        result = self.module.lift_host_containment(ids=[self.AID_1])

        self.mock_client.command.assert_called_once_with(
            "PerformActionV2",
            parameters={"action_name": "lift_containment"},
            body={"ids": [self.AID_1]},
        )
        self.assertEqual(result["action"], "lift_containment")
        self.assertEqual(result["succeeded_ids"], [self.AID_1])

    def test_containment_dedupes_and_lowercases_ids(self):
        """Repeats, including case variants and padding, collapse to one ID."""
        self.mock_client.command.return_value = self._action_response([self.AID_2])

        self.module.contain_hosts(ids=[self.AID_2, self.AID_2.upper(), f" {self.AID_2} "])

        body = self.mock_client.command.call_args[1]["body"]
        self.assertEqual(body["ids"], [self.AID_2])

    def test_containment_rejects_bad_ids_without_calling_api(self):
        """Malformed IDs fail locally, before anything reaches the API."""
        bad_inputs = {
            "empty list": [],
            "too short": ["abc123"],
            "too long": ["a" * 33],
            "non-hex": ["g" * 32],
            "hostname": ["WORKSTATION-01"],
            "blank": ["   "],
            "one bad among good": [self.AID_1, "not-an-aid"],
            "too many": [f"{i:032x}" for i in range(101)],
        }
        for tool in (self.module.contain_hosts, self.module.lift_host_containment):
            for label, ids in bad_inputs.items():
                with self.subTest(tool=tool.__name__, case=label):
                    self.mock_client.command.reset_mock()
                    result = tool(ids=ids)
                    self.assertIn("error", result)
                    self.mock_client.command.assert_not_called()

    def test_containment_accepts_exactly_100_ids(self):
        """The cap counts distinct IDs, and 100 is allowed."""
        ids = [f"{i:032x}" for i in range(100)]
        self.mock_client.command.return_value = self._action_response(ids)

        result = self.module.contain_hosts(ids=ids + ids[:5])

        self.assertNotIn("error", result)
        self.assertEqual(len(self.mock_client.command.call_args[1]["body"]["ids"]), 100)

    def test_containment_partial_failure(self):
        """Hosts the API confirmed and hosts it rejected are both reported."""
        errors = [{"code": 404, "message": f"Device {self.AID_2} not found"}]
        self.mock_client.command.return_value = self._action_response(
            [self.AID_1], status_code=202, errors=errors
        )

        result = self.module.contain_hosts(ids=[self.AID_1, self.AID_2])

        self.assertNotIn("error", result)
        self.assertTrue(result["partial_failure"])
        self.assertEqual(result["succeeded_ids"], [self.AID_1])
        self.assertEqual(result["failed_ids"], [self.AID_2])
        self.assertEqual(result["errors"], errors)
        self.assertIn("1 of 2", result["warning"])

    def test_containment_partial_failure_under_error_status(self):
        """A non-2xx that still carries resources must not hide the changed hosts."""
        errors = [{"code": 404, "message": "not found"}]
        self.mock_client.command.return_value = self._action_response(
            [self.AID_1], status_code=404, errors=errors
        )

        result = self.module.contain_hosts(ids=[self.AID_1, self.AID_2])

        self.assertTrue(result["partial_failure"])
        self.assertEqual(result["succeeded_ids"], [self.AID_1])
        self.assertEqual(result["failed_ids"], [self.AID_2])

    def test_containment_api_error(self):
        """A failure with no resources comes back as the standard error shape."""
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied"}], "resources": []},
        }

        result = self.module.contain_hosts(ids=[self.AID_1])

        self.assertIn("error", result)
        self.assertIn("access denied", result["error"])
        self.assertEqual(result["details"]["status_code"], 403)
        self.assertIn("required_scopes", result)
        self.assertNotIn("succeeded_ids", result)

    def test_containment_errors_under_success_status(self):
        """A 2xx with only errors is still a failure, not a silent success."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"errors": [{"message": "device not eligible"}], "resources": []},
        }

        result = self.module.lift_host_containment(ids=[self.AID_1])

        self.assertIn("error", result)
        self.assertIn("device not eligible", result["error"])


    # ----------------------------------------------------------------- #
    # host context reads
    # ----------------------------------------------------------------- #
    UNKNOWN = "f" * 32

    @staticmethod
    def _ok(resources, status_code=200):
        return {"status_code": status_code, "body": {"resources": resources, "errors": []}}

    def _unknown_id(self, status_code=400):
        return {
            "status_code": status_code,
            "body": {
                "resources": [],
                "errors": [{"code": 400, "message": f"invalid device id [{self.UNKNOWN}]"}],
            },
        }

    def test_online_state_request_shape(self):
        """IDs go in the query string; results come back with an empty not_found."""
        record = {"id": self.AID_1, "state": "online", "last_seen": "2026-11-14T00:00:00Z"}
        self.mock_client.command.return_value = self._ok([record])

        result = self.module.get_host_online_state(ids=[self.AID_1.upper()])

        self.mock_client.command.assert_called_once_with(
            "GetOnlineState_V1", parameters={"ids": [self.AID_1]}
        )
        self.assertEqual(result, {"results": [record], "not_found": []})

    def test_online_state_caps_at_100(self):
        result = self.module.get_host_online_state(ids=[f"{i:032x}" for i in range(101)])
        self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_unknown_id_is_set_aside_and_the_rest_retried(self):
        """One unknown AID fails the whole call, so the known hosts are retried alone."""
        record = {"id": self.AID_1, "state": "offline"}
        self.mock_client.command.side_effect = [
            self._unknown_id(status_code=200),  # online state reports it under 200
            {
                "status_code": 400,
                "body": {
                    "resources": [{"device_id": self.AID_1}],
                    "errors": [{"message": f"invalid device id [{self.UNKNOWN}]"}],
                },
            },
            self._ok([record]),
        ]

        result = self.module.get_host_online_state(ids=[self.AID_1, self.UNKNOWN])

        calls = self.mock_client.command.call_args_list
        self.assertEqual(calls[1][0][0], "PostDeviceDetailsV2")
        self.assertEqual(calls[2][1]["parameters"], {"ids": [self.AID_1]})
        self.assertEqual(result, {"results": [record], "not_found": [self.UNKNOWN]})

    def test_all_unknown_ids_skip_the_retry(self):
        self.mock_client.command.side_effect = [self._unknown_id(), self._unknown_id()]

        result = self.module.get_host_network_history(ids=[self.UNKNOWN])

        self.assertEqual(self.mock_client.command.call_count, 2)
        self.assertEqual(result, {"results": [], "not_found": [self.UNKNOWN]})

    def test_unknown_id_with_failed_lookup_returns_the_original_error(self):
        """If host details can't say which IDs exist, nothing is guessed."""
        self.mock_client.command.side_effect = [
            self._unknown_id(),
            {"status_code": 403, "body": {"errors": [{"message": "access denied"}]}},
        ]

        result = self.module.get_host_network_history(ids=[self.AID_1, self.UNKNOWN])

        self.assertIn("error", result)
        self.assertEqual(result["details"]["status_code"], 400)
        self.assertEqual(self.mock_client.command.call_count, 2)

    def test_errors_under_200_are_reported(self):
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [], "errors": [{"message": "service unavailable"}]},
        }

        result = self.module.get_host_online_state(ids=[self.AID_1])

        self.assertIn("error", result)
        self.assertIn("service unavailable", result["error"])

    def test_network_history_request_shape_and_cap(self):
        record = {"device_id": self.AID_1, "history": []}
        self.mock_client.command.return_value = self._ok([record])

        result = self.module.get_host_network_history(ids=[self.AID_1])

        self.mock_client.command.assert_called_once_with(
            "QueryGetNetworkAddressHistoryV1", body={"ids": [self.AID_1]}
        )
        self.assertEqual(result["results"], [record])

        self.mock_client.command.reset_mock()
        result = self.module.get_host_network_history(ids=[f"{i:032x}" for i in range(501)])
        self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_login_history_defaults_to_recent_logins(self):
        self.mock_client.command.return_value = self._ok([])

        self.module.get_host_login_history(
            ids=[self.AID_1], interactive_only=False, since="now-7d", until="now", limit=10
        )

        self.mock_client.command.assert_called_once_with(
            "QueryDeviceLoginHistory", body={"ids": [self.AID_1]}
        )

    def test_login_history_interactive_uses_the_window(self):
        self.mock_client.command.return_value = self._ok([])

        self.module.get_host_login_history(
            ids=[self.AID_1], interactive_only=True, since="now-30d", until="now", limit=50
        )

        self.mock_client.command.assert_called_once_with(
            "QueryDeviceLoginHistoryV2",
            parameters={"from": "now-30d", "to": "now", "limit": 50},
            body={"ids": [self.AID_1]},
        )

    def test_login_history_interactive_caps_at_10(self):
        ids = [f"{i:032x}" for i in range(11)]
        result = self.module.get_host_login_history(
            ids=ids, interactive_only=True, since="now-7d", until="now", limit=10
        )
        self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

        self.mock_client.command.return_value = self._ok([])
        result = self.module.get_host_login_history(
            ids=ids, interactive_only=False, since="now-7d", until="now", limit=10
        )
        self.assertNotIn("error", result)

    def test_search_hidden_hosts(self):
        """Hidden host IDs are hydrated through the regular host details endpoint."""
        self.mock_client.command.side_effect = [
            {
                "status_code": 200,
                "body": {
                    "resources": ["h1", "h2"],
                    "meta": {"pagination": {"offset": 0, "limit": 10, "total": 2}},
                },
            },
            self._ok([{"device_id": "h2"}, {"device_id": "h1"}]),
        ]

        result = self.module.search_hidden_hosts(
            filter="platform_name:'Windows'", limit=10, offset=None, sort=None
        )

        calls = self.mock_client.command.call_args_list
        self.assertEqual(calls[0][0][0], "QueryHiddenDevices")
        self.assertEqual(calls[0][1]["parameters"]["filter"], "platform_name:'Windows'")
        self.assertEqual(calls[1][0][0], "PostDeviceDetailsV2")
        self.assertEqual([r["device_id"] for r in result["results"]], ["h1", "h2"])
        self.assertEqual(result["pagination"]["total"], 2)

    # ----------------------------------------------------------------- #
    # hide / unhide / delete
    # ----------------------------------------------------------------- #
    def test_hide_and_unhide_request_shape(self):
        for tool, action in (
            (self.module.hide_hosts, "hide_host"),
            (self.module.unhide_hosts, "unhide_host"),
        ):
            with self.subTest(action=action):
                self.mock_client.command.reset_mock()
                self.mock_client.command.return_value = self._action_response([self.AID_1])

                result = tool(ids=[self.AID_1])

                self.mock_client.command.assert_called_once_with(
                    "PerformActionV2",
                    parameters={"action_name": action},
                    body={"ids": [self.AID_1]},
                )
                self.assertEqual(result["succeeded_ids"], [self.AID_1])

    def test_delete_hosts_sends_ids_only(self):
        """The endpoint also takes a filter; the tool never sends one."""
        self.mock_client.command.return_value = self._action_response([self.AID_1, self.AID_2])

        result = self.module.delete_hosts(ids=[self.AID_1, self.AID_2])

        self.mock_client.command.assert_called_once_with(
            "DevicesActionsDeleteV1", body={"ids": [self.AID_1, self.AID_2]}
        )
        self.assertEqual(result["action"], "delete")
        self.assertEqual(result["succeeded_ids"], [self.AID_1, self.AID_2])
        self.assertNotIn("partial_failure", result)

    def test_delete_hosts_without_confirmation_is_not_reported_as_success(self):
        self.mock_client.command.return_value = {"status_code": 202, "body": {"resources": []}}

        result = self.module.delete_hosts(ids=[self.AID_1])

        self.assertEqual(result["succeeded_ids"], [])
        self.assertEqual(result["failed_ids"], [self.AID_1])
        self.assertTrue(result["partial_failure"])

    def test_host_writes_reject_bad_ids_without_calling_api(self):
        for tool in (self.module.hide_hosts, self.module.unhide_hosts, self.module.delete_hosts):
            for ids in ([], ["WORKSTATION-01"], [f"{i:032x}" for i in range(101)]):
                with self.subTest(tool=tool.__name__, count=len(ids)):
                    self.mock_client.command.reset_mock()
                    self.assertIn("error", tool(ids=ids))
                    self.mock_client.command.assert_not_called()

    def test_delete_hosts_forbidden(self):
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied"}]},
        }

        result = self.module.delete_hosts(ids=[self.AID_1])

        self.assertIn("error", result)
        self.assertIn("required_scopes", result)


if __name__ == "__main__":
    unittest.main()
