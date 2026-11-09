"""
Unit tests for the Discover module.
"""

import unittest
from unittest.mock import MagicMock

from mcp.server import FastMCP

from falcon_mcp.client import FalconClient
from falcon_mcp.modules.base import READ_ONLY_ANNOTATIONS
from falcon_mcp.modules.discover import DiscoverModule
from falcon_mcp.resources.discover import SEARCH_ACCOUNTS_FQL_DOCUMENTATION


class TestDiscoverModule(unittest.TestCase):
    """Test cases for the Discover module."""

    def setUp(self):
        """Set up test fixtures."""
        self.client = MagicMock(spec=FalconClient)
        self.module = DiscoverModule(self.client)
        self.server = MagicMock(spec=FastMCP)

    def test_register_tools(self):
        """Test that tools are registered correctly."""
        self.module.register_tools(self.server)
        self.assertEqual(self.server.add_tool.call_count, 4)
        self.assertEqual(len(self.module.tools), 4)
        self.assertEqual(self.module.tools[0], "falcon_search_applications")
        self.assertEqual(self.module.tools[1], "falcon_search_unmanaged_assets")
        self.assertEqual(self.module.tools[2], "falcon_search_managed_assets")
        self.assertEqual(self.module.tools[3], "falcon_search_accounts")
        for call in self.server.add_tool.call_args_list:
            self.assertEqual(call.kwargs["annotations"], READ_ONLY_ANNOTATIONS)

    def test_register_resources(self):
        """Test that resources are registered correctly."""
        self.module.register_resources(self.server)
        self.assertEqual(self.server.add_resource.call_count, 4)
        self.assertEqual(len(self.module.resources), 4)
        self.assertEqual(
            str(self.module.resources[0]), "falcon://discover/applications/fql-guide"
        )
        self.assertEqual(
            str(self.module.resources[1]), "falcon://discover/hosts/fql-guide"
        )
        self.assertEqual(
            str(self.module.resources[2]),
            "falcon://discover/managed-assets/fql-guide",
        )
        self.assertEqual(str(self.module.resources[3]), "falcon://discover/accounts/fql-guide")

    def test_search_applications(self):
        """Test search_applications method."""
        mock_response = {
            "status_code": 200,
            "body": {
                "meta": {"pagination": {"offset": 0, "limit": 100, "total": 1}},
                "resources": [{"id": "app1", "name": "Chrome"}],
            },
        }
        self.client.command.return_value = mock_response

        result = self.module.search_applications(filter="name:'Chrome'")

        first_call = self.client.command.call_args_list[0]
        self.assertEqual(first_call[0][0], "combined_applications")
        self.assertEqual(first_call[1]["parameters"]["filter"], "name:'Chrome'")
        self.assertEqual(result["results"], [{"id": "app1", "name": "Chrome"}])
        self.assertEqual(result["pagination"]["total"], 1)
        self.assertEqual(result["filter_used"], "name:'Chrome'")

    def test_search_applications_with_error(self):
        """Test search_applications method when an error occurs."""
        mock_response = {
            "status_code": 400,
            "body": {"errors": [{"message": "Something went wrong"}]},
        }
        self.client.command.return_value = mock_response

        result = self.module.search_applications(filter="name:'Chrome'")

        self.assertIsInstance(result, list)
        self.assertIn("error", result[0])

    def test_search_applications_with_all_params(self):
        """Test search_applications method with all parameters."""
        mock_response = {
            "status_code": 200,
            "body": {
                "meta": {"pagination": {"offset": 0, "limit": 50, "total": 1}},
                "resources": [{"id": "app1", "name": "Chrome"}],
            },
        }
        self.client.command.return_value = mock_response

        result = self.module.search_applications(
            filter="name:'Chrome'",
            facet="host_info",
            limit=50,
            sort="name.asc",
        )

        first_call = self.client.command.call_args_list[0]
        self.assertEqual(first_call[0][0], "combined_applications")
        params = first_call[1]["parameters"]
        self.assertEqual(params["filter"], "name:'Chrome'")
        self.assertEqual(params["facet"], "host_info")
        self.assertEqual(params["limit"], 50)
        self.assertEqual(params["sort"], "name.asc")
        self.assertEqual(result["results"], [{"id": "app1", "name": "Chrome"}])

    def test_search_unmanaged_assets(self):
        """Test search_unmanaged_assets method."""
        mock_response = {
            "status_code": 200,
            "body": {
                "meta": {"pagination": {"offset": 0, "limit": 100, "total": 1}},
                "resources": [{"device_id": "host1", "hostname": "PC-001"}],
            },
        }
        self.client.command.return_value = mock_response

        result = self.module.search_unmanaged_assets(filter="platform_name:'Windows'")

        first_call = self.client.command.call_args_list[0]
        self.assertEqual(first_call[0][0], "combined_hosts")
        self.assertEqual(
            first_call[1]["parameters"]["filter"],
            "entity_type:'unmanaged'+platform_name:'Windows'",
        )
        self.assertEqual(
            result["results"], [{"device_id": "host1", "hostname": "PC-001"}]
        )

    def test_search_unmanaged_assets_without_filter(self):
        """Test search_unmanaged_assets method without user filter."""
        mock_response = {
            "status_code": 200,
            "body": {
                "meta": {"pagination": {"offset": 0, "limit": 100, "total": 1}},
                "resources": [{"device_id": "host1", "hostname": "PC-001"}],
            },
        }
        self.client.command.return_value = mock_response

        result = self.module.search_unmanaged_assets(filter=None)

        first_call = self.client.command.call_args_list[0]
        self.assertEqual(first_call[0][0], "combined_hosts")
        self.assertEqual(
            first_call[1]["parameters"]["filter"], "entity_type:'unmanaged'"
        )
        self.assertEqual(
            result["results"], [{"device_id": "host1", "hostname": "PC-001"}]
        )

    def test_search_unmanaged_assets_with_error(self):
        """Test search_unmanaged_assets method when an error occurs."""
        mock_response = {
            "status_code": 400,
            "body": {"errors": [{"message": "Something went wrong"}]},
        }
        self.client.command.return_value = mock_response

        result = self.module.search_unmanaged_assets(filter="platform_name:'Windows'")

        self.assertIsInstance(result, list)
        self.assertIn("error", result[0])

    def test_search_unmanaged_assets_with_all_params(self):
        """Test search_unmanaged_assets method with all parameters."""
        mock_response = {
            "status_code": 200,
            "body": {
                "meta": {"pagination": {"offset": 10, "limit": 50, "total": 1}},
                "resources": [{"device_id": "host1", "hostname": "PC-001"}],
            },
        }
        self.client.command.return_value = mock_response

        result = self.module.search_unmanaged_assets(
            filter="criticality:'Critical'",
            limit=50,
            offset=10,
            sort="hostname.asc",
        )

        first_call = self.client.command.call_args_list[0]
        self.assertEqual(first_call[0][0], "combined_hosts")
        params = first_call[1]["parameters"]
        self.assertEqual(
            params["filter"], "entity_type:'unmanaged'+criticality:'Critical'"
        )
        self.assertEqual(params["limit"], 50)
        self.assertEqual(params["offset"], 10)
        self.assertEqual(params["sort"], "hostname.asc")
        self.assertEqual(
            result["results"], [{"device_id": "host1", "hostname": "PC-001"}]
        )

    def test_search_managed_assets(self):
        """Test search_managed_assets method enforces entity_type:'managed'."""
        mock_response = {
            "status_code": 200,
            "body": {
                "meta": {"pagination": {"offset": 0, "limit": 100, "total": 1}},
                "resources": [
                    {"id": "host1", "encryption_status": "Unencrypted"}
                ],
            },
        }
        self.client.command.return_value = mock_response

        result = self.module.search_managed_assets(
            filter="encryption_status:'Unencrypted'"
        )

        first_call = self.client.command.call_args_list[0]
        self.assertEqual(first_call[0][0], "combined_hosts")
        self.assertEqual(
            first_call[1]["parameters"]["filter"],
            "entity_type:'managed'+encryption_status:'Unencrypted'",
        )
        self.assertEqual(
            result["results"], [{"id": "host1", "encryption_status": "Unencrypted"}]
        )
        self.assertEqual(result["pagination"]["total"], 1)
        self.assertEqual(result["filter_used"], "encryption_status:'Unencrypted'")

    def test_search_managed_assets_without_filter(self):
        """Test search_managed_assets method without user filter."""
        mock_response = {
            "status_code": 200,
            "body": {
                "meta": {"pagination": {"offset": 0, "limit": 100, "total": 1}},
                "resources": [{"id": "host1", "hostname": "PC-001"}],
            },
        }
        self.client.command.return_value = mock_response

        result = self.module.search_managed_assets(filter=None)

        first_call = self.client.command.call_args_list[0]
        self.assertEqual(first_call[0][0], "combined_hosts")
        self.assertEqual(
            first_call[1]["parameters"]["filter"], "entity_type:'managed'"
        )
        self.assertEqual(result["results"], [{"id": "host1", "hostname": "PC-001"}])

    def test_search_managed_assets_with_error(self):
        """Test search_managed_assets returns the FQL guide when an error occurs."""
        mock_response = {
            "status_code": 400,
            "body": {"errors": [{"message": "property foo not allowed"}]},
        }
        self.client.command.return_value = mock_response

        result = self.module.search_managed_assets(filter="foo:'bar'")

        # combined_hosts 400s loudly on a bad filter field, so the tool attaches the
        # FQL guide instead of returning a bare error.
        self.assertIsInstance(result, dict)
        self.assertIn("fql_guide", result)
        self.assertEqual(result["filter_used"], "foo:'bar'")
        self.assertIn("error", result["results"][0])

    def test_search_managed_assets_with_all_params(self):
        """Test search_managed_assets method with all parameters."""
        mock_response = {
            "status_code": 200,
            "body": {
                "meta": {"pagination": {"offset": 10, "limit": 50, "total": 1}},
                "resources": [{"id": "host1", "hostname": "PC-001"}],
            },
        }
        self.client.command.return_value = mock_response

        result = self.module.search_managed_assets(
            filter="criticality:'Critical'",
            limit=50,
            offset=10,
            sort="hostname.asc",
        )

        first_call = self.client.command.call_args_list[0]
        self.assertEqual(first_call[0][0], "combined_hosts")
        params = first_call[1]["parameters"]
        self.assertEqual(
            params["filter"], "entity_type:'managed'+criticality:'Critical'"
        )
        self.assertEqual(params["limit"], 50)
        self.assertEqual(params["offset"], 10)
        self.assertEqual(params["sort"], "hostname.asc")
        self.assertEqual(result["results"], [{"id": "host1", "hostname": "PC-001"}])

    def test_search_accounts(self):
        """search_accounts queries IDs, then hydrates them in query order."""
        self.client.command.side_effect = [
            {
                "status_code": 200,
                "body": {
                    "meta": {"pagination": {"offset": 0, "limit": 2, "total": 7}},
                    "resources": ["acct2", "acct1"],
                },
            },
            {
                "status_code": 200,
                "body": {
                    "resources": [
                        {"id": "acct1", "username": "alice"},
                        {"id": "acct2", "username": "bob"},
                    ]
                },
            },
        ]

        result = self.module.search_accounts(
            filter="admin_privileges:'Yes'",
            limit=2,
            offset=0,
            sort="username|desc",
        )

        query_call, get_call = self.client.command.call_args_list
        self.assertEqual(query_call[0][0], "query_accounts")
        self.assertEqual(
            query_call[1]["parameters"],
            {
                "filter": "admin_privileges:'Yes'",
                "limit": 2,
                "offset": 0,
                "sort": "username|desc",
            },
        )
        self.assertEqual(get_call[0][0], "get_accounts")
        self.assertEqual(get_call[1]["parameters"], {"ids": ["acct2", "acct1"]})
        self.assertEqual(
            result["results"],
            [{"id": "acct2", "username": "bob"}, {"id": "acct1", "username": "alice"}],
        )
        self.assertEqual(result["pagination"]["total"], 7)
        self.assertEqual(result["filter_used"], "admin_privileges:'Yes'")

    def test_search_accounts_no_results(self):
        """No matching IDs skips hydration and returns an empty envelope."""
        self.client.command.return_value = {
            "status_code": 200,
            "body": {
                "meta": {"pagination": {"offset": 0, "limit": 100, "total": 0}},
                "resources": [],
            },
        }

        result = self.module.search_accounts(filter=None, limit=100, offset=None, sort=None)

        self.client.command.assert_called_once_with("query_accounts", parameters={"limit": 100})
        self.assertEqual(result["results"], [])
        self.assertEqual(result["pagination"]["total"], 0)

    def test_search_accounts_query_error_returns_fql_guide(self):
        """A failed query step returns the FQL guide to help fix the filter."""
        self.client.command.return_value = {
            "status_code": 400,
            "body": {"errors": [{"message": "invalid filter"}]},
        }

        result = self.module.search_accounts(
            filter="bogus_field:'x'", limit=100, offset=None, sort=None
        )

        self.assertIn("error", result["results"][0])
        self.assertEqual(result["fql_guide"], SEARCH_ACCOUNTS_FQL_DOCUMENTATION)
        self.assertEqual(result["filter_used"], "bogus_field:'x'")

    def test_search_accounts_hydration_error(self):
        """A failed hydration step returns the error in a list."""
        self.client.command.side_effect = [
            {"status_code": 200, "body": {"resources": ["acct1"]}},
            {"status_code": 403, "body": {"errors": [{"message": "denied"}]}},
        ]

        result = self.module.search_accounts(filter=None, limit=100, offset=None, sort=None)

        self.assertIsInstance(result, list)
        self.assertIn("error", result[0])



def _app(app_id: str, hostname: str = "PC-1") -> dict:
    return {
        "id": app_id,
        "name": f"App {app_id}",
        "vendor": "Vendor",
        "version": "1.0",
        "software_type": "application",
        "is_suspicious": False,
        "installation_paths": ["C:\\App"],
        "last_used_timestamp": "2026-11-09T17:00:00Z",
        "architectures": ["x64"],
        "host": {"id": "h1", "hostname": hostname, "os_version": "Windows 11"},
    }


def _ok(resources: list, total: int | None = None) -> dict:
    body: dict = {"resources": resources}
    if total is not None:
        body["meta"] = {"pagination": {"total": total}}
    return {"status_code": 200, "body": body}


class TestSearchApplicationsWithoutFilter(unittest.TestCase):
    """falcon_search_applications lists every application when no filter is given."""

    def setUp(self):
        self.client = MagicMock(spec=FalconClient)
        self.module = DiscoverModule(self.client)

    def _call(self, **kwargs):
        params = {
            "filter": None,
            "facet": None,
            "limit": 100,
            "sort": None,
            "offset": None,
            "after": None,
            "fields": "full",
        }
        params.update(kwargs)
        return self.module.search_applications(**params)

    def test_uses_query_then_entities(self):
        self.client.command.side_effect = [
            _ok(["a2", "a1"], total=285000),
            _ok([_app("a1"), _app("a2")]),
        ]

        result = self._call(sort="last_used_timestamp.desc")

        calls = self.client.command.call_args_list
        self.assertEqual(calls[0][0][0], "query_applications")
        self.assertEqual(
            calls[0][1]["parameters"],
            {"limit": 100, "offset": 0, "sort": "last_used_timestamp.desc"},
        )
        self.assertNotIn("filter", calls[0][1]["parameters"])
        self.assertEqual(calls[1][0][0], "get_applications")
        self.assertEqual(calls[1][1]["parameters"], {"ids": ["a2", "a1"]})
        # The query step's sort order survives hydration.
        self.assertEqual([row["id"] for row in result["results"]], ["a2", "a1"])
        self.assertEqual(result["pagination"]["total"], 285000)
        self.assertNotIn("filter_used", result)

    def test_empty_filter_string_also_lists_everything(self):
        self.client.command.side_effect = [_ok([], total=0)]
        result = self._call(filter="")
        self.assertEqual(self.client.command.call_args[0][0], "query_applications")
        self.assertEqual(result["results"], [])
        self.assertEqual(result["pagination"]["total"], 0)

    def test_pages_query_and_entities_in_hundreds(self):
        first = [f"a{i}" for i in range(100)]
        second = [f"a{i}" for i in range(100, 150)]
        self.client.command.side_effect = [
            _ok(first, total=1000),
            _ok(second, total=1000),
            _ok([_app(i) for i in first]),
            _ok([_app(i) for i in second]),
        ]

        result = self._call(limit=150, offset=200)

        calls = self.client.command.call_args_list
        self.assertEqual(calls[0][1]["parameters"], {"limit": 100, "offset": 200})
        self.assertEqual(calls[1][1]["parameters"], {"limit": 50, "offset": 300})
        self.assertEqual(len(calls[2][1]["parameters"]["ids"]), 100)
        self.assertEqual(len(calls[3][1]["parameters"]["ids"]), 50)
        self.assertEqual(len(result["results"]), 150)
        self.assertEqual(result["pagination"]["offset"], 200)
        self.assertEqual(result["pagination"]["next_offset"], 350)

    def test_stops_when_query_runs_out(self):
        self.client.command.side_effect = [
            _ok(["a1", "a2"], total=2),
            _ok([_app("a1"), _app("a2")]),
        ]
        result = self._call(limit=500)
        self.assertEqual(self.client.command.call_count, 2)
        self.assertIsNone(result["pagination"]["next_offset"])

    def test_refuses_window_past_query_ceiling(self):
        result = self._call(offset=9950, limit=100)
        self.assertIsInstance(result, list)
        self.assertIn("error", result[0])
        self.client.command.assert_not_called()

    def test_compact_fields(self):
        self.client.command.side_effect = [
            _ok(["a1"], total=1),
            _ok([_app("a1", hostname="WS-9")]),
        ]
        result = self._call(fields="compact")
        self.assertEqual(
            result["results"][0],
            {
                "id": "a1",
                "name": "App a1",
                "vendor": "Vendor",
                "version": "1.0",
                "software_type": "application",
                "is_suspicious": False,
                "installation_paths": ["C:\\App"],
                "last_used_timestamp": "2026-11-09T17:00:00Z",
                "host": {"id": "h1", "hostname": "WS-9"},
            },
        )

    def test_query_error(self):
        self.client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"code": 403, "message": "denied"}]},
        }
        result = self._call()
        self.assertIsInstance(result, list)
        self.assertIn("error", result[0])

    def test_entities_error(self):
        self.client.command.side_effect = [
            _ok(["a1"], total=1),
            {"status_code": 500, "body": {"errors": [{"code": 500, "message": "boom"}]}},
        ]
        result = self._call()
        self.assertIsInstance(result, list)
        self.assertIn("error", result[0])

    def test_filtered_call_passes_after_and_compacts(self):
        self.client.command.return_value = {
            "status_code": 200,
            "body": {
                "meta": {"pagination": {"total": 5, "after": "next-token"}},
                "resources": [_app("a1")],
            },
        }
        result = self._call(filter="name:*'*'", facet="host_info", after="tok", fields="compact")
        params = self.client.command.call_args[1]["parameters"]
        self.assertEqual(self.client.command.call_args[0][0], "combined_applications")
        self.assertEqual(params["after"], "tok")
        self.assertEqual(params["facet"], "host_info")
        self.assertEqual(result["pagination"]["next"], "next-token")
        self.assertEqual(result["results"][0]["host"], {"id": "h1", "hostname": "PC-1"})
        self.assertNotIn("architectures", result["results"][0])


if __name__ == "__main__":
    unittest.main()
