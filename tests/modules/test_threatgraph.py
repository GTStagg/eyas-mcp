"""
Tests for the Threat Graph module.
"""

import unittest

from falcon_mcp.modules.base import READ_ONLY_ANNOTATIONS
from falcon_mcp.modules.threatgraph import VERTEX_TYPES, ThreatGraphModule
from tests.modules.utils.test_modules import TestModules

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
PROCESS_VERTEX = "pid:0123456789abcdef0123456789abcdef:123456789012"


def _ok(resources, meta=None):
    body = {"resources": resources}
    if meta is not None:
        body["meta"] = meta
    return {"status_code": 200, "body": body}


class TestThreatGraphModule(TestModules):
    """Test cases for the Threat Graph module."""

    def setUp(self):
        self.setup_module(ThreatGraphModule)

    # Registration

    def test_register_tools(self):
        self.assert_tools_registered(
            [
                "falcon_get_threatgraph_summary",
                "falcon_get_threatgraph_ran_on",
                "falcon_get_threatgraph_edges",
                "falcon_list_threatgraph_edge_types",
            ]
        )

    def test_tools_are_read_only(self):
        self.module.register_tools(self.mock_server)
        for name in self.module.tools:
            self.assert_tool_annotations(name, READ_ONLY_ANNOTATIONS)

    def test_register_resources(self):
        self.assert_resources_registered(["falcon_threatgraph_guide"])

    def test_vertex_types_loaded_from_falconpy(self):
        self.assertIn("domain", VERTEX_TYPES)
        self.assertIn("any-vertex", VERTEX_TYPES)
        self.assertNotIn("sha256", VERTEX_TYPES)

    # Summary

    def test_summary_process_vertex(self):
        record = {"id": PROCESS_VERTEX, "vertex_type": "process", "edges": {}}
        self.mock_client.command.return_value = _ok([record])

        result = self.module.get_threatgraph_summary(
            ids=[PROCESS_VERTEX + " "], vertex_type="Processes", scope="device", nano=False
        )

        self.mock_client.command.assert_called_once_with(
            "combined_summary_get",
            vertex_type="processes",
            parameters={"ids": [PROCESS_VERTEX], "scope": "device"},
        )
        self.assertEqual(result, [record])

    def test_summary_process_with_nano(self):
        self.mock_client.command.return_value = _ok([])

        result = self.module.get_threatgraph_summary(
            ids=[PROCESS_VERTEX], vertex_type="process", scope="device", nano=True
        )

        self.mock_client.command.assert_called_once_with(
            "combined_summary_get",
            vertex_type="process",
            parameters={"ids": [PROCESS_VERTEX], "scope": "device", "nano": True},
        )
        self.assertEqual(result, [])

    def test_summary_rejects_hash_type(self):
        result = self.module.get_threatgraph_summary(
            ids=[SHA256], vertex_type="sha256", scope="device", nano=False
        )
        self.assertIn("falcon_get_threatgraph_ran_on", result[0]["error"])
        self.mock_client.command.assert_not_called()

    def test_summary_rejects_unknown_and_malformed_vertex_types(self):
        for vertex_type in ("not_a_type", "domain/../x", "domain?x=1", ""):
            result = self.module.get_threatgraph_summary(
                ids=["example.com"], vertex_type=vertex_type, scope="device", nano=False
            )
            self.assertIn("Unknown vertex type", result[0]["error"], vertex_type)
        self.mock_client.command.assert_not_called()

    def test_summary_does_not_shape_check_network_values(self):
        """Raw domain/IP values go to the API, which rejects them with its own error."""
        self.mock_client.command.return_value = {
            "status_code": 400,
            "body": {"errors": [{"message": "Invalid id 'example.com'."}]},
        }
        result = self.module.get_threatgraph_summary(
            ids=["example.com"], vertex_type="domain", scope="device", nano=False
        )
        self.mock_client.command.assert_called_once()
        self.assertIn("Invalid id", result[0]["error"])

    def test_summary_validates_ids_and_scope(self):
        bad = [
            {"ids": [], "scope": "device"},
            {"ids": ["a"] * 101, "scope": "device"},
            {"ids": ["has space"], "scope": "device"},
            {"ids": ["ok"], "scope": "global"},
        ]
        for kwargs in bad:
            result = self.module.get_threatgraph_summary(
                vertex_type="any-vertex", nano=False, **kwargs
            )
            self.assertIn("error", result[0])
        self.mock_client.command.assert_not_called()

    def test_summary_api_error(self):
        self.mock_client.command.return_value = {
            "status_code": 400,
            "body": {"errors": [{"message": "invalid or unsupported vertex type"}]},
        }
        result = self.module.get_threatgraph_summary(
            ids=["203.0.113.7"], vertex_type="ipv4", scope="device", nano=False
        )
        self.assertEqual(len(result), 1)
        self.assertIn("Failed to get Threat Graph summary", result[0]["error"])

    # Ran on

    def test_ran_on_hash(self):
        resources = [{"device_id": "abc", "edge_type": "ran_on"}]
        self.mock_client.command.return_value = _ok(
            resources, meta={"paging": {"next": "cursor-2"}}
        )

        result = self.module.get_threatgraph_ran_on(
            value=SHA256.upper(), indicator_type="sha256", limit=50, offset=None, nano=False
        )

        self.mock_client.command.assert_called_once_with(
            "combined_ran_on_get",
            parameters={"value": SHA256.upper(), "type": "sha256", "limit": 50},
        )
        self.assertEqual(result["results"], resources)
        self.assertEqual(result["pagination"], {"next": "cursor-2"})

    def test_ran_on_passes_offset_and_nano(self):
        self.mock_client.command.return_value = _ok([])

        result = self.module.get_threatgraph_ran_on(
            value="d41d8cd98f00b204e9800998ecf8427e",
            indicator_type="md5",
            limit=100,
            offset="cursor-2",
            nano=True,
        )

        self.mock_client.command.assert_called_once_with(
            "combined_ran_on_get",
            parameters={
                "value": "d41d8cd98f00b204e9800998ecf8427e",
                "type": "md5",
                "limit": 100,
                "offset": "cursor-2",
                "nano": True,
            },
        )
        self.assertEqual(result, {"results": [], "pagination": {"next": None}})

    def test_ran_on_validation(self):
        bad = [
            {"value": SHA256, "indicator_type": "sha512"},
            {"value": SHA256[:-1], "indicator_type": "sha256"},
            {"value": "z" * 40, "indicator_type": "sha1"},
            {"value": SHA256, "indicator_type": "md5"},
            {"value": "", "indicator_type": "sha256"},
            {"value": "bad domain", "indicator_type": "domain"},
            {"value": "1.2.3", "indicator_type": "ipv4"},
            {"value": SHA256, "indicator_type": "sha256", "limit": 0},
            {"value": SHA256, "indicator_type": "sha256", "limit": 101},
            {"value": SHA256, "indicator_type": "sha256", "offset": "a b"},
        ]
        for kwargs in bad:
            args = {"limit": 100, "offset": None, "nano": False, **kwargs}
            result = self.module.get_threatgraph_ran_on(**args)
            self.assertIn("error", result, kwargs)
        self.mock_client.command.assert_not_called()

    def test_ran_on_network_error_adds_hint(self):
        self.mock_client.command.return_value = {
            "status_code": 400,
            "body": {"errors": [{"message": "bad request"}]},
        }
        result = self.module.get_threatgraph_ran_on(
            value="example.com", indicator_type="domain", limit=10, offset=None, nano=False
        )
        self.assertIn("error", result)
        self.assertIn("falcon_get_threatgraph_edges", result["hint"])

    def test_ran_on_hash_error_has_no_hint(self):
        self.mock_client.command.return_value = {"status_code": 500, "body": {}}
        result = self.module.get_threatgraph_ran_on(
            value=SHA256, indicator_type="sha256", limit=10, offset=None, nano=False
        )
        self.assertIn("error", result)
        self.assertNotIn("hint", result)

    def test_ran_on_not_found_is_empty_result(self):
        self.mock_client.command.return_value = {
            "status_code": 404,
            "body": {
                "errors": [
                    {
                        "code": 404,
                        "message": "resource not found or may no longer exist as it has "
                        "passed your default retention period",
                    }
                ]
            },
        }
        result = self.module.get_threatgraph_ran_on(
            value=SHA256, indicator_type="sha256", limit=10, offset=None, nano=False
        )
        self.assertEqual(
            result,
            {
                "results": [],
                "pagination": {"next": None},
                "note": "No devices in this tenant ran this indicator within the retention period.",
            },
        )

    def test_ran_on_other_404_is_error(self):
        self.mock_client.command.return_value = {
            "status_code": 404,
            "body": {"errors": [{"message": "route does not exist"}]},
        }
        result = self.module.get_threatgraph_ran_on(
            value=SHA256, indicator_type="sha256", limit=10, offset=None, nano=False
        )
        self.assertIn("error", result)
        self.assertNotIn("note", result)

    def test_ran_on_not_found_text_on_other_status_is_error(self):
        self.mock_client.command.return_value = {
            "status_code": 400,
            "body": {"errors": [{"message": "resource not found"}]},
        }
        result = self.module.get_threatgraph_ran_on(
            value=SHA256, indicator_type="sha256", limit=10, offset=None, nano=False
        )
        self.assertIn("error", result)

    # Edges

    def test_edges(self):
        resources = [{"source_vertex_id": PROCESS_VERTEX, "target_vertex_id": "pid:x:2"}]
        self.mock_client.command.return_value = _ok(resources)

        result = self.module.get_threatgraph_edges(
            vertex_id=PROCESS_VERTEX,
            edge_type="child_process",
            direction="out",
            scope="device",
            limit=25,
            offset=None,
            nano=False,
        )

        self.mock_client.command.assert_called_once_with(
            "combined_edges_get",
            parameters={
                "ids": PROCESS_VERTEX,
                "edge_type": "child_process",
                "direction": "out",
                "scope": "device",
                "limit": 25,
            },
        )
        self.assertEqual(result, {"results": resources, "pagination": {"next": None}})

    def test_edges_omits_direction_for_both(self):
        self.mock_client.command.return_value = _ok([], meta={"pagination": {"after": "c3"}})

        result = self.module.get_threatgraph_edges(
            vertex_id=PROCESS_VERTEX,
            edge_type="dns_request",
            direction=None,
            scope="customer",
            limit=100,
            offset="c2",
            nano=True,
        )

        params = self.mock_client.command.call_args.kwargs["parameters"]
        self.assertNotIn("direction", params)
        self.assertEqual(params["offset"], "c2")
        self.assertTrue(params["nano"])
        self.assertEqual(result["pagination"], {"next": "c3"})

    def test_edges_validation(self):
        bad = [
            {"vertex_id": ""},
            {"vertex_id": "a\nb"},
            {"vertex_id": "x" * 1025},
            {"edge_type": "Child_Process"},
            {"edge_type": "child process"},
            {"edge_type": "child_process&limit=1"},
            {"edge_type": ""},
            {"direction": "any"},
            {"scope": "global"},
            {"limit": 1000},
            {"offset": "a b"},
        ]
        for kwargs in bad:
            args = {
                "vertex_id": PROCESS_VERTEX,
                "edge_type": "child_process",
                "direction": None,
                "scope": "device",
                "limit": 100,
                "offset": None,
                "nano": False,
                **kwargs,
            }
            result = self.module.get_threatgraph_edges(**args)
            self.assertIn("error", result, kwargs)
        self.mock_client.command.assert_not_called()

    def test_edges_api_error(self):
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied"}]},
        }
        result = self.module.get_threatgraph_edges(
            vertex_id=PROCESS_VERTEX,
            edge_type="child_process",
            direction=None,
            scope="device",
            limit=100,
            offset=None,
            nano=False,
        )
        self.assertIn("Failed to get Threat Graph edges", result["error"])

    # Edge types

    def test_list_edge_types(self):
        self.mock_client.command.return_value = _ok(["child_process", "dns_request"])

        result = self.module.list_threatgraph_edge_types()

        self.mock_client.command.assert_called_once_with("queries_edgetypes_get")
        self.assertEqual(result, ["child_process", "dns_request"])

    def test_list_edge_types_error(self):
        self.mock_client.command.return_value = {"status_code": 500, "body": {}}
        result = self.module.list_threatgraph_edge_types()
        self.assertEqual(len(result), 1)
        self.assertIn("error", result[0])


if __name__ == "__main__":
    unittest.main()
