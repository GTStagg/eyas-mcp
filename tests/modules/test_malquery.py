"""
Tests for the MalQuery module.
"""

import unittest

from falcon_mcp.modules.base import READ_ONLY_ANNOTATIONS
from falcon_mcp.modules.malquery import MalQueryModule
from tests.modules.utils.test_modules import TestModules

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
MD5 = "d41d8cd98f00b204e9800998ecf8427e"
REQUEST_ID = "9f1c2e4a-6b7d-4c8e-9a0b-1c2d3e4f5a6b"


class TestMalQueryModule(TestModules):
    """Test cases for the MalQuery module."""

    def setUp(self):
        """Set up test fixtures."""
        self.setup_module(MalQueryModule)

    def search(self, pattern="evil-c2.example.com", **kwargs):
        """Call start_malquery_exact_search with explicit defaults."""
        args = {
            "pattern_type": "ascii",
            "limit": 100,
            "filter_filetypes": None,
            "filter_meta": None,
            "min_date": None,
            "max_date": None,
            "min_size": None,
            "max_size": None,
        }
        args.update(kwargs)
        return self.module.start_malquery_exact_search(pattern=pattern, **args)

    def test_register_tools(self):
        """Test registering tools with the server."""
        self.assert_tools_registered(
            [
                "falcon_get_malquery_quotas",
                "falcon_get_malquery_file_metadata",
                "falcon_start_malquery_exact_search",
                "falcon_get_malquery_request",
            ]
        )

    def test_register_resources(self):
        """Test registering resources with the server."""
        self.assert_resources_registered(["falcon_malquery_exact_search_guide"])

    def test_tool_annotations(self):
        """All MalQuery tools are read-only."""
        self.module.register_tools(self.mock_server)
        for tool in self.module.tools:
            self.assert_tool_annotations(tool, READ_ONLY_ANNOTATIONS)

    # Quotas

    def test_get_quotas_returns_meta(self):
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {
                "meta": {
                    "query_time": 0.01,
                    "trace_id": "abc",
                    "powered_by": "malquery",
                    "hunt_count": 3,
                    "hunt_limit": 100,
                },
                "resources": [],
                "errors": [],
            },
        }

        result = self.module.get_malquery_quotas()

        self.mock_client.command.assert_called_once_with("GetMalQueryQuotasV1")
        self.assertEqual(
            result, {"quotas": {"query_time": 0.01, "hunt_count": 3, "hunt_limit": 100}}
        )

    def test_get_quotas_error(self):
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied"}]},
        }

        result = self.module.get_malquery_quotas()

        self.assertIn("error", result)
        self.assertIn("Failed to get MalQuery quotas", result["error"])

    # File metadata

    def test_get_file_metadata_success(self):
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"sha256": SHA256, "family": "Test"}]},
        }

        result = self.module.get_malquery_file_metadata(
            hashes=[SHA256.upper(), f" {SHA1} ", MD5, SHA256]
        )

        self.mock_client.command.assert_called_once_with(
            "GetMalQueryMetadataV1",
            parameters={"ids": [SHA256, SHA1, MD5]},
        )
        self.assertEqual(result, [{"sha256": SHA256, "family": "Test"}])

    def test_get_file_metadata_rejects_invalid_hash(self):
        for bad in ["not-a-hash", "abc", SHA256 + "0", "g" * 64, f"{MD5}' or 1=1"]:
            with self.subTest(bad=bad):
                result = self.module.get_malquery_file_metadata(hashes=[SHA256, bad])
                self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_get_file_metadata_rejects_empty_and_too_many(self):
        self.assertIn("error", self.module.get_malquery_file_metadata(hashes=[]))
        self.assertIn("error", self.module.get_malquery_file_metadata(hashes=[MD5] * 101))
        self.mock_client.command.assert_not_called()

    def test_get_file_metadata_error(self):
        self.mock_client.command.return_value = {"status_code": 500, "body": {"errors": []}}

        result = self.module.get_malquery_file_metadata(hashes=[SHA256])

        self.assertIn("error", result)

    # Exact search

    def test_exact_search_minimal_body(self):
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"meta": {"reqid": REQUEST_ID, "status": "inprogress"}, "resources": []},
        }

        result = self.search()

        self.mock_client.command.assert_called_once_with(
            "PostMalQueryExactSearchV1",
            body={
                "patterns": [{"type": "ascii", "value": "evil-c2.example.com"}],
                "options": {"limit": 100},
            },
        )
        self.assertEqual(result["request_id"], REQUEST_ID)
        self.assertEqual(result["status"], "inprogress")

    def test_exact_search_all_options(self):
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"meta": {"reqid": REQUEST_ID, "status": "inprogress"}},
        }

        self.search(
            pattern=" 4D5A90000300 ",
            pattern_type="hex",
            limit=25,
            filter_filetypes=["pe32", "pe64"],
            filter_meta=["sha256", "family"],
            min_date="2024/01/01",
            max_date="2024/12/31",
            min_size="10kb",
            max_size="5MB",
        )

        self.mock_client.command.assert_called_once_with(
            "PostMalQueryExactSearchV1",
            body={
                "patterns": [{"type": "hex", "value": "4d5a90000300"}],
                "options": {
                    "limit": 25,
                    "filter_filetypes": ["pe32", "pe64"],
                    "filter_meta": ["sha256", "family"],
                    "min_date": "2024/01/01",
                    "max_date": "2024/12/31",
                    "min_size": "10KB",
                    "max_size": "5MB",
                },
            },
        )

    def test_exact_search_wide_pattern(self):
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"meta": {"reqid": REQUEST_ID, "status": "inprogress"}},
        }

        self.search(pattern="AsyncRAT", pattern_type="wide")

        body = self.mock_client.command.call_args.kwargs["body"]
        self.assertEqual(body["patterns"], [{"type": "wide", "value": "AsyncRAT"}])

    def test_exact_search_rejects_invalid_input(self):
        cases = [
            {"pattern": ""},
            {"pattern": "   "},
            {"pattern": "abc"},
            {"pattern": "x" * 201},
            {"pattern": "line\nbreak"},
            {"pattern": "café-domain"},
            {"pattern": "regex", "pattern_type": "regex"},
            {"pattern": "4d5", "pattern_type": "hex"},
            {"pattern": "4d", "pattern_type": "hex"},
            {"pattern": "0x4d5a", "pattern_type": "hex"},
            {"pattern": "4d 5a 90", "pattern_type": "hex"},
            {"pattern": "evil-c2.example.com", "limit": 0},
            {"pattern": "evil-c2.example.com", "limit": 1001},
            {"pattern": "evil-c2.example.com", "filter_filetypes": ["PE32; drop"]},
            {"pattern": "evil-c2.example.com", "filter_meta": ["sha256", "password"]},
            {"pattern": "evil-c2.example.com", "min_date": "2024-01-01"},
            {"pattern": "evil-c2.example.com", "max_date": "yesterday"},
            {"pattern": "evil-c2.example.com", "min_size": "10 KB"},
            {"pattern": "evil-c2.example.com", "max_size": "-5MB"},
        ]
        for case in cases:
            with self.subTest(case=case):
                result = self.search(**case)
                self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_exact_search_api_error(self):
        self.mock_client.command.return_value = {
            "status_code": 429,
            "body": {"errors": [{"message": "quota exceeded"}]},
        }

        result = self.search()

        self.assertIn("error", result)
        self.assertIn("quota exceeded", result["error"])

    def test_exact_search_missing_request_id(self):
        self.mock_client.command.return_value = {"status_code": 200, "body": {"meta": {}}}

        result = self.search()

        self.assertIn("error", result)

    # Request polling

    def test_get_request_done(self):
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {
                "meta": {"reqid": REQUEST_ID, "status": "done"},
                "resources": [{"sha256": SHA256, "family": "Test"}],
            },
        }

        result = self.module.get_malquery_request(request_id=f" {REQUEST_ID} ")

        self.mock_client.command.assert_called_once_with(
            "GetMalQueryRequestV1", parameters={"ids": REQUEST_ID}
        )
        self.assertEqual(
            result,
            {
                "request_id": REQUEST_ID,
                "status": "done",
                "results": [{"sha256": SHA256, "family": "Test"}],
            },
        )

    def test_get_request_in_progress(self):
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"meta": {"reqid": REQUEST_ID, "status": "inprogress"}, "resources": []},
        }

        result = self.module.get_malquery_request(request_id=REQUEST_ID)

        self.assertEqual(result["status"], "inprogress")
        self.assertEqual(result["results"], [])

    def test_get_request_rejects_invalid_id(self):
        for bad in ["", "not-a-uuid", REQUEST_ID + "&ids=other", "../" + REQUEST_ID]:
            with self.subTest(bad=bad):
                self.assertIn("error", self.module.get_malquery_request(request_id=bad))
        self.mock_client.command.assert_not_called()

    def test_get_request_error(self):
        self.mock_client.command.return_value = {
            "status_code": 404,
            "body": {"errors": [{"message": "not found"}]},
        }

        result = self.module.get_malquery_request(request_id=REQUEST_ID)

        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
