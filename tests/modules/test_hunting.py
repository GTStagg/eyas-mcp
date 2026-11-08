"""
Tests for the Hunting module.
"""

import unittest
from unittest.mock import call

from falcon_mcp.modules.base import READ_ONLY_ANNOTATIONS
from falcon_mcp.modules.hunting import HuntingModule
from falcon_mcp.resources.hunting import (
    SEARCH_HUNTING_GUIDES_FQL_DOCUMENTATION,
    SEARCH_HUNTING_QUERIES_FQL_DOCUMENTATION,
)
from tests.modules.utils.test_modules import TestModules

_TOOLS = [
    "falcon_search_hunting_guides",
    "falcon_get_hunting_guides",
    "falcon_search_hunting_queries",
    "falcon_get_hunting_queries",
]


def _ok(resources, total=None):
    body = {"resources": resources}
    if total is not None:
        body["meta"] = {"pagination": {"total": total, "offset": 0, "limit": 10}}
    return {"status_code": 200, "body": body}


def _error(status_code, message="bad request"):
    return {"status_code": status_code, "body": {"errors": [{"message": message}]}}


class TestHuntingModule(TestModules):
    """Test cases for the Hunting module."""

    def setUp(self):
        """Set up test fixtures."""
        self.setup_module(HuntingModule)

    # --- Registration ---

    def test_register_tools(self):
        """Every hunting tool is registered."""
        self.assert_tools_registered(_TOOLS)

    def test_tools_are_read_only(self):
        """Every hunting tool uses the default read-only annotations."""
        self.module.register_tools(self.mock_server)
        for tool in _TOOLS:
            self.assert_tool_annotations(tool, READ_ONLY_ANNOTATIONS)

    def test_register_resources(self):
        """Both FQL guides are registered."""
        self.assert_resources_registered(
            [
                "falcon_search_hunting_guides_fql_guide",
                "falcon_search_hunting_queries_fql_guide",
            ]
        )

    # --- search_hunting_guides ---

    def test_search_guides_searches_then_hydrates_in_order(self):
        """IDs from the search are fetched as query parameters and keep their order."""
        self.mock_client.command.side_effect = [
            _ok(["g2", "g1"], total=2),
            _ok([{"id": "g1", "name": "One"}, {"id": "g2", "name": "Two"}]),
        ]

        result = self.module.search_hunting_guides(
            q="mimikatz", filter=None, limit=5, offset=None, sort="name.asc", max_text_chars=1000
        )

        self.assertEqual(
            self.mock_client.command.call_args_list,
            [
                call(
                    "SearchHuntingGuides",
                    parameters={"q": "mimikatz", "limit": 5, "sort": "name.asc"},
                ),
                call("GetHuntingGuides", parameters={"ids": ["g2", "g1"]}),
            ],
        )
        self.assertEqual([r["id"] for r in result["results"]], ["g2", "g1"])
        self.assert_pagination(result, total=2)

    def test_search_guides_empty_skips_hydration(self):
        """No matching IDs returns an empty envelope without a second call."""
        self.mock_client.command.return_value = _ok([], total=0)

        result = self.module.search_hunting_guides(
            q=None, filter="name:~'x'", limit=5, offset=None, sort=None, max_text_chars=1000
        )

        self.mock_client.command.assert_called_once()
        self.assertEqual(result["results"], [])
        self.assertEqual(result["filter_used"], "name:~'x'")
        self.assert_pagination(result, total=0)

    def test_search_guides_clips_long_text(self):
        """Long text in a guide is cut to max_text_chars with a marker."""
        self.mock_client.command.side_effect = [
            _ok(["g1"]),
            _ok([{"id": "g1", "content": "a" * 1500, "tags": ["short"]}]),
        ]

        result = self.module.search_hunting_guides(
            q="x", filter=None, limit=5, offset=None, sort=None, max_text_chars=1000
        )

        content = result["results"][0]["content"]
        self.assertTrue(content.startswith("a" * 1000))
        self.assertIn("[truncated: 500 more characters", content)
        self.assertEqual(result["results"][0]["tags"], ["short"])

    def test_search_guides_filter_400_returns_guide(self):
        """A 400 on a filtered search returns the FQL guide."""
        self.mock_client.command.return_value = _error(400, "unknown property")

        result = self.module.search_hunting_guides(
            q=None, filter="bogus:'x'", limit=5, offset=None, sort=None, max_text_chars=1000
        )

        self.assertEqual(result["fql_guide"], SEARCH_HUNTING_GUIDES_FQL_DOCUMENTATION)
        self.assertEqual(result["filter_used"], "bogus:'x'")
        self.assertIn("error", result["results"][0])

    def test_search_guides_400_without_filter_omits_guide(self):
        """A 400 without a filter is not blamed on FQL."""
        self.mock_client.command.return_value = _error(400, "bad sort")

        result = self.module.search_hunting_guides(
            q=None, filter=None, limit=5, offset=None, sort="nope.asc", max_text_chars=1000
        )

        self.assertIn("error", result)
        self.assertNotIn("fql_guide", result)

    def test_search_guides_scope_error(self):
        """A 403 surfaces as a plain error without the FQL guide."""
        self.mock_client.command.return_value = _error(403, "access denied")

        result = self.module.search_hunting_guides(
            q=None, filter="name:'x'", limit=5, offset=None, sort=None, max_text_chars=1000
        )

        self.assertIn("error", result)
        self.assertNotIn("fql_guide", result)

    def test_search_guides_hydration_error(self):
        """An error fetching the guides is returned as is."""
        self.mock_client.command.side_effect = [_ok(["g1"]), _error(500, "boom")]

        result = self.module.search_hunting_guides(
            q="x", filter=None, limit=5, offset=None, sort=None, max_text_chars=1000
        )

        self.assertIn("error", result)

    # --- get_hunting_guides ---

    def test_get_guides(self):
        """Guides are fetched by ID as query parameters and clipped."""
        self.mock_client.command.return_value = _ok([{"id": "g1", "content": "b" * 600}])

        result = self.module.get_hunting_guides(ids=["g1"], max_text_chars=500)

        self.mock_client.command.assert_called_once_with(
            "GetHuntingGuides", parameters={"ids": ["g1"]}
        )
        self.assertIn("[truncated: 100 more characters", result[0]["content"])

    def test_get_guides_error(self):
        """An API error is returned as an error dict."""
        self.mock_client.command.return_value = _error(404, "not found")

        result = self.module.get_hunting_guides(ids=["missing"], max_text_chars=500)

        self.assertIn("error", result)

    # --- search_hunting_queries ---

    def test_search_queries_forwards_translation(self):
        """include_translated_content goes to the get call, not the search."""
        self.mock_client.command.side_effect = [
            _ok(["q1"], total=1),
            _ok([{"id": "q1", "content": "#event_simpleName=ProcessRollup2"}]),
        ]

        result = self.module.search_hunting_queries(
            q="rundll32",
            filter="language:'cql'",
            limit=10,
            offset=20,
            sort=None,
            include_translated_content="SPL",
            max_text_chars=1000,
        )

        self.assertEqual(
            self.mock_client.command.call_args_list,
            [
                call(
                    "SearchIntelligenceQueries",
                    parameters={
                        "q": "rundll32",
                        "filter": "language:'cql'",
                        "limit": 10,
                        "offset": 20,
                    },
                ),
                call(
                    "GetIntelligenceQueries",
                    parameters={"ids": ["q1"], "include_translated_content": "SPL"},
                ),
            ],
        )
        self.assertEqual(result["results"][0]["id"], "q1")
        self.assertEqual(result["filter_used"], "language:'cql'")

    def test_search_queries_omits_unset_translation(self):
        """Without a translation request the get call sends only IDs."""
        self.mock_client.command.side_effect = [_ok(["q1"]), _ok([{"id": "q1"}])]

        self.module.search_hunting_queries(
            q="x",
            filter=None,
            limit=10,
            offset=None,
            sort=None,
            include_translated_content=None,
            max_text_chars=1000,
        )

        self.assertEqual(
            self.mock_client.command.call_args_list[1],
            call("GetIntelligenceQueries", parameters={"ids": ["q1"]}),
        )

    def test_search_queries_filter_400_returns_guide(self):
        """A 400 on a filtered query search returns the queries FQL guide."""
        self.mock_client.command.return_value = _error(400)

        result = self.module.search_hunting_queries(
            q=None,
            filter="bogus:'x'",
            limit=10,
            offset=None,
            sort=None,
            include_translated_content=None,
            max_text_chars=1000,
        )

        self.assertEqual(result["fql_guide"], SEARCH_HUNTING_QUERIES_FQL_DOCUMENTATION)

    # --- get_hunting_queries ---

    def test_get_queries(self):
        """Queries are fetched by ID with the translation option."""
        self.mock_client.command.return_value = _ok([{"id": "q1"}, {"id": "q2"}])

        result = self.module.get_hunting_queries(
            ids=["q1", "q2"], include_translated_content="__all__", max_text_chars=1000
        )

        self.mock_client.command.assert_called_once_with(
            "GetIntelligenceQueries",
            parameters={"ids": ["q1", "q2"], "include_translated_content": "__all__"},
        )
        self.assertEqual(len(result), 2)

    def test_get_queries_error(self):
        """An API error is returned as an error dict."""
        self.mock_client.command.return_value = _error(403, "denied")

        result = self.module.get_hunting_queries(
            ids=["q1"], include_translated_content=None, max_text_chars=1000
        )

        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
