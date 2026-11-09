"""Tests for the local CQL checks."""

import pytest

from falcon_mcp.common.cql_lint import lint_cql


@pytest.mark.parametrize(
    ("query", "rules", "fixed"),
    [
        (
            "#event_simpleName=ProcessRollup2 | limit(5)",
            ["limit_function"],
            "#event_simpleName=ProcessRollup2 | head(5)",
        ),
        (
            "#event_simpleName='ProcessRollup2' | head(5)",
            ["single_quoted_string"],
            '#event_simpleName="ProcessRollup2" | head(5)',
        ),
        (
            "event_simpleName=ProcessRollup2 | head(5)",
            ["missing_tag_prefix"],
            "#event_simpleName=ProcessRollup2 | head(5)",
        ),
        (
            "#repo=base_sensor | event_simpleName!=DnsRequest",
            ["missing_tag_prefix"],
            "#repo=base_sensor | #event_simpleName!=DnsRequest",
        ),
        (
            "#event_simpleName=ProcessRollup2 | groupBy(ImageFileName) | sort(_count)",
            ["sort_without_limit"],
            "#event_simpleName=ProcessRollup2 | groupBy(ImageFileName) | sort(_count, limit=1000)",
        ),
        (
            "#event_simpleName=ProcessRollup2 | sort()",
            ["sort_without_limit"],
            "#event_simpleName=ProcessRollup2 | sort(limit=1000)",
        ),
        (
            "event_simpleName='DnsRequest' | sort(_count) | limit(10)",
            ["limit_function", "single_quoted_string", "missing_tag_prefix", "sort_without_limit"],
            '#event_simpleName="DnsRequest" | sort(_count, limit=1000) | head(10)',
        ),
    ],
)
def test_finds_and_fixes_mistakes(query: str, rules: list[str], fixed: str) -> None:
    issues, suggestion = lint_cql(query)
    assert [issue["rule"] for issue in issues] == rules
    assert suggestion == fixed
    # The suggested query passes its own check.
    assert lint_cql(suggestion)[0] == []


@pytest.mark.parametrize(
    "query",
    [
        "#event_simpleName=ProcessRollup2 | head(5)",
        "#event_simpleName=ProcessRollup2 | groupBy(ImageFileName) | sort(_count, order=desc, limit=50)",
        # Partial regexes are valid: CQL regexes are not anchored.
        "#event_simpleName=ProcessRollup2 | ImageFileName=/svchost/ | head(5)",
        # Text inside strings and regexes is not code.
        "#event_simpleName=ProcessRollup2 | CommandLine=\"*limit(3)* 'x' event_simpleName=a sort(x)\"",
        "#event_simpleName=ProcessRollup2 | ImageFileName=/sort\\(it'/ | head(5)",
        # Dotted and prefixed names are other fields.
        "#repo=base_sensor | aid.event_simpleName=1 | my_repo=x",
    ],
)
def test_leaves_valid_queries_alone(query: str) -> None:
    issues, suggestion = lint_cql(query)
    assert issues == []
    assert suggestion == query
