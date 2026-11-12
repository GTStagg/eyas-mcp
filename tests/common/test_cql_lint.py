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


def _catalog() -> dict:
    from falcon_mcp.modules.ngsiem import _load_cql_catalog

    return _load_cql_catalog()


def test_every_issue_has_a_severity() -> None:
    issues, _ = lint_cql("event_simpleName='x' | sort(a) | limit(1) | lmit(2)", _catalog())
    assert {issue["rule"]: issue["severity"] for issue in issues} == {
        "limit_function": "error",
        "single_quoted_string": "error",
        "missing_tag_prefix": "error",
        "sort_without_limit": "error",
        "unknown_function": "warning",
    }


@pytest.mark.parametrize(
    "query",
    [
        "#event_simpleName=ProcessRollup2 | groupBy([ComputerName], function=count(as=cnt)) "
        "| sort(cnt, order=desc, limit=5)",
        # Namespaced functions.
        'x | array:filter(array="a[]", function={b=1}, var=b) '
        "| bitfield:extractFlags(field=f, output=[[0, A]]) "
        '| text:contains(string=x, substring="y")',
        # Nested calls, assignments, logical groups and saved searches.
        "x | not(a=1 or b=2) | eval(y := lower(z)) | $savedSearch(x=1) | test(a > 1)",
        # Names inside strings, regexes and comments are not calls.
        'x | CommandLine="foo(1)" | ImageFileName=/bar\\(/ | // baz(\n y=1 /* qux( */',
        # A space before a parenthesis is not read as a call.
        "x | y = 1 (z)",
    ],
)
def test_known_functions_pass_cleanly(query: str) -> None:
    assert lint_cql(query, _catalog()) == ([], query)


def test_unknown_function_is_a_warning_with_suggestions() -> None:
    query = "#event_simpleName=ProcessRollup2 | groupby([ComputerName]) | hed(5)"
    issues, fixed = lint_cql(query, _catalog())
    assert [(i["rule"], i["severity"], i["match"]) for i in issues] == [
        ("unknown_function", "warning", "groupby("),
        ("unknown_function", "warning", "hed("),
    ]
    # Names are case-sensitive, and a case-only difference is the first suggestion.
    assert issues[0]["suggestions"][0] == "groupBy"
    assert "head" in issues[1]["suggestions"]
    assert len(issues[1]["suggestions"]) <= 5
    assert "Did you mean" in issues[1]["message"]
    # Nothing to fix automatically.
    assert fixed == query


def test_namespaced_unknown_function_is_reported_whole() -> None:
    issues, _ = lint_cql("x | array:filtr(array=a)", _catalog())
    assert [i["match"] for i in issues] == ["array:filtr("]
    assert issues[0]["suggestions"][0] == "array:filter"


def test_limit_stage_is_reported_once_with_its_fix() -> None:
    issues, fixed = lint_cql("#event_simpleName=ProcessRollup2 | limit(5)", _catalog())
    assert [i["rule"] for i in issues] == ["limit_function"]
    assert "head(N)" in issues[0]["message"]
    assert fixed == "#event_simpleName=ProcessRollup2 | head(5)"


def test_limit_inside_a_call_gets_the_head_hint() -> None:
    issues, _ = lint_cql("x | groupBy([a], function=limit(5))", _catalog())
    assert [i["rule"] for i in issues] == ["unknown_function"]
    assert "head(N)" in issues[0]["message"]


def test_name_with_no_close_match_has_no_suggestions() -> None:
    issues, _ = lint_cql("x | qqqqqqqqqqqq(1)", _catalog())
    assert issues[0]["suggestions"] == []
    assert "Did you mean" not in issues[0]["message"]


def test_unknown_function_rule_needs_the_catalog() -> None:
    assert lint_cql("x | hed(5)") == ([], "x | hed(5)")
