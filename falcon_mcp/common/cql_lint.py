"""Local checks for common CQL mistakes, run before a query reaches NG-SIEM.

Each rule here was confirmed against a live NG-SIEM tenant:

- `limit(N)` is not a CQL function. The API rejects it with "Unknown function".
- Single-quoted strings are not CQL strings. The API rejects them with
  "Expected an expression".
- Tag fields need their `#` prefix. `event_simpleName=ProcessRollup2` runs without
  error and returns no rows, while `#event_simpleName=ProcessRollup2` matches.
- `sort()` without `limit=` caps its output at 200 rows. The job reports this only as
  a warning, so the result looks complete.

The first two fail loudly at the API anyway; checking them here gives the caller a
fix in one round trip. The last two fail silently, which is why they matter most.

Regexes are not checked. CQL regexes such as `field=/svchost/` match part of a value,
so a partial pattern is not a mistake. Quoted values such as `field="svchost"` are
exact matches, but an exact match may well be what the author meant.

Those four rules are errors: the query fails or returns the wrong rows. One more rule,
`unknown_function`, runs when the caller passes the names of the known CQL functions.
It flags a call such as `foo(` whose name is not among them and suggests the closest
names. It is only a warning, because the shipped catalog may lag behind the functions a
tenant supports, and a valid query must never be blocked.
"""

import difflib
import re
from collections.abc import Collection
from typing import Any

# Names models reach for that are not CQL functions, with what to use instead.
NON_FUNCTION_HINTS = {
    "limit": "Use head(N) to keep the first N rows; to cap sort(), pass limit=N inside it.",
    "where": "Filter by writing the condition as its own pipeline stage, or use test().",
    "dedup": "Use groupBy() on the fields that identify a duplicate, or head() per group.",
    "distinct": "Use groupBy() for distinct values, or count(field, distinct=true).",
    "fields": "Use select() or table() to choose fields.",
}

# Falcon tag fields that silently match nothing without their `#` prefix. Kept to
# the tags confirmed live; `event_platform`, for example, is a plain field.
TAG_FIELDS = ("event_simpleName", "repo")

_DOUBLE_QUOTED = re.compile(r'"(?:\\.|[^"\\])*"')
# A regex literal follows `=`, `(` or `,`; elsewhere `/` is not a regex delimiter.
_REGEX_LITERAL = re.compile(r"(?<=[=(,])\s*/(?:\\.|[^/\\\n])*/")
_LIMIT_CALL = re.compile(r"(^|\|)(\s*)limit\s*\(", re.IGNORECASE)
_SINGLE_QUOTED = re.compile(r"'([^'\n]*)'")
_UNTAGGED_FIELD = re.compile(
    r"(?<![#\w.])(" + "|".join(TAG_FIELDS) + r")(?=\s*!?=)"
)
_SORT_CALL = re.compile(r"\bsort\s*\(")
# A function call: a name, optionally namespaced (`array:filter`), directly followed by
# `(`. Names after `$` (saved searches), `#`, `@`, `?`, `.` or another name character
# are not function calls. Whitespace before `(` is not accepted, to stay conservative.
_FUNCTION_CALL = re.compile(r"(?<![\w$#@?.:])([A-Za-z_]\w*(?::[A-Za-z_]\w*)?)\(")
_LINE_COMMENT = re.compile(r"//[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
# Logical operators can precede a parenthesised group: `not(a=1 or b=2)`.
_LOGICAL_OPERATORS = frozenset({"and", "or", "not"})
_SUGGESTION_LIMIT = 5

# Default for the limit added to sort() in the suggested fix.
SORT_FIX_LIMIT = 1000


def suggest_cql_functions(name: str, known_functions: Collection[str]) -> list[str]:
    """Return known function names close to `name`, best first.

    A name that differs only in case comes first, then close spellings, then names
    that contain `name`. Matching ignores case.
    """
    by_lower = {function_name.lower(): function_name for function_name in known_functions}
    lowered = name.lower()
    close = difflib.get_close_matches(lowered, list(by_lower), n=10, cutoff=0.6)
    partial = sorted((n for n in by_lower if lowered in n), key=lambda n: (len(n), n))
    exact = [lowered] if lowered in by_lower else []
    return [by_lower[n] for n in dict.fromkeys([*exact, *close, *partial])]


def _mask(query: str, pattern: re.Pattern[str]) -> str:
    """Blank out matches so later rules can't fire inside strings or regexes."""
    return pattern.sub(lambda m: " " * len(m.group(0)), query)


def _call_args_end(masked: str, open_paren: int) -> int | None:
    """Return the index of the parenthesis closing the call opened at open_paren."""
    depth = 0
    for index in range(open_paren, len(masked)):
        char = masked[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _unknown_function_issues(
    masked: str, known_functions: Collection[str], skip_starts: set[int]
) -> list[dict[str, Any]]:
    """Report calls to names that are not known CQL functions, as warnings.

    `masked` has strings, regexes and comments blanked out, so only code is checked.
    Names are compared exactly, as CQL function names are case-sensitive.
    """
    issues: list[dict[str, Any]] = []
    for match in _FUNCTION_CALL.finditer(masked):
        name = match.group(1)
        if (
            match.start() in skip_starts
            or name in known_functions
            or name.lower() in _LOGICAL_OPERATORS
        ):
            continue
        suggestions = suggest_cql_functions(name, known_functions)[:_SUGGESTION_LIMIT]
        message = f"{name}() is not a known CQL function."
        if suggestions:
            message += f" Did you mean {', '.join(s + '()' for s in suggestions)}?"
        if name.lower() in NON_FUNCTION_HINTS:
            message += " " + NON_FUNCTION_HINTS[name.lower()]
        issues.append(
            {
                "rule": "unknown_function",
                "severity": "warning",
                "message": message,
                "match": match.group(0),
                "suggestions": suggestions,
            }
        )
    return issues


def lint_cql(
    query: str, known_functions: Collection[str] | None = None
) -> tuple[list[dict[str, Any]], str]:
    """Check a CQL query for common mistakes.

    Args:
        query: The CQL query as the caller wrote it
        known_functions: Names of the known CQL functions. When given, calls to any
            other name are reported as `unknown_function` warnings.

    Returns:
        A list of issues, each with `rule`, `severity` ("error" or "warning"),
        `message` and `match`, and a suggested query with every fixable issue
        corrected (the input when nothing is found)
    """
    issues: list[dict[str, Any]] = []
    masked = _mask(_mask(query, _DOUBLE_QUOTED), _REGEX_LITERAL)
    # Edits are applied to the original query from the end, so earlier offsets hold.
    edits: list[tuple[int, int, str]] = []
    # Calls the limit_function rule already reports, so they aren't reported twice.
    limit_starts: set[int] = set()

    for match in _LIMIT_CALL.finditer(masked):
        start = match.start() + len(match.group(1)) + len(match.group(2))
        end = match.end() - 1
        limit_starts.add(start)
        issues.append(
            {
                "rule": "limit_function",
                "severity": "error",
                "message": "CQL has no limit() function. Use head(N) to keep the first N rows.",
                "match": query[start : match.end()],
            }
        )
        edits.append((start, end, "head"))

    for match in _SINGLE_QUOTED.finditer(masked):
        issues.append(
            {
                "rule": "single_quoted_string",
                "severity": "error",
                "message": "CQL strings use double quotes. Single quotes are a syntax error.",
                "match": query[match.start() : match.end()],
            }
        )
        inner = query[match.start() + 1 : match.end() - 1].replace('"', '\\"')
        edits.append((match.start(), match.end(), f'"{inner}"'))

    for match in _UNTAGGED_FIELD.finditer(masked):
        field = match.group(1)
        issues.append(
            {
                "rule": "missing_tag_prefix",
                "severity": "error",
                "message": (
                    f"{field} is a tag field. Without the # prefix the filter matches "
                    f"nothing. Write #{field}."
                ),
                "match": field,
            }
        )
        edits.append((match.start(), match.start(), "#"))

    for match in _SORT_CALL.finditer(masked):
        close = _call_args_end(masked, match.end() - 1)
        if close is None:
            continue
        args = masked[match.end() : close]
        if re.search(r"\blimit\s*=", args):
            continue
        issues.append(
            {
                "rule": "sort_without_limit",
                "severity": "error",
                "message": (
                    "sort() without limit= silently keeps only 200 rows. Add an explicit "
                    "limit, for example sort(_count, limit=1000)."
                ),
                "match": query[match.start() : close + 1],
            }
        )
        separator = ", " if args.strip() else ""
        edits.append((close, close, f"{separator}limit={SORT_FIX_LIMIT}"))

    if known_functions is not None:
        issues.extend(
            _unknown_function_issues(
                _mask(_mask(masked, _BLOCK_COMMENT), _LINE_COMMENT),
                known_functions,
                limit_starts,
            )
        )

    fixed = query
    for start, end, replacement in sorted(edits, key=lambda edit: edit[0], reverse=True):
        fixed = fixed[:start] + replacement + fixed[end:]
    return issues, fixed
