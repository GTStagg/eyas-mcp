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
"""

import re
from typing import Any

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

# Default for the limit added to sort() in the suggested fix.
SORT_FIX_LIMIT = 1000


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


def lint_cql(query: str) -> tuple[list[dict[str, Any]], str]:
    """Check a CQL query for common mistakes.

    Args:
        query: The CQL query as the caller wrote it

    Returns:
        A list of issues, each with `rule`, `message` and `match`, and a suggested
        query with every fixable issue corrected (the input when nothing is found)
    """
    issues: list[dict[str, Any]] = []
    masked = _mask(_mask(query, _DOUBLE_QUOTED), _REGEX_LITERAL)
    # Edits are applied to the original query from the end, so earlier offsets hold.
    edits: list[tuple[int, int, str]] = []

    for match in _LIMIT_CALL.finditer(masked):
        start = match.start() + len(match.group(1)) + len(match.group(2))
        end = match.end() - 1
        issues.append(
            {
                "rule": "limit_function",
                "message": "CQL has no limit() function. Use head(N) to keep the first N rows.",
                "match": query[start : match.end()],
            }
        )
        edits.append((start, end, "head"))

    for match in _SINGLE_QUOTED.finditer(masked):
        issues.append(
            {
                "rule": "single_quoted_string",
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
                "message": (
                    "sort() without limit= silently keeps only 200 rows. Add an explicit "
                    "limit, for example sort(_count, limit=1000)."
                ),
                "match": query[match.start() : close + 1],
            }
        )
        separator = ", " if args.strip() else ""
        edits.append((close, close, f"{separator}limit={SORT_FIX_LIMIT}"))

    fixed = query
    for start, end, replacement in sorted(edits, key=lambda edit: edit[0], reverse=True):
        fixed = fixed[:start] + replacement + fixed[end:]
    return issues, fixed
