"""Build the CQL function catalog shipped with eyas-mcp.

Reads a catalog JSON of LogScale query functions and writes the slimmed copy that
`falcon_lookup_cql_function` serves: `falcon_mcp/resources/cql_functions.json`.

Only factual fields are kept: the function name, its signature, parameter names
and whether each is required, categories, the default argument, availability and a
link to the function's documentation page. Descriptions and any other prose from
the documentation are dropped, so the shipped file carries none of it.

The input is a JSON object with a `functions` list (or a bare list) whose records
carry at least `name` and `signature`. Parameters are taken from `params` when
present and otherwise parsed from the signature, where `[name]` marks an optional
parameter.

Usage:
    .venv/Scripts/python scripts/build_cql_catalog.py path/to/catalog.json
    .venv/Scripts/python scripts/build_cql_catalog.py in.json --output out.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / "falcon_mcp" / "resources" / "cql_functions.json"

DOCS_BASE_URL = "https://library.humio.com/data-analysis/"
INDEX_URL = DOCS_BASE_URL + "functions.html"

# Function names are identifiers with an optional namespace, such as `array:sort`.
_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?::[A-Za-z][A-Za-z0-9]*)?$")
_PARAM = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
_SIGNATURE = re.compile(r"^([A-Za-z][A-Za-z0-9:]*)\(([^()]*)\)$")
_DOC_PAGE = re.compile(r"^functions-[A-Za-z0-9._-]+\.html$")
# Availability is a short version note such as "added in 1.229"; anything longer is
# not a fact this catalog keeps.
_AVAILABILITY = re.compile(r"^[A-Za-z0-9 .,:-]{1,40}$")
_CATEGORY = re.compile(r"^[A-Za-z0-9 _-]{1,40}$")


def parse_signature(signature: str) -> list[dict[str, Any]]:
    """Parse the parameter list of a signature like `sort([field], [order])`."""
    match = _SIGNATURE.match(signature.strip())
    if not match:
        raise ValueError(f"unparseable signature: {signature!r}")
    params: list[dict[str, Any]] = []
    for raw in match.group(2).split(","):
        token = raw.strip()
        if not token:
            continue
        optional = token.startswith("[") and token.endswith("]")
        name = token[1:-1].strip() if optional else token
        params.append({"name": name, "required": not optional})
    return params


def _doc_url(record: dict[str, Any], name: str) -> str:
    """Return the function's documentation URL, built from its own page name."""
    url = record.get("doc_url")
    if isinstance(url, str) and url.startswith(DOCS_BASE_URL):
        page = url[len(DOCS_BASE_URL) :]
        if _DOC_PAGE.match(page):
            return url
    # LogScale names each page after the function, with ':' written as '-'.
    return f"{DOCS_BASE_URL}functions-{name.replace(':', '-').lower()}.html"


def slim_record(record: dict[str, Any]) -> dict[str, Any]:
    """Keep only the factual fields of one catalog record."""
    name = record.get("name")
    signature = record.get("signature")
    if not isinstance(name, str) or not _NAME.match(name):
        raise ValueError(f"invalid function name: {name!r}")
    if not isinstance(signature, str):
        raise ValueError(f"{name}: missing signature")
    signature = signature.strip()
    match = _SIGNATURE.match(signature)
    if not match or match.group(1) != name:
        raise ValueError(f"{name}: signature {signature!r} does not name the function")

    raw_params = record.get("params")
    if not isinstance(raw_params, list):
        raw_params = parse_signature(signature)
    params = []
    for param in raw_params:
        param_name = param.get("name") if isinstance(param, dict) else None
        if not isinstance(param_name, str) or not _PARAM.match(param_name):
            raise ValueError(f"{name}: invalid parameter {param!r}")
        params.append({"name": param_name, "required": bool(param.get("required"))})

    categories = [
        c for c in record.get("categories") or [] if isinstance(c, str) and _CATEGORY.match(c)
    ]

    default_arg = record.get("default_arg")
    if not (isinstance(default_arg, str) and _PARAM.match(default_arg)):
        default_arg = None

    availability = record.get("availability")
    if not (isinstance(availability, str) and _AVAILABILITY.match(availability)):
        availability = None

    return {
        "name": name,
        "signature": signature,
        "params": params,
        "categories": sorted(set(categories)),
        "default_arg": default_arg,
        "availability": availability,
        "doc_url": _doc_url(record, name),
    }


def build_catalog(source: Any) -> dict[str, Any]:
    """Build the slimmed catalog from a loaded source catalog."""
    records = source.get("functions") if isinstance(source, dict) else source
    if not isinstance(records, list) or not records:
        raise ValueError("source catalog has no functions")
    functions = sorted((slim_record(r) for r in records), key=lambda f: f["name"])
    names = [f["name"] for f in functions]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise ValueError(f"duplicate function names: {duplicates}")
    return {
        "source": INDEX_URL,
        "fields": ["name", "signature", "params", "categories", "default_arg", "availability"],
        "function_count": len(functions),
        "functions": functions,
    }


def render_catalog(catalog: dict[str, Any]) -> str:
    """Serialize the catalog with one function per line, so a rebuild diffs cleanly."""
    header = {k: v for k, v in catalog.items() if k != "functions"}
    lines = [json.dumps(header, ensure_ascii=False)[:-1] + ', "functions": [']
    rows = [json.dumps(f, ensure_ascii=False) for f in catalog["functions"]]
    lines.append(",\n".join(rows))
    lines.append("]}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("source", type=Path, help="Path to the source catalog JSON")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Where to write the catalog (default: {DEFAULT_OUTPUT.relative_to(REPO_ROOT)})",
    )
    args = parser.parse_args(argv)

    source = json.loads(args.source.read_text(encoding="utf-8"))
    catalog = build_catalog(source)
    args.output.write_text(render_catalog(catalog), encoding="utf-8")
    print(f"wrote {args.output} ({catalog['function_count']} functions)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
