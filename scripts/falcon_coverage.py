"""Report Falcon API coverage from FalconPy's operation table.

Compares the installed FalconPy against the committed baseline, then shows which
operations falcon_mcp/ reaches, by route group. Reads FalconPy's table and this
repository's source only: it makes no network calls and needs no credentials.

Usage:
    python scripts/falcon_coverage.py                    # changes, overrides, group totals
    python scripts/falcon_coverage.py --list             # also every operation by group
    python scripts/falcon_coverage.py --list --unused    # only operations not reached yet
    python scripts/falcon_coverage.py --group alerts     # one group's operations
    python scripts/falcon_coverage.py --update-baseline  # accept the installed FalconPy

Coverage counts endpoints (verb plus route), not names. Hundreds of endpoints have two
names, such as `admission-control-get-policies` and `admission_control_get_policies`, so
counting names would report a covered endpoint as missing under its other spelling.

An endpoint is reached in one of two ways:

- By name: an operation name appears as an exact string literal. FalconPy runs the first
  table row for a name, so a name with several routes reaches only that row.
- By override: a call passes `override="METHOD,/route"`, which a name match can't see.
  Any module can do this, so overrides are found in the source, not from a list of modules.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

import falconpy
from falconpy._endpoint import api_endpoints

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCE_ROOT = PROJECT_ROOT / "falcon_mcp"
BASELINE_PATH = Path(__file__).resolve().parent / "falconpy_operations.json"

# This table names operations to describe their scopes, which doesn't mean they're called.
NOT_USAGE = frozenset({Path("common/api_scopes.py")})

VERBS = "GET|POST|PATCH|PUT|DELETE|HEAD"
ROUTE = r"/[\w-]+(?:/[\w.{}-]+)+"
ROUTE_RE = re.compile(ROUTE)
OVERRIDE_RE = re.compile(rf"({VERBS}),({ROUTE})")
TEMPLATE_PREFIX_RE = re.compile(rf"({VERBS}),")


class Endpoint(NamedTuple):
    """One unique row of FalconPy's operation table."""

    operation: str
    verb: str
    route: str

    @property
    def pair(self) -> tuple[str, str]:
        """Identify the API endpoint itself, whatever it is named."""
        return self.verb, self.route

    @property
    def group(self) -> str:
        """Return the route group, the first path segment."""
        return self.route.split("/")[1]


@dataclass
class Usage:
    """What falcon_mcp/ reaches, keyed by source file label."""

    names: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    overrides: dict[str, set[tuple[str, str]]] = field(default_factory=lambda: defaultdict(set))
    unresolved: list[str] = field(default_factory=list)


@dataclass
class Changes:
    """Differences between the baseline and the installed table."""

    added: list[Endpoint]
    removed: list[Endpoint]
    changed: dict[str, tuple[list[Endpoint], list[Endpoint]]]

    def __bool__(self) -> bool:
        return bool(self.added or self.removed or self.changed)


def load_installed() -> tuple[str, list[Endpoint]]:
    """Return the FalconPy version and its unique rows, in table order."""
    rows = [Endpoint(row[0], row[1], row[2]) for row in api_endpoints]
    return falconpy.__version__, list(dict.fromkeys(rows))


def load_baseline(path: Path) -> tuple[str, list[Endpoint]]:
    """Return the FalconPy version and the operations saved in a baseline file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["falconpy_version"], [Endpoint(*row) for row in data["operations"]]


def write_baseline(path: Path, version: str, endpoints: list[Endpoint]) -> None:
    """Save a baseline sorted and with one row per line, so bumps produce small diffs."""
    rows = ",\n".join(f"    {json.dumps(list(row))}" for row in sorted(set(endpoints)))
    text = (
        "{\n"
        f'  "falconpy_version": {json.dumps(version)},\n'
        f'  "operations": [\n{rows}\n  ]\n'
        "}\n"
    )
    path.write_text(text, encoding="utf-8", newline="\n")


def compare(baseline: list[Endpoint], current: list[Endpoint]) -> Changes:
    """List operations added, removed, or changed in verb or route."""
    before = _by_operation(baseline)
    after = _by_operation(current)
    changed = {
        name: (before[name], after[name])
        for name in sorted(before.keys() & after.keys())
        if before[name] != after[name]
    }
    return Changes(
        added=sorted(row for name in after.keys() - before.keys() for row in after[name]),
        removed=sorted(row for name in before.keys() - after.keys() for row in before[name]),
        changed=changed,
    )


def _by_operation(endpoints: list[Endpoint]) -> dict[str, list[Endpoint]]:
    grouped: dict[str, list[Endpoint]] = defaultdict(list)
    for endpoint in sorted(set(endpoints)):
        grouped[endpoint.operation].append(endpoint)
    return grouped


def _label(path: Path, root: Path) -> str:
    """Name a source file the way people refer to it: `alerts`, `cloud/cloud_iom`."""
    relative = path.relative_to(root).with_suffix("").as_posix()
    return relative.removeprefix("modules/")


def scan_source(root: Path, known_names: set[str]) -> Usage:
    """Find the operation names and override routes used under `root`."""
    usage = Usage()
    for path in sorted(root.rglob("*.py")):
        if path.relative_to(root) in NOT_USAGE:
            continue
        label = _label(path, root)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and node.value in known_names:
                usage.names[str(node.value)].add(label)
        _scan_overrides(tree, label, usage)
    return usage


def _route_literal(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        if ROUTE_RE.fullmatch(node.value):
            return node.value
    return None


def _route_bindings(tree: ast.AST) -> dict[str, set[str]]:
    """Map each variable or keyword name to the route literals it is given."""
    bindings: dict[str, set[str]] = defaultdict(set)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            route = _route_literal(node.value)
            if route:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        bindings[target.id].add(route)
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg:
            route = _route_literal(node.value)
            if route:
                bindings[node.arg].add(route)
            elif isinstance(node.value, ast.Name):
                bindings[node.arg] |= bindings.get(node.value.id, set())
    return bindings


def _template(node: ast.JoinedStr) -> tuple[str, str] | None:
    """Split `f"GET,{route}"` into its verb and variable name."""
    match node.values:
        case [
            ast.Constant(value=str(prefix)),
            ast.FormattedValue(value=ast.Name(id=name), format_spec=None),
        ]:
            found = TEMPLATE_PREFIX_RE.fullmatch(prefix)
            if found:
                return found.group(1), name
    return None


def _scan_overrides(tree: ast.AST, label: str, usage: Usage) -> None:
    """Record the endpoints one file reaches through `override=`.

    A template such as `f"POST,{invoke_route}"` gets the verb from its own text, and
    only the routes bound to that variable, so a file that mixes verbs doesn't claim a
    verb a route is never called with. A variable with no literal bound to it is a
    plain parameter, such as guardian's `route`, and takes the file's remaining routes.

    Anything else is reported as unresolved rather than silently left uncounted.
    """
    templates: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.keyword) and node.arg == "override"):
            continue
        value = node.value
        literal = value.value if isinstance(value, ast.Constant) else None
        found = OVERRIDE_RE.fullmatch(literal) if isinstance(literal, str) else None
        template = _template(value) if isinstance(value, ast.JoinedStr) else None
        if found:
            usage.overrides[label].add((found.group(1), found.group(2)))
        elif template:
            templates.append(template)
        else:
            usage.unresolved.append(f"{label}:{node.value.lineno}: {ast.unparse(value)}")

    if not templates:
        return
    bindings = _route_bindings(tree)
    claimed = {r for _, name in templates for r in bindings.get(name, set())}
    nodes = (node for node in ast.walk(tree) if isinstance(node, ast.expr))
    literals = {route for node in nodes if (route := _route_literal(node))}
    for verb, name in templates:
        routes = bindings.get(name) or literals - claimed
        if not routes:
            usage.unresolved.append(f'{label}: f"{verb},{{{name}}}" has no known route')
        usage.overrides[label].update((verb, route) for route in routes)


class Coverage:
    """Answers what reaches an endpoint, given the table and the source scan."""

    def __init__(self, endpoints: list[Endpoint], usage: Usage) -> None:
        self.usage = usage
        self.override_pairs = {pair for pairs in usage.overrides.values() for pair in pairs}
        first_route: dict[str, Endpoint] = {}
        for endpoint in endpoints:
            first_route.setdefault(endpoint.operation, endpoint)
        self.first_route = first_route

        self.modules: dict[tuple[str, str], set[str]] = defaultdict(set)
        for name, labels in usage.names.items():
            if name in first_route:
                self.modules[first_route[name].pair] |= labels
        for label, pairs in usage.overrides.items():
            for pair in pairs:
                self.modules[pair].add(label)

    def mark(self, endpoint: Endpoint) -> str:
        """Return `o` for override, `n` for name, `a` for alias, or a space if unused."""
        if endpoint.pair in self.override_pairs:
            return "o"
        if self.first_route.get(endpoint.operation) == endpoint and (
            endpoint.operation in self.usage.names
        ):
            return "n"
        return "a" if endpoint.pair in self.modules else " "

    def used_by(self, endpoint: Endpoint) -> list[str]:
        """Return the source files reaching a row, even one no longer in the table."""
        labels = set(self.modules.get(endpoint.pair, set()))
        return sorted(labels | self.usage.names.get(endpoint.operation, set()))


def _route_order(endpoint: Endpoint) -> tuple[str, str, str]:
    """Sort so a new API family reads as a block, not scattered by operation name."""
    return endpoint.route, endpoint.verb, endpoint.operation


def _row(endpoint: Endpoint, mark: str, modules: list[str]) -> str:
    suffix = f"  ({', '.join(modules)})" if modules else ""
    return f"  [{mark}] {endpoint.verb:<6} {endpoint.route}  {endpoint.operation}{suffix}"


def _heading(text: str) -> list[str]:
    return ["", text, "-" * len(text)]


LEGEND = "[n] by name  [o] by override  [a] other name for a used endpoint  [ ] not used"


def summary_lines(version: str, endpoints: list[Endpoint], coverage: Coverage) -> list[str]:
    """Headline totals for the installed FalconPy."""
    pairs = {e.pair for e in endpoints}
    groups = {e.group for e in endpoints}
    used = {e for e in endpoints if coverage.mark(e) != " "}
    used_pairs = {e.pair for e in used}
    by_name = {e.pair for e in endpoints if coverage.mark(e) == "n"}
    return [
        f"FalconPy {version}: {len(pairs)} endpoints, "
        f"{len({e.operation for e in endpoints})} operation names, {len(groups)} route groups",
        f"falcon_mcp reaches {len(used_pairs)} of {len(pairs)} endpoints, "
        f"in {len({e.group for e in used})} of {len(groups)} route groups",
        f"  {len(by_name)} endpoints reached by operation name",
        f"  {len(coverage.override_pairs & pairs)} endpoints reached by override",
    ]


def change_lines(
    baseline_version: str, version: str, changes: Changes, coverage: Coverage
) -> list[str]:
    """Show what moved since the baseline, and whether falcon_mcp is affected."""
    lines = _heading(f"Changes since baseline (FalconPy {baseline_version} -> {version})")
    if not changes:
        return [*lines, "  None."]
    lines.append(LEGEND)

    unused = sum(coverage.mark(e) == " " for e in changes.added)
    lines += ["", f"Added: {len(changes.added)} ({unused} not used yet)"]
    added = sorted(changes.added, key=_route_order)
    lines += [_row(e, coverage.mark(e), coverage.used_by(e)) for e in added]

    broken = [e for e in changes.removed if coverage.used_by(e)]
    lines += ["", f"Removed: {len(changes.removed)} ({len(broken)} still used, fix these first)"]
    for endpoint in sorted(changes.removed, key=_route_order):
        modules = coverage.used_by(endpoint)
        lines.append(_row(endpoint, "!" if modules else " ", modules))

    lines += ["", f"Changed verb or route: {len(changes.changed)}"]
    for name, (before, after) in changes.changed.items():
        modules = sorted({label for e in [*before, *after] for label in coverage.used_by(e)})
        flag = "!" if modules else " "
        lines.append(f"  [{flag}] {name}" + (f"  ({', '.join(modules)})" if modules else ""))
        lines += [f"      - {e.verb:<6} {e.route}" for e in before if e not in after]
        lines += [f"      + {e.verb:<6} {e.route}" for e in after if e not in before]
    return lines


def override_lines(endpoints: list[Endpoint], coverage: Coverage) -> list[str]:
    """Show each module's override routes, which a name match can't see."""
    lines = _heading("Override routes")
    names: dict[tuple[str, str], list[str]] = defaultdict(list)
    for endpoint in sorted(endpoints):
        names[endpoint.pair].append(endpoint.operation)

    for label, pairs in sorted(coverage.usage.overrides.items()):
        unknown = [pair for pair in pairs if pair not in names]
        lines.append(f"{label}: {len(pairs)} routes, {len(unknown)} not in FalconPy's table")
        for verb, route in sorted(pairs, key=lambda pair: (pair[1], pair[0])):
            operations = ", ".join(names.get((verb, route), ["NOT IN FALCONPY"]))
            lines.append(f"  {verb:<6} {route}  {operations}")
    if coverage.usage.unresolved:
        lines += ["", "Overrides this script couldn't resolve, so they aren't counted:"]
        lines += [f"  {item}" for item in coverage.usage.unresolved]
    return lines


def group_lines(endpoints: list[Endpoint], coverage: Coverage) -> list[str]:
    """Show how many endpoints each route group has and how many are reached."""
    totals: dict[str, set[tuple[str, str]]] = defaultdict(set)
    reached: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for endpoint in endpoints:
        totals[endpoint.group].add(endpoint.pair)
        if coverage.mark(endpoint) != " ":
            reached[endpoint.group].add(endpoint.pair)

    width = max(len(group) for group in totals)
    lines = _heading("Route groups (endpoints used / total)")
    for group in sorted(totals):
        lines.append(f"  {group:<{width}}  {len(reached[group]):>3} / {len(totals[group]):>3}")
    return lines


def operation_lines(
    endpoints: list[Endpoint], coverage: Coverage, groups: list[str], unused_only: bool
) -> list[str]:
    """List operations under each route group."""
    selected: dict[str, list[Endpoint]] = defaultdict(list)
    for endpoint in sorted(endpoints, key=_route_order):
        if groups and endpoint.group not in groups:
            continue
        if unused_only and coverage.mark(endpoint) != " ":
            continue
        selected[endpoint.group].append(endpoint)

    lines = _heading("Operations by route group")
    lines.append(LEGEND)
    for group in sorted(selected):
        lines += ["", group]
        lines += [_row(e, coverage.mark(e), coverage.used_by(e)) for e in selected[group]]
    return lines


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Report Falcon API coverage from FalconPy.")
    parser.add_argument("--list", action="store_true", help="list every operation by route group")
    parser.add_argument(
        "--group",
        action="append",
        default=[],
        metavar="NAME",
        help="list only this route group's operations (repeatable)",
    )
    parser.add_argument(
        "--unused", action="store_true", help="with --list or --group, hide used operations"
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="save the installed FalconPy as the new baseline, after reviewing the report",
    )
    parser.add_argument("--baseline", type=Path, default=BASELINE_PATH, help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    version, endpoints = load_installed()

    if args.update_baseline:
        write_baseline(args.baseline, version, endpoints)
        print(f"Saved FalconPy {version} to {args.baseline}")
        return 0

    if not args.baseline.exists():
        print(f"No baseline at {args.baseline}. Run with --update-baseline.", file=sys.stderr)
        return 2
    baseline_version, baseline = load_baseline(args.baseline)

    unknown = sorted(set(args.group) - {e.group for e in endpoints})
    if unknown:
        print(f"Unknown route group: {', '.join(unknown)}", file=sys.stderr)
        return 2

    names = {e.operation for e in [*endpoints, *baseline]}
    coverage = Coverage(endpoints, scan_source(SOURCE_ROOT, names))

    lines: list[str] = []
    if not args.group:
        lines += summary_lines(version, endpoints, coverage)
        changes = compare(baseline, endpoints)
        lines += change_lines(baseline_version, version, changes, coverage)
        lines += override_lines(endpoints, coverage)
        lines += group_lines(endpoints, coverage)
    if args.list or args.group:
        lines += operation_lines(endpoints, coverage, args.group, args.unused)
    print("\n".join(lines).lstrip("\n"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
