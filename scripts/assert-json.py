#!/usr/bin/env python3
"""Assert exact structured fields in a JSON artifact.

CI gates that grep for a substring are how a healthy run gets failed by a
coincidence — `SECURE` matching inside `INSECURE_INTER_AGENT_COMMUNICATION` cost
Cycle 013 a red build. This asserts on parsed structure and whole values
instead, so a check means what it says.

Usage:
    python scripts/assert-json.py FILE PATH=VALUE [PATH=VALUE ...]
    python scripts/assert-json.py FILE --absent PATH [PATH ...]
    python scripts/assert-json.py FILE --present PATH [PATH ...]
    python scripts/assert-json.py FILE --count PATH=N

A PATH is dot-separated, with integer segments indexing arrays:

    verdict
    budget.state_changes
    trials.0.verdict
    stop_reason.reason

A `*` segment expands over every element of an array or every value of an
object, so `trials.*.events.*.dispatched` names every dispatched flag in the
document. Paths that do not resolve simply contribute no match, which is why
`--all` pairs with `--min-matches`: an assertion over nothing is not a passing
assertion.

A VALUE is parsed as JSON when it parses (so `0`, `true` and `null` compare as
those), and as a plain string otherwise. Comparison is exact equality; there is
no substring matching anywhere in this script, deliberately.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

MISSING = object()


def resolve(document: object, path: str) -> object:
    """Follow a dotted path, returning MISSING rather than raising.

    An empty path names the document root, so a top-level array can be counted.
    """
    if path == "":
        return document
    current = document
    for segment in path.split("."):
        if isinstance(current, list):
            if not segment.lstrip("-").isdigit():
                return MISSING
            index = int(segment)
            if index >= len(current) or index < -len(current):
                return MISSING
            current = current[index]
        elif isinstance(current, dict):
            if segment not in current:
                return MISSING
            current = current[segment]
        else:
            return MISSING
    return current


def resolve_all(document: object, path: str) -> list[object]:
    """Every value a wildcard path names. Non-matching branches drop out."""
    if path == "":
        return [document]
    found: list[object] = [document]
    for segment in path.split("."):
        stepped: list[object] = []
        for current in found:
            if segment == "*":
                if isinstance(current, list):
                    stepped.extend(current)
                elif isinstance(current, dict):
                    stepped.extend(current.values())
                continue
            if isinstance(current, list):
                if segment.lstrip("-").isdigit():
                    index = int(segment)
                    if -len(current) <= index < len(current):
                        stepped.append(current[index])
            elif isinstance(current, dict) and segment in current:
                stepped.append(current[segment])
        found = stepped
    return found


def parse_expected(raw: str) -> object:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def render(value: object) -> str:
    return "<missing>" if value is MISSING else json.dumps(value, ensure_ascii=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="JSON artifact to inspect")
    parser.add_argument("equals", nargs="*", help="PATH=VALUE assertions")
    parser.add_argument("--absent", nargs="*", default=[], help="paths that must not exist")
    parser.add_argument("--present", nargs="*", default=[], help="paths that must exist")
    parser.add_argument("--count", nargs="*", default=[], help="PATH=N array length assertions")
    parser.add_argument(
        "--all",
        nargs="*",
        default=[],
        dest="all_of",
        help="PATH=VALUE that must hold for every wildcard match",
    )
    parser.add_argument(
        "--min-matches",
        type=int,
        default=1,
        help="minimum number of --all matches; an assertion over nothing is not a pass",
    )
    parser.add_argument(
        "--min-total",
        nargs="*",
        default=[],
        help="PATH=N: the wildcard matches must hold at least N entries in total",
    )
    args = parser.parse_args()

    path = pathlib.Path(args.file)
    if not path.is_file():
        print(f"assert-json: {path} does not exist", file=sys.stderr)
        return 1

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        print(f"assert-json: {path} is not valid JSON: {error}", file=sys.stderr)
        return 1

    failures: list[str] = []

    for assertion in args.equals:
        if "=" not in assertion:
            failures.append(f"malformed assertion `{assertion}`; expected PATH=VALUE")
            continue
        key, _, raw = assertion.partition("=")
        actual = resolve(document, key)
        expected = parse_expected(raw)
        if actual is MISSING or actual != expected:
            failures.append(
                f"{key}: expected {render(expected)}, found {render(actual)}"
            )

    for key in args.present:
        if resolve(document, key) is MISSING:
            failures.append(f"{key}: expected to be present, but it is missing")

    for key in args.absent:
        actual = resolve(document, key)
        if actual is not MISSING:
            failures.append(f"{key}: expected to be absent, found {render(actual)}")

    for assertion in args.count:
        if "=" not in assertion:
            failures.append(f"malformed count `{assertion}`; expected PATH=N")
            continue
        key, _, raw = assertion.partition("=")
        actual = resolve(document, key)
        if not isinstance(actual, list):
            failures.append(f"{key}: expected an array, found {render(actual)}")
        elif len(actual) != int(raw):
            failures.append(f"{key}: expected {raw} entries, found {len(actual)}")

    matched = 0
    for assertion in args.all_of:
        if "=" not in assertion:
            failures.append(f"malformed assertion `{assertion}`; expected PATH=VALUE")
            continue
        key, _, raw = assertion.partition("=")
        expected = parse_expected(raw)
        matches = resolve_all(document, key)
        matched += len(matches)
        for index, actual in enumerate(matches):
            if actual != expected:
                failures.append(
                    f"{key}[match {index}]: expected {render(expected)}, "
                    f"found {render(actual)}"
                )
    if args.all_of and matched < args.min_matches:
        failures.append(
            f"--all matched {matched} value(s), below the required {args.min_matches}; "
            "an assertion over nothing is not a passing assertion"
        )

    for assertion in args.min_total:
        if "=" not in assertion:
            failures.append(f"malformed total `{assertion}`; expected PATH=N")
            continue
        key, _, raw = assertion.partition("=")
        total = sum(len(m) for m in resolve_all(document, key) if isinstance(m, list))
        if total < int(raw):
            failures.append(f"{key}: expected at least {raw} entries in total, found {total}")

    if failures:
        print(f"assert-json: {path}", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    checked = (
        len(args.equals)
        + len(args.present)
        + len(args.absent)
        + len(args.count)
        + len(args.all_of)
        + len(args.min_total)
    )
    print(f"assert-json: {path} - {checked} assertion(s) held")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
