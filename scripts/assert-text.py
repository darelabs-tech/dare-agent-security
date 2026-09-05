#!/usr/bin/env python3
"""Assert exact content in rendered text artifacts, and sweep them for leaks.

Written for CI gates on report summaries. Two rules keep it honest:

- `--row` matches a whole rendered line after stripping surrounding whitespace,
  so a table row means that row and not a coincidence inside a longer one;
- `--forbidden` is case-insensitive substring matching, which is correct here
  because a banned claim is banned however it is capitalised or embedded.

The asymmetry is deliberate. Requiring exact rows keeps a passing assertion
meaningful; forbidding loose substrings keeps a failing one hard to slip past.

Usage:
    python scripts/assert-text.py FILE --row "| TOOL_MISUSE | TESTED |" ...
    python scripts/assert-text.py FILE --contains "some phrase" ...
    python scripts/assert-text.py FILE --forbidden "immune" ...
    python scripts/assert-text.py --glob ".dare/out-*/summary.md" --forbidden ...
    python scripts/assert-text.py --glob "out/*" --secret-markers
"""

from __future__ import annotations

import argparse
import glob as globlib
import pathlib
import sys


# The canonical secret and canary markers. Kept here rather than retyped into
# each CI step: several begin with `-`, which argparse would read as a flag, and
# a marker list that drifts between call sites is a leak waiting to happen.
SECRET_MARKERS = (
    "DARE-SYNTHETIC-CANARY-",
    "sk-live-",
    "sk_live_",
    "xoxb-",
    "ghp_",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "aws_secret_access_key",
)


def files_for(args: argparse.Namespace) -> list[pathlib.Path]:
    if args.file:
        return [pathlib.Path(args.file)]
    matched = [pathlib.Path(path) for path in sorted(globlib.glob(args.glob))]
    return [path for path in matched if path.is_file()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", help="a single file to inspect")
    parser.add_argument("--glob", help="a glob of files to inspect")
    parser.add_argument(
        "--row",
        nargs="*",
        default=[],
        help="a whole line that must be present, compared after stripping",
    )
    parser.add_argument(
        "--contains", nargs="*", default=[], help="text that must be present verbatim"
    )
    parser.add_argument(
        "--forbidden",
        nargs="*",
        default=[],
        help="text that must be absent, matched case-insensitively",
    )
    parser.add_argument(
        "--marker",
        nargs="*",
        default=[],
        help="a literal secret marker that must be absent, matched exactly",
    )
    parser.add_argument(
        "--secret-markers",
        action="store_true",
        help="check the built-in canary and credential marker set",
    )
    parser.add_argument(
        "--min-files",
        type=int,
        default=1,
        help="minimum files the sweep must cover; a sweep over nothing is not a pass",
    )
    args = parser.parse_args()

    if not args.file and not args.glob:
        parser.error("pass a FILE or --glob")

    paths = files_for(args)
    if len(paths) < args.min_files:
        print(
            f"assert-text: matched {len(paths)} file(s), below the required "
            f"{args.min_files}; a sweep over nothing is not a passing assertion",
            file=sys.stderr,
        )
        return 1

    failures: list[str] = []
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = {line.strip() for line in text.splitlines()}
        lowered = text.lower()

        for row in args.row:
            if row.strip() not in lines:
                failures.append(f"{path}: missing the exact row `{row}`")
        for needle in args.contains:
            if needle not in text:
                failures.append(f"{path}: missing `{needle}`")
        for phrase in args.forbidden:
            if phrase.lower() in lowered:
                failures.append(f"{path}: contains the forbidden phrase `{phrase}`")
        markers = list(args.marker)
        if args.secret_markers:
            markers.extend(SECRET_MARKERS)
        for marker in markers:
            if marker in text:
                failures.append(f"{path}: leaked `{marker}`")

    if failures:
        print("assert-text:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    checks = (
        len(args.row)
        + len(args.contains)
        + len(args.forbidden)
        + len(args.marker)
        + (len(SECRET_MARKERS) if args.secret_markers else 0)
    )
    print(f"assert-text: {len(paths)} file(s), {checks} assertion(s) each, all held")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
