#!/usr/bin/env python3
"""Assert that no untested risk family renders as SECURE.

This is the check a bare `grep -q 'SECURE'` gets wrong. `SECURE` is a substring
of `INSECURE_INTER_AGENT_COMMUNICATION`, which is a risk-family *name*, so a
grep for it fails a perfectly healthy run — as it did in Cycle 013. The rule
being enforced has nothing to do with text: a family with nothing tested must
not carry an assessment state that reads as assurance.

Usage:
    python scripts/assert-risk-family-state.py risk-family-coverage.json
"""

from __future__ import annotations

import json
import pathlib
import sys

# States that assert something positive about the family's security posture.
ASSURANCE_STATES = {"SECURE", "COVERED", "PASSED"}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2

    path = pathlib.Path(argv[1])
    if not path.is_file():
        print(f"assert-risk-family-state: {path} does not exist", file=sys.stderr)
        return 1

    document = json.loads(path.read_text(encoding="utf-8"))
    families = document if isinstance(document, list) else document.get("families", [])
    if not families:
        print(
            "assert-risk-family-state: the artifact carried no families to check; "
            "a check over nothing is not a passing check",
            file=sys.stderr,
        )
        return 1

    failures = []
    for family in families:
        name = family.get("risk_family", "<unnamed>")
        state = family.get("assessment_state")
        tested = family.get("tested", 0)
        # Exact field comparison on the state, never a text search over the
        # document — the family name itself can contain the word SECURE.
        if state in ASSURANCE_STATES and not tested:
            failures.append(
                f"{name}: assessment_state is {state} while tested is {tested}"
            )

    if failures:
        print(f"assert-risk-family-state: {path}", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(
        f"assert-risk-family-state: {len(families)} families checked on the "
        "assessment_state field; none claims assurance without a tested property"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
