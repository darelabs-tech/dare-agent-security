#!/usr/bin/env python3
"""Verify that every test PROOF.md cites actually exists.

Cycle 016 shipped three citations naming tests that did not exist, and the
post-merge review of Cycle 018 found two more that had gone stale when their
tests were renamed. A proof document whose citations are unchecked is a claim
about a claim, so this is a gate rather than a habit.

Three kinds of name appear inside backticks in `PROOF.md`:

- **tests**, which must exist in the current tree;
- **named functions** that are cited as APIs rather than tests, listed in
  ``KNOWN_FUNCTIONS`` and each verified to exist by a `fn <name>` search;
- **historical test names**, cited by the post-merge section to record what a
  test used to assert. These must be *absent*: a name recorded as removed that
  still exists means the record is wrong in the other direction.

Run from the repository root.
"""

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROOF = ROOT / "DARE/cycles/018-mcp-2026-security-auth-hardening/PROOF.md"

SOURCE_ROOTS = [
    "crates/dare-mcp-auth-security/src",
    "crates/dare-mcp-auth-security/tests",
    "crates/dare-coverage/src",
    "crates/dare-coverage/tests",
    "crates/dare-agent-security-cli/src",
    "crates/dare-coaz-integrity/src",
]

# Cited as APIs, not tests. Each is checked for a real `fn` definition below.
KNOWN_FUNCTIONS = {
    "assert_no_conformance_claim",
    "assert_no_status_promotion",
    "compute_authorization_binding",
    "binding_material_v1",
    "bindings_equal",
    "changed_operation_fields",
    "normalize",
}

# Names the post-merge section records as having been removed or renamed. Each
# must be gone from the tree.
HISTORICAL_NAMES = {
    "comparison_is_semantic_rather_than_byte_exact",
    "casing_alone_is_not_an_authorization_relevant_change",
    "an_override_may_narrow_but_never_widen_past_the_hard_bound",
}


def collect_tests() -> set[str]:
    names: set[str] = set()
    for root in SOURCE_ROOTS:
        for path in (ROOT / root).rglob("*.rs"):
            pending = False
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if stripped.startswith("#[test]"):
                    pending = True
                    continue
                if pending and " fn " in f" {stripped}":
                    match = re.search(r"fn\s+([a-z_][a-z0-9_]*)", stripped)
                    if match:
                        names.add(match.group(1))
                    pending = False
    return names


def defines_function(name: str) -> bool:
    result = subprocess.run(
        ["git", "grep", "-l", f"fn {name}", "--", "crates/"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return bool(result.stdout.strip())


def cited_names(text: str) -> set[str]:
    names: set[str] = set()
    for chunk in re.findall(r"`([^`]+)`", text):
        for part in re.split(r"[,;/]\s*", chunk):
            name = part.strip().rsplit("::", 1)[-1]
            if not re.fullmatch(r"[a-z][a-z0-9_]*", name):
                continue
            if name.count("_") < 2:
                continue
            names.add(name)
    return names


def main() -> int:
    tests = collect_tests()
    cited = cited_names(PROOF.read_text(encoding="utf-8"))

    missing = []
    for name in sorted(cited):
        if name in tests:
            continue
        if name in KNOWN_FUNCTIONS:
            if not defines_function(name):
                missing.append(f"{name} — cited as a function, no `fn {name}` in crates/")
            continue
        if name in HISTORICAL_NAMES:
            if name in tests:
                missing.append(
                    f"{name} — recorded as removed but still exists; the record is wrong"
                )
            continue
        missing.append(f"{name} — cited as a test, not found")

    print(f"PROOF.md cites {len(cited)} names against {len(tests)} tests in the tree")
    print(f"  {len(KNOWN_FUNCTIONS)} function citations, {len(HISTORICAL_NAMES)} historical names")

    if missing:
        print("\nUNVERIFIED CITATIONS:", file=sys.stderr)
        for line in missing:
            print(f"  {line}", file=sys.stderr)
        return 1
    print("every cited name is verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
