#!/usr/bin/env python3
"""Verify that every test Cycle 022 PROOF.md cites actually exists.

Derived from `scripts/k21/verify_proof_citations.py` with Cycle 022 paths and
citation lists; the verification rules are unchanged.

Cycle 016 shipped three citations naming tests that did not exist, the
post-merge review of Cycle 018 found two more that had gone stale when their
tests were renamed, and Cycle 019 shipped eleven. A proof document whose
citations are unchecked is a claim about a claim, so this is a gate rather than
a habit.

Three kinds of name appear inside backticks in `PROOF.md`:

- **tests**, which must exist in the current tree;
- **named functions** cited as APIs rather than tests, listed in
  ``KNOWN_FUNCTIONS`` and each verified to exist by a `fn <name>` search;
- **historical test names**, cited by the regression record to name what a test
  used to assert. These must be *absent*: a name recorded as removed that still
  exists means the record is wrong in the other direction.

Run from the repository root.
"""

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROOF = ROOT / "DARE/cycles/022-remote-authorized-validation/PROOF.md"

SOURCE_ROOTS = [
    "crates/dare-remote-validation/src",
    "crates/dare-remote-validation/tests",
    "crates/dare-mcp-auth-security/src",
    "crates/dare-agent-security-cli/src",
    "crates/dare-agent-security-cli/tests",
    "crates/dare-a2a-security/src",
    "crates/dare-supply-chain-security/src",
    # hotfix-001: the executions document lives in the coverage crate.
    "crates/dare-coverage/src",
]

# Cited as APIs, not tests. Each is checked for a real `fn` definition below.
KNOWN_FUNCTIONS = {
    "admit_file",
    "build_evidence",
    "check_depth",
    "classify_status",
    "downgrade_pass",
    "final_verdict",
    "lower_limits",
    "opaque_uri",
    "record_kill",
    "render_artifacts",
    "render_summary",
    "replay_capture",
    "run_remote",
    "run_remote_lowered",
    "run_scenario",
    "run_with_gateway",
    "scenario_with_observed_resource",
    "validate_secret_safety",
}

# Names the regression record cites as having been removed or renamed. Each must
# be gone from the tree.
HISTORICAL_NAMES: set[str] = set()


def collect_tests() -> set[str]:
    names: set[str] = set()
    for root in SOURCE_ROOTS:
        for path in (ROOT / root).rglob("*.rs"):
            pending = False
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                # Cycle 022 tests are mostly async (`#[tokio::test(...)]`).
                if stripped.startswith("#[test]") or stripped.startswith("#[tokio::test"):
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
        ["git", "grep", "-l", f"fn {name}", "--", "crates/", "scripts/"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.stdout.strip():
        return True
    # Python helpers in scripts/ are cited too.
    result = subprocess.run(
        ["git", "grep", "-l", f"def {name}", "--", "scripts/"],
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
            name = name.removesuffix("()")
            if not re.fullmatch(r"[a-z][a-z0-9_]*", name):
                continue
            if name.count("_") < 2:
                continue
            names.add(name)
    return names


def main() -> int:
    tests = collect_tests()
    cited = cited_names(PROOF.read_text(encoding="utf-8"))

    # A verifier that found no citations would pass by reading nothing, which is
    # the failure this script exists to prevent one layer up.
    if not cited or not tests:
        print(
            f"citation check failed: {len(cited)} cited name(s) against "
            f"{len(tests)} test(s); a check that reads nothing proves nothing",
            file=sys.stderr,
        )
        return 1

    missing = []
    for name in sorted(cited):
        if name in HISTORICAL_NAMES:
            if name in tests:
                missing.append(
                    f"{name} — recorded as removed but still exists; the record is wrong"
                )
            continue
        if name in tests:
            continue
        if name in KNOWN_FUNCTIONS:
            if not defines_function(name):
                missing.append(f"{name} — cited as a function, no `fn {name}` found")
            continue
        missing.append(f"{name} — cited as a test, not found")

    print(f"PROOF.md cites {len(cited)} names against {len(tests)} tests in the tree")
    print(
        f"  {len(KNOWN_FUNCTIONS)} function citations allowed, "
        f"{len(HISTORICAL_NAMES)} historical names"
    )

    if missing:
        print("\nUNVERIFIED CITATIONS:", file=sys.stderr)
        for line in missing:
            print(f"  {line}", file=sys.stderr)
        return 1
    print("every cited name is verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
