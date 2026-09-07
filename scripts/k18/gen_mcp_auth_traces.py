#!/usr/bin/env python3
"""Generate the MCP-AUTH-SECURITY replay trace fixtures.

A trace records the requests a run observed. These are derived from the lab
scenarios rather than written by hand, so a trace cannot silently disagree with
the scenario it claims to replay.

Only the *requests* are copied. A trace carries no verdict, no expectation and
no invariant: it is evidence of what happened, never the authority that says
what was approved. That distinction is the Cycle 017 lesson, and the reason
`assert_matches` re-checks the observed requests against the approved scenario
before any evaluator sees them.

Two fixtures are deliberately unbound, and exist to be refused:

- `unbound-operation` restates the approved request with a wider operation while
  keeping the same `scenario_id`. It is the exact shape of the Cycle 017 defect.
- `foreign-scenario` names a scenario it was not recorded against.

`--check` verifies the committed files match, which is what CI runs.
"""

import argparse
import copy
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCENARIOS = ROOT / "crates" / "dare-mcp-auth-security" / "tests" / "fixtures" / "scenarios"
OUT = ROOT / "crates" / "dare-mcp-auth-security" / "tests" / "fixtures" / "traces"

# One bound trace per surface, so replay is exercised against more than a single
# shape of scenario. Each is the compliant control for that surface.
BOUND = [
    ("mcp-auth-lab-001", "protocol binding, routing and body in agreement"),
    ("mcp-auth-lab-011", "a token naming the resource the request was for"),
    ("mcp-auth-lab-016", "PKCE S256 bound to its verifier"),
    ("mcp-auth-lab-026", "an inbound credential kept distinct from the upstream one"),
]


def scenario(lab):
    return json.loads((SCENARIOS / f"{lab}.json").read_text(encoding="utf-8"))


def trace(trace_id, scenario_id, description, requests, trials=3):
    return {
        "schema_version": "1",
        "trace_id": trace_id,
        "scenario_id": scenario_id,
        "mode": "REPLAY",
        "synthetic": True,
        "description": description,
        "trials": [{"observed_requests": copy.deepcopy(requests)} for _ in range(trials)],
    }


def build():
    files = {}

    for lab, description in BOUND:
        doc = scenario(lab)
        name = lab.replace("mcp-auth-lab-", "trace-lab-")
        files[f"{name}.json"] = trace(
            name, doc["id"], description, doc["requests"]
        )

    # A trace that keeps the scenario id and widens the operation. The routing
    # metadata is left alone: a trace is allowed to disagree there, because that
    # disagreement is exactly what the binding invariants judge. What it may not
    # do is restate the operation the server executed.
    doc = scenario("mcp-auth-lab-001")
    widened = copy.deepcopy(doc["requests"])
    widened[0]["operation"]["name"] = "delete-invoice"
    files["trace-unbound-operation.json"] = trace(
        "trace-unbound-operation",
        doc["id"],
        "restates the approved request with a wider operation under the same scenario id",
        widened,
        trials=1,
    )

    # A trace recorded against another scenario entirely.
    files["trace-foreign-scenario.json"] = trace(
        "trace-foreign-scenario",
        "MCP-AUTH-LAB-011",
        "names a scenario it was not recorded against",
        doc["requests"],
        trials=1,
    )

    return {
        name: json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        for name, payload in files.items()
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify without writing")
    args = parser.parse_args()

    files = build()

    if args.check:
        differences = []
        for name, text in sorted(files.items()):
            path = OUT / name
            if not path.exists():
                differences.append(f"missing {name}")
            elif path.read_text(encoding="utf-8") != text:
                differences.append(f"differs {name}")
        if OUT.exists():
            for path in sorted(OUT.glob("*.json")):
                if path.name not in files:
                    differences.append(f"unexpected {path.name}")
        if differences:
            print("mcp-auth-security traces are out of date:", file=sys.stderr)
            for line in differences:
                print(f"  {line}", file=sys.stderr)
            return 1
        print(f"mcp-auth-security traces are current ({len(files)} traces)")
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (OUT / name).write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {len(files)} traces under {OUT.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
