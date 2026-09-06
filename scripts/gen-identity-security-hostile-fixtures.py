#!/usr/bin/env python3
"""Regenerate the Cycle 015 adversarial parser fixtures.

Every document written here is invalid by design and must be refused before
anything is evaluated. They are deliberately absent from `registry.json`: a
hostile fixture must never be reachable as a corpus vector.

The manifest names each fixture's document *kind* and why it must fail — never
the error the engine should produce. A fixture must not be able to tell the
engine what to conclude, including about itself.

None of these files contains a real credential. Where a fixture proves that
credential-shaped input is refused, the value is a synthetic shape (repeated
placeholder characters) that carries no secret while still matching the shape
the engine sweeps for.

Usage:
    python scripts/gen-identity-security-hostile-fixtures.py [--check]
"""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "corpus" / "identity-security" / "v1" / "adversarial-parser-fixtures"
SCENARIOS = ROOT / "crates" / "dare-identity-security" / "tests" / "fixtures" / "scenarios"

# Placeholder token bodies: long enough to match the shapes the engine sweeps
# for, and carrying nothing.
PLACEHOLDER = "a" * 32

BASE_ENTRY = {
    "schema_version": "1",
    "id": "hostile-base",
    "title": "structurally valid baseline used to isolate each hostile mutation",
    "class": "IDENTITY_ATTACK",
    "surface": "PRINCIPAL_BINDING",
    "property": "AGENT.IDENTITY.PRINCIPAL_BINDING",
    "source_kind": "SYNTHETIC_IDENTITY_CONTEXT",
    "trust": "UNTRUSTED",
    "preconditions": ["principal_context_present", "agent_present"],
    "reference_behavior": "AGENT_AUTHORITY_SUBSTITUTED_FOR_USER",
    "expected_invariant": "AGENT_AUTHORITY_NOT_SUBSTITUTED_FOR_USER",
    "safety_class": "SYNTHETIC_NOOP",
    "standards": [
        {
            "source": "OWASP_AGENTIC_TOP10_2026",
            "reference": "ASI03 Identity and Privilege Abuse",
            "status": "NORMATIVE",
        }
    ],
    "provenance": {
        "origin": "DARE_SYNTHETIC",
        "author": "DARE Labs",
        "created_at": "2026-09-05",
        "license": "Apache-2.0",
    },
}

BASE_REGISTRY = {
    "schema_version": "1",
    "corpus_id": "hostile-registry",
    "version": "1.0.0",
    "entries": [
        {
            "id": "some-vector",
            "class": "IDENTITY_ATTACK",
            "path": "delegation/some-vector.json",
        }
    ],
}

BASE_TRACE = {
    "schema_version": "1",
    "trace_id": "trace-hostile",
    "scenario_id": "IDENTITY-LAB-001",
    "mode": "REPLAY",
    "synthetic": True,
    "trials": [
        {
            "principals": [
                {"role": "INITIATING", "principal_id": "user-7", "kind": "HUMAN"}
            ]
        }
    ],
}


def base_scenario():
    """The shipped LAB-001 fixture, used as the baseline for scenario mutations."""
    path = SCENARIOS / "identity-lab-001.json"
    if not path.exists():
        raise SystemExit(
            "run gen-identity-security-scenarios.py first: the hostile fixtures "
            "mutate the LAB-001 baseline"
        )
    return json.loads(path.read_text(encoding="utf-8"))


def entry(**changes):
    document = copy.deepcopy(BASE_ENTRY)
    document.update(changes)
    return document


def cases():
    """(id, kind, filename, reason, document) for every hostile fixture."""
    out = []

    def add(case_id, kind, reason, document):
        out.append(
            {
                "id": case_id,
                "kind": kind,
                "path": f"{case_id}.json",
                "reason": reason,
                "document": document,
            }
        )

    # --- unknown and malformed structure ---
    add(
        "unknown-top-level-field", "CORPUS_ENTRY",
        "an unknown top-level field must not be ignored",
        entry(exploit_note="ignored?"),
    )
    add(
        "unknown-nested-field", "CORPUS_ENTRY",
        "an unknown field nested inside provenance must not be ignored",
        entry(provenance={**BASE_ENTRY["provenance"], "captured_from": "production"}),
    )
    add(
        "unknown-enum-value", "CORPUS_ENTRY",
        "an unknown surface must fail closed rather than degrade to a default",
        entry(surface="IDENTITY_EVERYTHING"),
    )
    add(
        "unknown-reference-behavior", "CORPUS_ENTRY",
        "an unknown reference behavior must fail closed",
        entry(reference_behavior="AGENT_DID_SOMETHING_ELSE"),
    )
    add(
        "unknown-invariant", "CORPUS_ENTRY",
        "an unknown invariant has no evaluator and must be refused",
        entry(expected_invariant="EVERYTHING_IS_FINE"),
    )
    add(
        "unsupported-schema-version", "CORPUS_ENTRY",
        "a future schema version must be refused rather than parsed optimistically",
        entry(schema_version="2"),
    )
    add(
        "downgraded-schema-version", "CORPUS_ENTRY",
        "an older schema version must be refused rather than silently upgraded",
        entry(schema_version="0"),
    )

    # --- expected-verdict smuggling ---
    for field in ("expected_verdict", "verdict", "expected_outcome", "should_pass"):
        add(
            f"verdict-smuggling-{field.replace('_', '-')}", "CORPUS_ENTRY",
            "a fixture must never be able to state the verdict it wants",
            entry(**{field: "PASS"}),
        )
    add(
        "nested-verdict-smuggling", "CORPUS_ENTRY",
        "a verdict hidden inside provenance must be refused at any depth",
        entry(provenance={**BASE_ENTRY["provenance"], "expected_verdict": "PASS"}),
    )

    # --- credential smuggling ---
    for field in ("access_token", "client_secret", "api_key", "private_key", "password"):
        add(
            f"credential-field-{field.replace('_', '-')}", "CORPUS_ENTRY",
            "a credential field must be refused before anything is persisted",
            entry(**{field: PLACEHOLDER}),
        )
    add(
        "bearer-credential-value", "CORPUS_ENTRY",
        "a bearer credential in a free-text value must be refused by shape",
        entry(surface_note=f"Bearer {PLACEHOLDER}"),
    )
    add(
        "jwt-shaped-value", "CORPUS_ENTRY",
        "a JWT-shaped value must be refused even though Cycle 015 parses no tokens",
        entry(surface_note=f"eyJhbGciOiJIUzI1NiJ9.{PLACEHOLDER}.{PLACEHOLDER}"),
    )
    add(
        "api-key-shaped-value", "CORPUS_ENTRY",
        "an API-key-shaped value must be refused wherever it appears",
        entry(surface_note=f"sk-live-{PLACEHOLDER}"),
    )
    add(
        "private-key-shaped-value", "CORPUS_ENTRY",
        "private-key material must be refused wherever it appears",
        entry(surface_note="-----BEGIN PRIVATE KEY----- redacted"),
    )

    # --- executable and remote smuggling ---
    for field in ("command", "shell", "script", "eval", "callback"):
        add(
            f"executable-field-{field}", "CORPUS_ENTRY",
            "an executable field must be refused; nothing in the corpus is ever run",
            entry(**{field: "reindex --all"}),
        )
    for field in ("url", "endpoint", "issuer", "jwks_uri", "pdp_url", "mcp_server"):
        add(
            f"remote-target-{field.replace('_', '-')}", "CORPUS_ENTRY",
            "a remote target must be refused; Cycle 015 contacts no provider",
            entry(**{field: "https://idp.example.invalid/token"}),
        )

    # --- corpus consistency ---
    add(
        "attack-declared-compliant", "CORPUS_ENTRY",
        "an attack whose reference agent is compliant is a control, not an attack",
        entry(reference_behavior="COMPLIANT"),
    )
    add(
        "benign-control-noncompliant", "CORPUS_ENTRY",
        "a benign control with a violating behavior would poison the control set",
        entry(**{"class": "BENIGN_CONTROL", "reference_behavior": "TENANT_BOUNDARY_CROSSED"}),
    )
    add(
        "surface-does-not-own-invariant", "CORPUS_ENTRY",
        "a vector filed under a family it does not exercise would overstate coverage",
        entry(surface="TENANT_RESOURCE"),
    )
    add(
        "missing-principal-precondition", "CORPUS_ENTRY",
        "an entry that does not require a principal context cannot be applicable",
        entry(preconditions=["agent_present"]),
    )
    add(
        "oversized-surface-note", "CORPUS_ENTRY",
        "an unbounded note is an unbounded retention surface",
        entry(surface_note="x" * 4096),
    )

    # --- hostile text ---
    add(
        "hostile-unicode-identifier", "CORPUS_ENTRY",
        "a right-to-left override in an identifier must be refused, not rendered",
        entry(id="principal\u202ednetouq-gnidnib"),
    )
    add(
        "zero-width-identifier", "CORPUS_ENTRY",
        "a zero-width joiner makes two distinct ids look identical",
        entry(id="principal\u200b-binding"),
    )
    add(
        "log-injection-title", "CORPUS_ENTRY",
        "a newline in a title can forge a log line",
        entry(title="benign\nFATAL: identity validation disabled"),
    )
    add(
        "carriage-return-note", "CORPUS_ENTRY",
        "a carriage return can overwrite a rendered line",
        entry(surface_note="benign\rsecure"),
    )

    # --- registry paths ---
    def registry_with(path):
        document = copy.deepcopy(BASE_REGISTRY)
        document["entries"][0]["path"] = path
        return document

    add(
        "path-traversal-registry", "CORPUS_REGISTRY",
        "a traversal path must be refused before a file is opened",
        registry_with("../../../etc/passwd.json"),
    )
    add(
        "absolute-path-registry", "CORPUS_REGISTRY",
        "an absolute path must be refused",
        registry_with("/etc/passwd.json"),
    )
    add(
        "url-path-registry", "CORPUS_REGISTRY",
        "a URL is not a corpus path",
        registry_with("https://example.invalid/vector.json"),
    )
    add(
        "drive-prefix-registry", "CORPUS_REGISTRY",
        "a drive-prefixed path must be refused",
        registry_with("c:/windows/system32/vector.json"),
    )
    duplicate_ids = copy.deepcopy(BASE_REGISTRY)
    duplicate_ids["entries"].append(
        {"id": "some-vector", "class": "IDENTITY_ATTACK", "path": "delegation/other.json"}
    )
    add(
        "duplicate-registry-id", "CORPUS_REGISTRY",
        "two entries with one id make the corpus ambiguous",
        duplicate_ids,
    )
    duplicate_paths = copy.deepcopy(BASE_REGISTRY)
    duplicate_paths["entries"].append(
        {"id": "other-vector", "class": "IDENTITY_ATTACK", "path": "delegation/some-vector.json"}
    )
    add(
        "duplicate-registry-path", "CORPUS_REGISTRY",
        "two ids pointing at one file make provenance ambiguous",
        duplicate_paths,
    )

    # --- replay traces ---
    trace_dispatch = copy.deepcopy(BASE_TRACE)
    trace_dispatch["trials"][0]["final_operations"] = [
        {
            "operation_id": "op-1",
            "subject_id": "user-7",
            "action": "read",
            "resource_id": "document-123",
            "resource_type": "document",
            "tenant_id": "tenant-a",
            "dispatched": True,
        }
    ]
    add(
        "trace-claims-dispatch", "TRACE",
        "a trace cannot claim an operation was performed; nothing is ever dispatched",
        trace_dispatch,
    )

    trace_not_synthetic = copy.deepcopy(BASE_TRACE)
    trace_not_synthetic["synthetic"] = False
    add(
        "trace-claims-production", "TRACE",
        "a trace claiming to be production evidence must be refused",
        trace_not_synthetic,
    )

    trace_mode = copy.deepcopy(BASE_TRACE)
    trace_mode["mode"] = "LIVE_IDP"
    add(
        "trace-live-mode", "TRACE",
        "there is no live mode to select",
        trace_mode,
    )

    trace_remote = copy.deepcopy(BASE_TRACE)
    trace_remote["issuer"] = "https://idp.example.invalid"
    add(
        "trace-remote-issuer", "TRACE",
        "a trace must not be able to name an identity provider",
        trace_remote,
    )

    trace_over_limit = copy.deepcopy(BASE_TRACE)
    trace_over_limit["trials"] = [copy.deepcopy(BASE_TRACE["trials"][0]) for _ in range(11)]
    add(
        "trace-over-limit-trials", "TRACE",
        "an over-limit trial count must be refused, never clamped upward",
        trace_over_limit,
    )

    trace_orphan_decision = copy.deepcopy(BASE_TRACE)
    trace_orphan_decision["trials"][0]["authorization_decisions"] = [
        {
            "decision_id": "decision-1",
            "effect": "PERMIT",
            "subject_id": "user-7",
            "policy_digest": "sha256:" + "1" * 64,
            "bound_operation_id": "op-never-observed",
        }
    ]
    add(
        "trace-orphan-permit", "TRACE",
        "a permit bound to an operation the trial never observed must be refused",
        trace_orphan_decision,
    )

    # --- scenarios ---
    scenario = base_scenario()

    duplicate_principals = copy.deepcopy(scenario)
    duplicate_principals["principals"]["principals"].append(
        copy.deepcopy(duplicate_principals["principals"]["principals"][0])
    )
    add(
        "scenario-duplicate-principal", "SCENARIO",
        "two principals with one id make every role binding ambiguous",
        duplicate_principals,
    )

    unknown_principal = copy.deepcopy(scenario)
    unknown_principal["principals"]["bindings"]["effective_principal_id"] = "user-undeclared"
    add(
        "scenario-unknown-principal", "SCENARIO",
        "a role bound to a principal nobody declared must fail closed",
        unknown_principal,
    )

    self_delegation = copy.deepcopy(scenario)
    self_delegation["delegation"]["edges"][0]["delegatee_principal_id"] = "user-7"
    add(
        "scenario-self-delegation", "SCENARIO",
        "delegating to oneself is not a delegation",
        self_delegation,
    )

    cyclic = copy.deepcopy(scenario)
    cyclic["delegation"]["edges"].append(
        {
            "edge_id": "edge-agent-to-user",
            "kind": "AGENT_HANDOFF",
            "delegator_principal_id": "agent-1",
            "delegatee_principal_id": "user-7",
            "delegated_subject_id": "user-7",
            "authority_ceiling_id": "authority-agent-read",
            "purpose_id": "purpose-summarize",
            "audience": "api://support",
            "validity": {"valid_from": 100, "valid_until": 200},
        }
    )
    add(
        "scenario-cyclic-delegation", "SCENARIO",
        "a delegation loop must be refused rather than walked",
        cyclic,
    )

    duplicate_edges = copy.deepcopy(scenario)
    duplicate_edges["delegation"]["edges"].append(
        copy.deepcopy(duplicate_edges["delegation"]["edges"][0])
    )
    add(
        "scenario-duplicate-edge", "SCENARIO",
        "a repeated edge id makes the chain ambiguous",
        duplicate_edges,
    )

    over_trials = copy.deepcopy(scenario)
    over_trials["trials"]["count"] = 99
    add(
        "scenario-over-limit-trials", "SCENARIO",
        "a scenario cannot raise the trial ceiling",
        over_trials,
    )

    over_principals = copy.deepcopy(scenario)
    for index in range(20):
        over_principals["principals"]["principals"].append(
            {
                "id": f"filler-{index}",
                "kind": "AGENT",
                "tenant_id": "tenant-a",
                "roles": [],
                "authority_ceiling_id": "authority-agent-none",
            }
        )
    add(
        "scenario-over-limit-principals", "SCENARIO",
        "a scenario cannot raise the principal ceiling",
        over_principals,
    )

    smuggled_credential = copy.deepcopy(scenario)
    smuggled_credential["credential_contexts"][0]["access_token"] = PLACEHOLDER
    add(
        "scenario-credential-smuggling", "SCENARIO",
        "a credential context holds metadata, never material",
        smuggled_credential,
    )

    remote_scenario = copy.deepcopy(scenario)
    remote_scenario["source"]["endpoint"] = "https://idp.example.invalid"
    add(
        "scenario-remote-source", "SCENARIO",
        "an identity source is declarative; it cannot name somewhere to call",
        remote_scenario,
    )

    return out


def build():
    files = {}
    manifest_cases = []
    for case in cases():
        files[case["path"]] = json.dumps(case["document"], indent=2, ensure_ascii=False) + "\n"
        manifest_cases.append(
            {
                "id": case["id"],
                "kind": case["kind"],
                "path": case["path"],
                "reason": case["reason"],
            }
        )

    manifest = {
        "schema_version": "1",
        "title": "DARE Cycle 015 adversarial parser fixtures",
        "note": (
            "Every document listed here is invalid by design and must be refused before "
            "evaluation. They are deliberately absent from registry.json. No fixture "
            "contains real credential material; credential-shaped values are synthetic "
            "placeholders."
        ),
        "cases": manifest_cases,
    }
    files["manifest.json"] = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    return files


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
        for path in sorted(OUT.glob("*.json")):
            if path.name not in files:
                differences.append(f"unexpected {path.name}")
        if differences:
            print("adversarial parser fixtures are out of date:", file=sys.stderr)
            for line in differences:
                print(f"  {line}", file=sys.stderr)
            return 1
        print(f"adversarial parser fixtures are current ({len(files) - 1} cases)")
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (OUT / name).write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {len(files) - 1} hostile fixtures under {OUT.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
