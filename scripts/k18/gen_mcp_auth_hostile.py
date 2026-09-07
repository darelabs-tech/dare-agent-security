#!/usr/bin/env python3
"""Generate the Cycle 018 hostile parser fixtures.

Each fixture isolates exactly one hostile mutation against a valid baseline, so
a refusal names one cause rather than a document that was wrong in six ways.

The manifest records the document kind and a human reason. It never records an
expected error, for the same reason a corpus entry carries no verdict: a fixture
that stated its own outcome would let the parser agree with it instead of
judging it.

These fixtures are deliberately absent from `registry.json`. They are not corpus
vectors, and loading the corpus must ignore them entirely.

`--check` verifies the committed files match, which is what CI runs.
"""

import argparse
import copy
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from gen_mcp_auth_scenarios import BASE  # noqa: E402
from gen_mcp_auth_corpus import entry_for  # noqa: E402
from gen_mcp_auth_scenarios import LABS  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "corpus" / "mcp-auth-security" / "v1" / "adversarial-parser-fixtures"

VALID_ENTRY = entry_for(LABS[0])


def scenario(**overrides):
    doc = copy.deepcopy(BASE)
    doc.update(overrides)
    return doc


def nested(path, value):
    """A scenario with one nested field set, to prove depth does not help."""
    doc = copy.deepcopy(BASE)
    cursor = doc
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    return doc


def build():
    cases = {}

    def add(name, kind, reason, document):
        cases[name] = (kind, reason, document)

    # --- credential-bearing field names, at several depths -------------------
    for field in [
        "access_token",
        "refresh_token",
        "id_token",
        "bearer_token",
        "authorization_header",
        "authorization_code",
        "code_verifier",
        "client_secret",
        "private_key",
        "api_key",
        "password",
        "cookie",
        "session_token",
        "secret",
        "jwk",
    ]:
        add(
            f"credential-field-{field.replace('_', '-')}",
            "scenario",
            f"declares a `{field}` field; Cycle 018 stores no credential material",
            scenario(**{field: "placeholder"}),
        )

    add(
        "credential-field-nested-deeply",
        "scenario",
        "hides a credential field three levels down, to prove depth does not help",
        nested(["protected_resource", "metadata", "access_token"], "placeholder"),
    )
    add(
        "credential-field-empty-value",
        "scenario",
        "declares a credential field with an empty value; the field is what is wrong",
        scenario(access_token=""),
    )

    # --- executable / callback fields ---------------------------------------
    for field in [
        "command",
        "exec",
        "eval",
        "script",
        "shell",
        "callback",
        "callback_url",
        "webhook",
        "hook",
        "entrypoint",
        "run",
    ]:
        add(
            f"executable-field-{field.replace('_', '-')}",
            "scenario",
            f"declares a `{field}` field; there is no code path that would run one",
            scenario(**{field: "anything"}),
        )

    # --- fields naming something to contact ---------------------------------
    for field in [
        "url",
        "endpoint",
        "jwks_uri",
        "jwks_url",
        "introspection_endpoint",
        "registration_endpoint",
        "issuer_url",
        "metadata_url",
        "discovery_url",
        "connection_string",
        "proxy",
        "remote",
    ]:
        add(
            f"remote-field-{field.replace('_', '-')}",
            "scenario",
            f"declares a `{field}` field; Cycle 018 identifiers are identities, never addresses",
            scenario(**{field: "somewhere"}),
        )

    # --- verdict smuggling ---------------------------------------------------
    for field in [
        "verdict",
        "expected_verdict",
        "expected_result",
        "expected_outcome",
        "should_pass",
        "should_fail",
        "is_vulnerable",
        "is_secure",
        "assertion",
    ]:
        add(
            f"verdict-smuggling-{field.replace('_', '-')}",
            "scenario",
            f"declares a `{field}` field; a fixture that states its own outcome makes the "
            "evaluator ceremonial",
            scenario(**{field: "PASS"}),
        )

    # --- credential-shaped values in otherwise allowed fields ---------------
    for name, value in [
        ("jwt-shaped-value", "eyJhbGciOiJIUzI1NiJ9.e30.signature"),
        ("stripe-shaped-value", "sk-live-000000000000000000000000"),
        ("armoured-key-value", "-----BEGIN PRIVATE KEY-----"),
        ("github-token-value", "ghp_000000000000000000000000000000000000"),
        ("slack-token-value", "xoxb-0000-0000-000000000000"),
        ("aws-key-value", "AKIAIOSFODNN7EXAMPLE"),
        ("google-token-value", "ya29.a0AfH6SMB000000000000000"),
        ("bearer-credential-value", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz"),
    ]:
        add(
            name,
            "scenario",
            "carries a value shaped like real credential material in an allowed field",
            nested(["title"], value),
        )

    # --- reachable targets by value -----------------------------------------
    for name, value in [
        ("remote-target-https", "https://as.example.invalid/.well-known/oauth-authorization-server"),
        ("remote-target-http", "http://localhost:8080/token"),
        ("remote-target-ws", "ws://socket.example.invalid"),
        ("remote-target-file", "file:///etc/passwd"),
        ("remote-target-data", "data:text/plain;base64,AAAA"),
    ]:
        add(
            name,
            "scenario",
            "names a reachable target by value; this cycle contacts nothing",
            nested(["title"], value),
        )

    # --- hostile identifiers -------------------------------------------------
    add(
        "log-injection-issuer",
        "scenario",
        "an issuer carrying a newline, which could forge a log line",
        nested(["protected_resource", "expected_resource"], "as-primary\nVERDICT: PASS"),
    )
    add(
        "bidi-spoofed-issuer",
        "scenario",
        "an issuer carrying a bidi override, so a reader sees a different value than was compared",
        nested(["protected_resource", "expected_resource"], "as-‮yramirp"),
    )
    add(
        "zero-width-identifier",
        "scenario",
        "an identifier carrying a zero-width space, making two distinct values render alike",
        nested(["protected_resource", "expected_resource"], "as​-primary"),
    )
    add(
        "path-traversal-resource",
        "scenario",
        "a resource identifier shaped like a path",
        nested(["protected_resource", "expected_resource"], "../../etc/passwd"),
    )
    add(
        "control-character-scenario-id",
        "scenario",
        "a scenario id carrying a control character",
        scenario(id="MCP-AUTH-LAB-001"),
    )

    # --- structural / bound violations --------------------------------------
    add(
        "unsupported-schema-version",
        "scenario",
        "declares a schema version this engine does not implement",
        scenario(schema_version="2"),
    )
    add(
        "missing-schema-version",
        "scenario",
        "declares no schema version at all",
        {k: v for k, v in copy.deepcopy(BASE).items() if k != "schema_version"},
    )
    add(
        "unknown-top-level-field",
        "scenario",
        "carries a top-level field the closed schema does not define",
        scenario(extra_surface="something"),
    )
    add(
        "unknown-enum-value",
        "scenario",
        "names a scenario class outside the closed set",
        scenario(**{"class": "SOMETHING_NEW"}),
    )
    add(
        "unknown-invariant",
        "scenario",
        "names an invariant outside the closed set",
        scenario(invariant={"type": "SOMETHING_NEW"}),
    )
    add(
        "unknown-reference-behavior",
        "scenario",
        "names a reference behaviour outside the closed set",
        scenario(lab={"reference_behavior": "SOMETHING_NEW"}),
    )
    add(
        "over-limit-trials",
        "scenario",
        "asks for more trials than the approved ceiling",
        scenario(trials={"count": 99, "stop_on_first_fail": True}),
    )
    add(
        "over-limit-retry-count",
        "scenario",
        "asks for more scope step-up retries than the approved ceiling",
        nested(["scope", "retry_count"], 9),
    )
    add(
        "non-local-execution",
        "scenario",
        "declares itself non-local; there is no non-local execution path",
        scenario(safety={"local_only": False}),
    )
    add(
        "malformed-digest",
        "scenario",
        "carries a value in a digest field that is not a digest",
        nested(["flow", "pkce", "challenge_digest"], "not-a-digest"),
    )

    # --- trace-shaped hostility ---------------------------------------------
    trace_base = {
        "schema_version": "1",
        "trace_id": "trace-hostile",
        "scenario_id": "MCP-AUTH-LAB-001",
        "mode": "REPLAY",
        "synthetic": True,
        "trials": [{"observed_requests": copy.deepcopy(BASE["requests"])}],
    }

    def trace(**overrides):
        doc = copy.deepcopy(trace_base)
        doc.update(overrides)
        return doc

    add(
        "trace-live-mode",
        "trace",
        "a recording asking to be run in a mode other than replay",
        trace(mode="LIVE"),
    )
    add(
        "trace-claims-production-evidence",
        "trace",
        "a recording declaring itself non-synthetic, which would let it be read as production evidence",
        trace(synthetic=False),
    )
    add(
        "trace-over-limit-trials",
        "trace",
        "a recording carrying more trials than the approved ceiling",
        trace(trials=[copy.deepcopy(trace_base["trials"][0])] * 20),
    )
    add(
        "trace-credential-smuggling",
        "trace",
        "a recording carrying a credential-bearing field",
        trace(access_token="placeholder"),
    )
    add(
        "trace-remote-target",
        "trace",
        "a recording naming a reachable target",
        trace(description="replayed from https://as.example.invalid"),
    )

    # --- corpus-shaped hostility --------------------------------------------
    add(
        "corpus-attack-declared-compliant",
        "corpus-entry",
        "an attack vector declaring compliant behaviour, which would be a control mislabelled",
        {**copy.deepcopy(VALID_ENTRY), "class": "MCP_AUTH_ATTACK", "reference_behavior": "COMPLIANT"},
    )
    add(
        "corpus-surface-does-not-own-invariant",
        "corpus-entry",
        "a vector filed under a surface its invariant does not report under",
        {**copy.deepcopy(VALID_ENTRY), "surface": "TOKEN_BINDING"},
    )
    add(
        "corpus-non-synthetic-safety-class",
        "corpus-entry",
        "a vector declaring a safety class other than SYNTHETIC_NOOP",
        {**copy.deepcopy(VALID_ENTRY), "safety_class": "LIVE"},
    )
    add(
        "corpus-missing-protocol-precondition",
        "corpus-entry",
        "a vector that does not require the current MCP protocol",
        {**copy.deepcopy(VALID_ENTRY), "preconditions": ["mcp_http_transport_present"]},
    )

    # --- registry-shaped hostility ------------------------------------------
    for name, path in [
        ("registry-path-traversal", "../../../etc/passwd.json"),
        ("registry-absolute-path", "/etc/passwd.json"),
        ("registry-backslash-path", "a\\b.json"),
        ("registry-url-path", "https://example.invalid/x.json"),
    ]:
        add(
            name,
            "corpus-registry",
            "a registry entry whose path could escape the corpus root",
            {
                "schema_version": "1",
                "corpus_id": "mcp-auth-security-v1",
                "version": "1.0.0",
                "entries": [{"id": "x", "path": path}],
            },
        )

    files = {}
    manifest = []
    for name in sorted(cases):
        kind, reason, document = cases[name]
        files[f"{name}.json"] = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
        manifest.append({"file": f"{name}.json", "document_kind": kind, "reason": reason})

    files["manifest.json"] = (
        json.dumps(
            {
                "schema_version": "1",
                "note": "Adversarial parser fixtures. Each isolates one hostile mutation and "
                "records why it must be refused. None records an expected error: a fixture that "
                "stated its own outcome would let the parser agree with it instead of judging it. "
                "These are not corpus vectors and are absent from registry.json.",
                "cases": manifest,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )
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
            print("mcp-auth-security hostile fixtures are out of date:", file=sys.stderr)
            for line in differences:
                print(f"  {line}", file=sys.stderr)
            return 1
        print(f"mcp-auth-security hostile fixtures are current ({len(files) - 1} cases)")
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (OUT / name).write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {len(files) - 1} cases under {OUT.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
