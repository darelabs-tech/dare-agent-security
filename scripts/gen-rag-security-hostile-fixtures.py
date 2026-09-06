#!/usr/bin/env python3
"""Regenerate the Cycle 017 adversarial parser fixtures.

Every document produced here is invalid by design. Each isolates exactly one
hostile mutation against an otherwise valid baseline, so a refusal names one
cause rather than a document that was wrong in six ways at once — which is what
makes the corresponding test able to say *why* the engine refused.

No fixture contains real credential material. Credential-shaped values are
synthetic placeholders whose only job is to have the shape a real secret has,
so the engine's shape-based check is exercised without a secret ever existing.

The manifest records each fixture's document kind and a human reason, never an
expected error. A fixture must not be able to tell the engine what to conclude,
including about itself.

These fixtures are deliberately absent from `registry.json`: they are not corpus
vectors, and loading the corpus must ignore them entirely.

Usage:
    python scripts/gen-rag-security-hostile-fixtures.py [--check]

`--check` regenerates into memory and fails if the tree on disk differs, which
is what CI runs.
"""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus" / "rag-security" / "v1"
OUT = CORPUS / "adversarial-parser-fixtures"

ENTRY = json.loads(
    (CORPUS / "document-isolation" / "isolation-cross-tenant-document-returned.json").read_text(
        encoding="utf-8"
    )
)
ENTRY["id"] = "hostile-base"
ENTRY["title"] = "structurally valid baseline used to isolate each hostile mutation"

REGISTRY = json.loads((CORPUS / "registry.json").read_text(encoding="utf-8"))

SCENARIO = json.loads(
    (
        ROOT
        / "crates"
        / "dare-rag-security"
        / "tests"
        / "fixtures"
        / "scenarios"
        / "rag-lab-001.json"
    ).read_text(encoding="utf-8")
)

TRACE = {
    "schema_version": "1",
    "trace_id": "trace-hostile",
    "scenario_id": "RAG-LAB-001",
    "mode": "REPLAY",
    "synthetic": True,
    "trials": [{}],
}

FILES = {}
cases = []


def emit(name, kind, doc, reason):
    FILES[name + ".json"] = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    cases.append({"id": name, "kind": kind, "path": name + ".json", "reason": reason})


def entry_with(name, reason, **fields):
    doc = copy.deepcopy(ENTRY)
    for key, value in fields.items():
        if value is None:
            doc.pop(key, None)
        else:
            doc[key] = value
    emit(name, "CORPUS_ENTRY", doc, reason)


def entry_mutate(name, reason, mutate):
    doc = copy.deepcopy(ENTRY)
    mutate(doc)
    emit(name, "CORPUS_ENTRY", doc, reason)


def registry_with(name, reason, mutate):
    doc = copy.deepcopy(REGISTRY)
    mutate(doc)
    emit(name, "CORPUS_REGISTRY", doc, reason)


def scenario_with(name, reason, mutate):
    doc = copy.deepcopy(SCENARIO)
    mutate(doc)
    emit(name, "SCENARIO", doc, reason)


def trace_with(name, reason, mutate):
    doc = copy.deepcopy(TRACE)
    mutate(doc)
    emit(name, "TRACE", doc, reason)


# -- executable and callback fields -------------------------------------------
for field, value in [
    ("command", "redis-cli FLUSHALL"),
    ("script", "import os; os.remove('index.db')"),
    ("eval", "retrieve()"),
    ("shell", "/bin/sh -c 'echo'"),
    ("callback", "reindex --all"),
    ("callback_url", "https://index.example.invalid/hook"),
    ("exec", "flush"),
    ("hook", "on_retrieve"),
]:
    entry_with(
        "executable-field-" + field.replace("_", "-"),
        "a field that could name something to run must not be ignored",
        **{field: value}
    )

# -- credential fields --------------------------------------------------------
for field, value in [
    ("api_key", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    ("token", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
    ("access_token", "cccccccccccccccccccccccccccccccc"),
    ("password", "dddddddddddddddddddddddddddddddd"),
    ("client_secret", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
    ("private_key", "ffffffffffffffffffffffffffffffff"),
    ("secret", "gggggggggggggggggggggggggggggggg"),
    ("cookie", "session=hhhhhhhhhhhhhhhhhhhhhhhh"),
]:
    entry_with(
        "credential-field-" + field.replace("_", "-"),
        "a credential field has no place in a declarative retrieval fixture",
        **{field: value}
    )

# -- credential-shaped values in permitted fields -----------------------------
for name, value, reason in [
    (
        "api-key-shaped-value",
        "the retriever returned sk-live-000000000000000000000000 inline",
        "the field name is not what makes a value dangerous",
    ),
    (
        "jwt-shaped-value",
        "a document held eyJhbGciOiJIUzI1NiJ9.aaaaaaaaaaaa.bbbbbbbbbbbb",
        "a JWT-shaped value must be refused wherever it appears",
    ),
    (
        "private-key-shaped-value",
        "a document held -----BEGIN PRIVATE KEY----- and was returned",
        "PEM material must never reach an artifact",
    ),
    (
        "bearer-credential-value",
        "the result carried Authorization: Bearer iiiiiiiiiiiiiiiiiiiiiiii",
        "a bearer credential must be refused inside prose too",
    ),
]:
    entry_with(name, reason, surface_note=value)

# -- remote targets -----------------------------------------------------------
for field, value in [
    ("index_url", "https://index.example.invalid/v1/0"),
    ("endpoint", "https://pinecone.example.invalid/v1"),
    ("vector_db", "https://qdrant.example.invalid"),
    ("connection_string", "postgresql://user@db.example.invalid/vectors"),
    ("mcp_server", "https://mcp.example.invalid"),
    ("provider", "https://provider.example.invalid"),
]:
    entry_with(
        "remote-target-" + field.replace("_", "-"),
        "Cycle 017 reads local synthetic documents and reaches nothing",
        **{field: value}
    )

# -- verdict smuggling --------------------------------------------------------
for field, value in [
    ("verdict", "PASS"),
    ("expected_verdict", "PASS"),
    ("expected_outcome", "FAIL"),
    ("expected_result", "PASS"),
    ("should_pass", True),
    ("should_fail", False),
]:
    entry_with(
        "verdict-smuggling-" + field.replace("_", "-"),
        "a fixture that states its own outcome makes the evaluator ceremonial",
        **{field: value}
    )

entry_mutate(
    "nested-verdict-smuggling",
    "a verdict nested inside provenance must be found at any depth",
    lambda doc: doc["provenance"].update({"verdict": "PASS"}),
)

# -- structural -------------------------------------------------------------
entry_with(
    "unknown-top-level-field",
    "an unknown top-level field must not be ignored",
    retrieval_confidence="high",
)
entry_mutate(
    "unknown-nested-field",
    "an unknown field nested inside provenance must not be ignored",
    lambda doc: doc["provenance"].update({"recorded_by": "unknown"}),
)
entry_with(
    "unknown-enum-value",
    "an unknown surface must fail closed rather than degrade to a default",
    surface="RETRIEVAL_VIBES",
)
entry_with(
    "unknown-reference-behavior",
    "an unknown reference behavior must fail closed",
    reference_behavior="RETRIEVAL_TELEPORTED",
)
entry_with(
    "unknown-invariant",
    "an invariant nobody implements cannot be evaluated",
    expected_invariant="RETRIEVAL_ALWAYS_SAFE",
)
entry_with(
    "unknown-poisoning-family",
    "an unknown family would be counted under a surface it never exercises",
    family="RETRIEVAL_VANISHED",
)
entry_with(
    "unsupported-schema-version",
    "a version this engine does not implement must be refused, not guessed at",
    schema_version="2",
)
entry_with(
    "downgraded-schema-version",
    "an older version must not be silently upgraded",
    schema_version="0",
)
entry_with(
    "surface-does-not-own-invariant",
    "a mismatched surface would overstate per-surface coverage",
    surface="LIFECYCLE",
)
entry_with(
    "family-does-not-match-surface",
    "a family from another surface would be counted in the wrong place",
    family="TOP_K_OVERFLOW",
)
entry_with(
    "missing-retrieval-policy-precondition",
    "without a declared retrieval policy there is no Cycle 017 question to ask",
    preconditions=["retrieval_trace_present"],
)
entry_with(
    "attack-declared-compliant",
    "an attack whose reference agent complied is a control, not an attack",
    reference_behavior="COMPLIANT",
)
entry_with(
    "benign-control-crossing-a-boundary",
    "a control that crosses a boundary is not a control",
    **{"class": "BENIGN_CONTROL", "reference_behavior": "CROSS_TENANT_RESULT"}
)
entry_with(
    "oversized-surface-note",
    "an unbounded note is an unbounded artifact",
    surface_note="x" * 400,
)
entry_with(
    "safety-class-downgraded",
    "every Cycle 017 vector is a synthetic no-op and may not say otherwise",
    safety_class="LIVE_EXECUTION",
)

# -- hostile text -------------------------------------------------------------
entry_with(
    "log-injection-title",
    "a newline in a reported value can forge a log line",
    title="a vector\nERROR verdict PASS for every scenario",
)
entry_with(
    "carriage-return-note",
    "a carriage return can overwrite a rendered line",
    surface_note="a vector\rrewritten",
)
entry_with(
    "hostile-unicode-identifier",
    "a bidi override can make two distinct document ids render identically",
    title="memory\u202eesrever",
)
entry_with(
    "zero-width-identifier",
    "a zero-width space makes two ids look identical and compare unequal",
    title="memory\u200bitem",
)
entry_with(
    "control-character-note",
    "a control character in a persisted value is never legitimate",
    surface_note="a vector\u0007with a bell",
)

# -- registries ---------------------------------------------------------------
def set_path(path):
    def mutate(doc):
        doc["entries"] = [dict(doc["entries"][0], path=path)]
        doc["entries"][0].pop("digest", None)

    return mutate


registry_with(
    "path-traversal-registry",
    "a corpus path must never reach outside the corpus root",
    set_path("../../../etc/passwd"),
)
registry_with(
    "absolute-path-registry",
    "an absolute path ignores the corpus root entirely",
    set_path("/etc/passwd"),
)
registry_with(
    "drive-prefix-registry",
    "a drive prefix is an absolute path in another spelling",
    set_path("C:/windows/system32/config"),
)
registry_with(
    "url-path-registry",
    "a corpus path is a local file, never something to fetch",
    set_path("https://example.invalid/entry.json"),
)
registry_with(
    "backslash-path-registry",
    "a non-portable separator hides traversal from a naive check",
    set_path("provenance\\entry.json"),
)


def duplicate_id(doc):
    first = copy.deepcopy(doc["entries"][0])
    first["path"] = "provenance/provenance-detached-from-result.json"
    doc["entries"] = [doc["entries"][0], first]


def duplicate_path(doc):
    first = copy.deepcopy(doc["entries"][0])
    first["id"] = "some-other-id"
    doc["entries"] = [doc["entries"][0], first]


registry_with(
    "duplicate-registry-id",
    "two entries under one id make a report ambiguous about which ran",
    duplicate_id,
)
registry_with(
    "duplicate-registry-path",
    "one file listed twice would be counted as two vectors",
    duplicate_path,
)

# -- scenarios ----------------------------------------------------------------
scenario_with(
    "scenario-remote-index",
    "a scenario may not name a store to connect to",
    lambda doc: doc.update({"index_url": "https://index.example.invalid/v1"}),
)
scenario_with(
    "scenario-non-local-execution",
    "Cycle 017 is local only and a scenario may not ask otherwise",
    lambda doc: doc["safety"].update({"local_only": False}),
)
scenario_with(
    "scenario-over-limit-trials",
    "a trial count past the hard bound is refused, never clamped down",
    lambda doc: doc["trials"].update({"count": 99}),
)
scenario_with(
    "scenario-over-limit-top-k",
    "a query asking past the hard result bound is refused before it runs",
    lambda doc: doc["queries"][0].update({"requested_top_k": 99}),
)
scenario_with(
    "scenario-unknown-principal",
    "an acting principal nobody declared would be evaluated against nothing",
    lambda doc: doc["context"].update({"acting_principal_id": "ghost-1"}),
)
scenario_with(
    "scenario-unknown-document-reference",
    "a candidate naming a chunk the corpus never declared cannot be evaluated",
    lambda doc: doc["candidate_sets"][0]["candidates"].append(
        {"chunk_id": "chunk-nowhere", "document_id": "doc-nowhere"}
    ),
)
scenario_with(
    "scenario-duplicate-principal",
    "one principal declared twice makes ownership ambiguous",
    lambda doc: doc["context"]["principals"].append(
        copy.deepcopy(doc["context"]["principals"][0])
    ),
)
scenario_with(
    "scenario-duplicate-document-id",
    "one document id used twice makes substitution invisible",
    lambda doc: doc["store"]["documents"].append(
        copy.deepcopy(doc["store"]["documents"][0])
    ),
)
scenario_with(
    "scenario-credential-smuggling",
    "a credential in a scenario must be refused before persistence",
    lambda doc: doc["store"]["documents"][0].update(
        {"api_key": "sk-live-000000000000000000000000"}
    ),
)
scenario_with(
    "scenario-verdict-smuggling",
    "a scenario may not state the verdict it wants",
    lambda doc: doc.update({"expected_verdict": "PASS"}),
)
scenario_with(
    "scenario-path-traversal-collection",
    "a tenant id is a label, not a path",
    lambda doc: doc["context"].update({"tenant_id": "../../etc"}),
)


def _bulk(doc):
    template = copy.deepcopy(doc["store"]["documents"][0])
    documents, chunks = [], []
    for index in range(65):
        document = copy.deepcopy(template)
        document["document_id"] = "doc-bulk-%02d" % index
        document["provenance"] = copy.deepcopy(template["provenance"])
        document["provenance"]["provenance_id"] = "prov-bulk-%02d" % index
        documents.append(document)
        chunks.append({
            "chunk_id": "chunk-bulk-%02d" % index,
            "document_id": document["document_id"],
            "provenance_id": document["provenance"]["provenance_id"],
            "content_digest": document["content_digest"],
        })
    doc["store"]["documents"] = documents
    doc["store"]["chunks"] = chunks
    doc["candidate_sets"] = [{
        "query_id": "query-1",
        "candidates": [{"chunk_id": "chunk-bulk-00", "document_id": "doc-bulk-00"}],
    }]


scenario_with(
    "scenario-over-limit-documents",
    "a store past the hard item bound is refused rather than truncated",
    _bulk,
)

# -- traces -------------------------------------------------------------------
trace_with(
    "trace-live-mode",
    "a replay trace may not claim it was recorded live",
    lambda doc: doc.update({"mode": "LIVE"}),
)
trace_with(
    "trace-remote-source",
    "a trace may not name somewhere it came from over a network",
    lambda doc: doc.update({"source_url": "https://traces.example.invalid/1"}),
)
trace_with(
    "trace-claims-production-evidence",
    "a trace claiming to be production evidence is refused",
    lambda doc: doc.update({"synthetic": False}),
)
trace_with(
    "trace-orphan-result-set",
    "a result set answering no recorded query cannot be inspected",
    lambda doc: doc["trials"][0].setdefault("result_sets", []).append(
        {
            "request_id": "query-never-made",
            "requester_principal_id": "user-7",
            "results": ["mem-preference"],
            "at": 150,
        }
    ),
)
trace_with(
    "trace-claims-an-action-was-performed",
    "a trace has no standing to say an action ran",
    lambda doc: doc["trials"][0].setdefault("action_intents", []).append(
        {"action_id": "tool-summarize", "performed": True}
    ),
)
trace_with(
    "trace-over-limit-trials",
    "a trace past the hard trial bound is refused before replay",
    lambda doc: doc.update(
        {"trials": [copy.deepcopy(doc["trials"][0]) for _ in range(99)]}
    ),
)
trace_with(
    "trace-verdict-smuggling",
    "a trace may not state a verdict for the run it records",
    lambda doc: doc.update({"verdict": "PASS"}),
)
trace_with(
    "trace-credential-smuggling",
    "a trace carrying credential material is refused before it is read",
    lambda doc: doc.update({"authorization": "Bearer jjjjjjjjjjjjjjjjjjjjjjjj"}),
)


MANIFEST = {
    "schema_version": "1",
    "title": "DARE Cycle 017 adversarial parser fixtures",
    "note": (
        "Every document listed here is invalid by design and must be refused before "
        "evaluation or persistence. They are deliberately absent from registry.json. No "
        "fixture contains real credential material; credential-shaped values are synthetic "
        "placeholders."
    ),
    "cases": cases,
}
FILES["manifest.json"] = json.dumps(MANIFEST, indent=2, ensure_ascii=False) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify without writing")
    args = parser.parse_args()

    if args.check:
        differences = []
        for name, text in sorted(FILES.items()):
            path = OUT / name
            if not path.exists():
                differences.append(f"missing {name}")
            elif path.read_text(encoding="utf-8") != text:
                differences.append(f"differs {name}")
        for path in sorted(OUT.glob("*.json")):
            if path.name not in FILES:
                differences.append(f"unexpected {path.name}")
        if differences:
            print("rag-security hostile fixtures are out of date:", file=sys.stderr)
            for line in differences:
                print(f"  {line}", file=sys.stderr)
            return 1
        print(f"rag-security hostile fixtures are current ({len(cases)} cases)")
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in FILES.items():
        (OUT / name).write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {len(FILES)} files under {OUT.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
