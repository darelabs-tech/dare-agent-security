# Cycle 017 — Blueprint

## Target architecture

Introduce a new additive crate, expected name `crates/dare-rag-security`, plus coverage/profile/CLI/product/CI integration.

Execution flow:

```text
Scenario / Replay Trace
        ↓
Schema + hostile-field validation
        ↓
Canonical retrieval context
        ↓
Policy + principal/tenant/collection bindings
        ↓
Candidate set + filters + ordered results
        ↓
Document/chunk/provenance normalization
        ↓
Deterministic invariant evaluation
        ↓
Cycle 001 evidence bridge
        ↓
PASS / FAIL / INCONCLUSIVE / ERROR
```

## Modules

Suggested crate modules:

- `source.rs` — closed enums and bounded source types;
- `schema.rs` — compiled-in schemas only;
- `document.rs` — document/chunk/provenance models;
- `policy.rs` — ACL, tenant, collection, protected-document and top-k policy;
- `query.rs` — retrieval request/candidate/result types;
- `canonical.rs` — stable digests and cross-object binding;
- `observation.rs` — normalized closed event model;
- `coverage.rs` — invariant-specific positive coverage;
- `invariant.rs` — total deterministic evaluator registry;
- `trials.rs` — hard/run-wide bounds;
- `replay.rs`;
- `simulated.rs`;
- `local_synthetic.rs`;
- `result.rs`;
- `evidence_bridge.rs`;
- `compat.rs` — Cycle 013/015/016 reuse assertions.

## Artifact trees

Expected new trees:

- `schemas/rag-security/v1/`
- `corpus/rag-security/v1/`
- `fixtures/rag-security/`
- `standards/rag-security/2026/`
- `profiles/rag-security-baseline-2026.json`
- `book/en/src/concepts/rag-security.md`
- `book/en/src/reference/extending-rag-security.md`

## Compatibility rules

1. No duplicate prompt-injection evaluator.
2. No duplicate identity/tenant model with incompatible semantics.
3. No automatic conversion of retrieved content into memory.
4. No modification of Cycle 006 coverage mathematics.
5. No 11th Agentic risk family.
6. No network/provider/vector-store SDK dependency.
7. No raw model/embedding inference required.
8. No arbitrary executable fields.

## Security boundary

All scenarios are synthetic or replayed from explicitly synthetic/local traces. State changes and external egress remain zero. A vector score is evidence supplied by the fixture/trace, never security authority by itself.

## CI strategy

The dedicated job must test:

- schemas and hostile fixtures;
- every invariant in PASS and FAIL directions where meaningful;
- INCONCLUSIVE-on-missing-evidence;
- cross-tenant, ACL, metadata-filter, provenance, result-set, top-k, protected-document and fallback cases;
- secret/redaction hygiene;
- no-live-mode/no-provider-flags;
- Cycle 013/014/015/016 regressions;
- Agentic family count and no-SECURE-on-untested regression;
- MCP baseline;
- bounded claim wording;
- generated fixture reproducibility if generators are introduced.

## Final proof

Task finalization must produce `REGRESSION.md` and `PROOF.md`. Every Design acceptance criterion must point to executed evidence rather than code existence or intent.
