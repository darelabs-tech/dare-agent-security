# DARE Agent Security — Cycle 001 TASKS

> Cycle: `001-evidence-schema`
> Status: **READY FOR EXECUTION SPECIFICATION**
> Issue: #2
> Source of truth: `DESIGN.md` + approved `BLUEPRINT.md`
> Implementation language: Rust

## Execution rules

- Execute only tasks whose `depends_on` are DONE.
- The approved `DESIGN.md` and `BLUEPRINT.md` are architectural constraints, not suggestions.
- Do not introduce MCP-, AuthZEN-, COAZ-, OWASP-, customer-, SaaS-, database- or UI-specific concepts into the generic evidence kernel.
- Do not add raw credential fields or serialize secret values.
- `INCONCLUSIVE` and `ERROR` must never degrade to `PASS`.
- Unsupported schema major versions must fail closed.
- No TODO/FIXME/stub/mock may remain in production code at task completion.
- Each task must satisfy its validation gates before it can be marked DONE.
- If implementation requires a semantic change to the approved Design or Blueprint, stop execution and return to DARE Review.

## Task map

| ID | Title | Status | Depends On | Complexity |
|---|---|---|---|---|
| task-001 | Bootstrap Rust workspace and evidence crate | PENDING | — | LOW |
| task-002 | Implement canonical evidence types and wire enums | PENDING | task-001 | HIGH |
| task-003 | Define canonical JSON Schema v1 | PENDING | task-002 | HIGH |
| task-004 | Implement schema versioning and semantic validation | PENDING | task-002 | HIGH |
| task-005 | Implement redaction safety and secret-safe errors | PENDING | task-002 | HIGH |
| task-006 | Implement deterministic outcome comparison and verdict consistency | PENDING | task-002, task-004 | HIGH |
| task-007 | Publish PASS/FAIL/INCONCLUSIVE/ERROR synthetic fixtures | PENDING | task-003, task-004, task-005, task-006 | MED |
| task-008 | Implement contract, round-trip and negative security tests | PENDING | task-003, task-004, task-005, task-006, task-007 | HIGH |
| task-009 | Add CI quality gates and evidence contract documentation | PENDING | task-008 | MED |
| task-010 | Prove Cycle 001 evidence contract end to end | PENDING | task-009 | HIGH |

## Phase A — Foundation

### task-001 — Bootstrap Rust workspace and evidence crate

Establish the minimal Rust workspace and isolated library crate:

```text
Cargo.toml
crates/dare-security-evidence/
```

The crate must not depend on future CLI, MCP, vector, graph, network or enterprise components.

**Primary proof:** the workspace builds and the empty evidence crate passes baseline Rust gates.

### task-002 — Implement canonical evidence types and wire enums

Implement the public Rust model defined by the Blueprint, including the top-level `SecurityEvidence` contract and its component types.

The wire contract must include explicit enums for verdict, severity, redaction strategy and other bounded vocabularies approved by the Blueprint.

**Primary proof:** deterministic serde round-trip tests for canonical types and enum wire formats.

## Phase B — Contract and invariants

### task-003 — Define canonical JSON Schema v1

Create:

```text
schemas/evidence/v1/evidence.schema.json
```

The schema must independently validate the public JSON contract without requiring Rust or a network fetch.

Use strict objects and deliberate extension points. Reject malformed digests, invalid enums and missing required fields structurally where practical.

**Primary proof:** schema self-validation plus valid/invalid structural fixtures.

### task-004 — Implement schema versioning and semantic validation

Implement typed semantic validation beyond JSON Schema.

Required invariants include:

- supported major version only;
- required semantic identifiers are non-empty;
- timestamp ordering is coherent;
- error/inconclusive semantics are explicit;
- hash metadata is coherent;
- protocol-specific assumptions remain outside the crate.

**Primary proof:** unsupported major versions and semantic contradictions fail with typed, secret-safe errors.

### task-005 — Implement redaction safety and secret-safe errors

Implement contract-level redaction protections and safe error behavior.

Required behavior:

- no raw credential field is introduced;
- redaction metadata is mandatory and internally coherent;
- high-risk key names are detected in extensible maps where applicable;
- rejected values are not echoed into errors;
- representative password/token/API-key/private-key/authorization inputs are rejected or sanitized before serialization.

Heuristics are defense-in-depth and must not be documented as complete secret discovery.

**Primary proof:** negative tests demonstrate that representative secret material cannot be emitted accidentally through supported public fields.

### task-006 — Implement deterministic outcome comparison and verdict consistency

Implement the generic comparison boundary and exact comparator described in the Blueprint.

Required properties:

- deterministic comparison is protocol-neutral;
- caller-created contradictory verdicts are rejected;
- `PASS` requires deterministic agreement;
- `FAIL` requires deterministic mismatch;
- `INCONCLUSIVE` represents insufficient evidence rather than success;
- `ERROR` represents evaluation/infrastructure failure rather than a security outcome.

**Primary proof:** the library rejects `expected=DENY`, `observed=ALLOW`, `verdict=PASS` and equivalent contradictions.

## Phase C — Public evidence and proof

### task-007 — Publish synthetic fixtures

Publish exactly the minimum canonical public examples required by the Design:

```text
examples/evidence/pass.json
examples/evidence/fail.json
examples/evidence/inconclusive.json
examples/evidence/error.json
```

Use only synthetic targets and identifiers. No customer-derived data is permitted.

**Primary proof:** all four fixtures pass structural and semantic validation.

### task-008 — Implement contract, round-trip and negative security tests

Build the compatibility/security test suite.

Every public fixture must:

1. deserialize;
2. validate against JSON Schema;
3. pass semantic validation;
4. serialize;
5. deserialize again;
6. remain semantically equivalent.

Negative coverage must include at least:

- unsupported major version;
- missing vector identifier;
- contradictory PASS;
- ERROR without required error context;
- invalid timestamp ordering;
- secret-like raw authorization content;
- invalid verdict enum;
- malformed digest;
- forbidden unknown top-level field.

**Primary proof:** valid corpus is green and every invalid case fails for the intended reason.

### task-009 — Add CI quality gates and documentation

Add the minimal project CI needed to enforce Cycle 001 quality.

Required gates:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Also enforce fixture/schema validation and existing repository secret checks where available.

Document:

- evidence model purpose;
- schema location;
- versioning rules;
- verdict semantics;
- redaction semantics;
- how another implementation can validate the JSON contract independently from Rust.

Do not implement the future DARE Agent Security marketplace/consumer GitHub Action in this task.

**Primary proof:** CI validates the same local quality contract required by the cycle.

### task-010 — Prove Cycle 001 evidence contract end to end

Run the final cycle acceptance proof without adding new product capability.

The proof must demonstrate:

```text
synthetic vector inputs
        -> canonical Rust model
        -> deterministic comparison
        -> verdict derivation/validation
        -> safe evidence serialization
        -> JSON Schema validation
        -> semantic validation
        -> round-trip persistence
```

And simultaneously prove:

- supported v1 evidence validates;
- unknown major version fails closed;
- contradictory verdict fails;
- representative raw secret material is rejected/sanitized;
- PASS/FAIL/INCONCLUSIVE/ERROR fixtures all behave according to documented semantics;
- no network access is required to validate the evidence contract;
- no MCP-specific concept is required by the generic schema;
- Rust formatting, clippy and tests are green.

## Completion criteria

Cycle 001 is complete only when `task-010` proves the approved Design and Blueprint without weakening any security property.

No implementation task may expand the cycle into MCP discovery, active testing, AuthZEN/COAZ vectors, attack graphs, databases, SaaS or customer-specific features.
