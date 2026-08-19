# Cycle 003 — Tasks: COAZ-MCP Authorization-to-Execution Integrity

> Status: **approved**
> Issue: #4
> Design: `DESIGN.md` (approved)
> Architecture: `BLUEPRINT.md` (approved)
> Approval: `APPROVAL.md`

## Execution contract

Every implementation task must satisfy the workspace gates applicable at that point:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Cycle-wide invariants:

- no production/customer target execution;
- no raw access token or credential serialization;
- no full arbitrary CEL engine unless separately reviewed as unavoidable;
- no claim that issue #603 is normative while it remains unresolved;
- semantic equality, not raw JSON byte equality;
- stale permit forwarding after a mapping-relevant change always yields FAIL;
- Cycle 001 evidence schema remains generic;
- vulnerable mode is impossible outside built-in synthetic fixtures.

## Task table

| ID | Task | Depends on | Complexity | Done when |
|---|---|---|---|---|
| task-001 | Reconcile merged Cycle 002 interfaces + pin standards snapshot | Cycles 001,002 | MEDIUM | implementation plan matches actual main and standards metadata is explicit |
| task-002 | Implement portable vector/result contracts + schemas | 001 | HIGH | vector/result JSON validates offline and invalid semantics fail closed |
| task-003 | Implement semantic normalization + canonicalization | 001 | HIGH | equivalent semantics produce identical canonical form/digest |
| task-004 | Implement authorization binding engine | 003 | HIGH | mapping-relevant changes deterministically change binding |
| task-005 | Implement authorization projector abstractions + synthetic mappings | 001,003 | HIGH | **DONE** — default and declared synthetic projections are deterministic |
| task-006 | Implement deterministic PDP + bound decision model | 004,005 | MEDIUM | permit/deny is fixture-deterministic and bound to the evaluated projection |
| task-007 | Implement controlled mutation stage + synthetic execution sink | 003,004 | HIGH | **DONE** — mutations/traces explicit; in-process sink; PEP modes instrumented |
| task-008 | Implement COAZ-INTEGRITY-001..007 fixtures and runner | 002,004,005,006,007 | HIGH | **DONE** — all five upstream vectors + two semantic controls execute deterministically |
| task-009 | Implement Cycle 001 evidence bridge | 002,008 | MEDIUM | **DONE** — vector results emit valid SecurityEvidence v1 via `dare.coaz.integrity` extensions |
| task-010 | Integrate `validate coaz-integrity` CLI | 008,009 | HIGH | **DONE** — fixture/all/JSON/reference-mode commands work with stable exits |
| task-011 | Add secure/vulnerable E2E proof + negative security tests | 010 | HIGH | **DONE** — stale-permit FAIL proven; secure modes cannot forward stale permits |
| task-012 | Docs, CI, final proof + upstream contribution package | 011 | MEDIUM | **DONE** — docs, PROOF.md, upstream package, operator doc test, CI gates documented |

## Phase A — Baseline and contracts

### task-001 — Reconcile main + standards snapshot

Before coding, inspect actual merged Cycle 002 crate/module/CLI/lab names and update implementation paths without introducing duplicate equivalents.

Record standards metadata for AuthZEN 1.0, COAZ Framework Draft 1, COAZ-MCP Draft 1, MCP 2026-07-28 and upstream issue #603.

### task-002 — Vector/result contracts

Create versioned JSON Schemas and Rust models for portable vector definitions and execution results.

Semantic validation must reject unsupported schema major, missing standards metadata, incoherent expected/observed/verdict combinations and secret-bearing prohibited fields.

### task-003 — Semantic canonicalization

Implement normalized JSON-like values and deterministic canonical serialization/digests. Prove object reordering/formatting equality and mapped-value inequality.

## Phase B — Authorization integrity engine

### task-004 — Binding engine

Implement versioned `BindingMaterialV1` and SHA-256 binding over method, operation name where applicable, mapping identity, mapped inputs, mapped trusted inputs and AuthZEN projection digest.

### task-005 — Projectors

Implement project-owned projector trait plus minimal default `tools/call` and declared `rental.quote` reference projectors. Do not broaden into general CEL conformance.

### task-006 — Deterministic PDP

Build in-process fixture policy and bound decision model. Provide policies that make stale-permit forwarding observable, including original permit + mutated deny cases.

### task-007 — Mutation + sink

Implement explicit mutation enum and in-process execution sink. Every forwarded operation must be traceable to the decision/binding used.

## Phase C — Vectors and evidence

### task-008 — Seven vectors

Implement required upstream candidate vectors 001–005 plus semantic controls 006–007. Run against secure and vulnerable reference modes where meaningful.

### task-009 — Evidence bridge

Map vector results to generic SecurityEvidence v1 without changing the Cycle 001 schema. Reference the full result artifact by path/digest.

### task-010 — CLI

Expose Cycle 003 via the merged validation CLI architecture. Vulnerable mode remains synthetic-only. JSON output is machine-clean.

## Phase D — Proof and standards package

### task-011 — E2E/security proof

Prove vulnerable mode forwards stale permits for 002–005 and receives FAIL; prove secure modes re-evaluate/refuse; prove 006–007 preserve binding; prove canary secrets never leak.

### task-012 — Final proof

Update docs/CI, generate compatibility/status notes, produce final acceptance matrix and prepare neutral vector material suitable for human-reviewed upstream contribution.

## Completion definition

Cycle 003 is DONE only when the repository can deterministically demonstrate both sides of issue #603: a secure PEP prevents stale-permit reuse after mapping-relevant change, while the intentionally vulnerable synthetic PEP produces reproducible FAIL evidence for the same vectors.
