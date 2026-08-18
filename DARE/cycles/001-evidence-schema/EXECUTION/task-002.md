# task-002 — Implement canonical evidence types and wire enums

> Cycle: `001-evidence-schema`
> Status: DONE
> Depends on: `task-001`
> Complexity: HIGH

## Objective

Implement the canonical Rust evidence model and bounded wire enums defined by the approved Blueprint.

## Scope

Implement the generic evidence contract only. The model must remain protocol-neutral and customer-neutral.

## Required implementation

Create the core types needed by `SecurityEvidence`, including at minimum:

- `SchemaRef`;
- `VectorRef`;
- `TargetRef`;
- `Precondition`;
- `NormalizedOperation`;
- `AuthorizationContext`;
- `ExpectedOutcome`;
- `ObservedOutcome`;
- `Verdict`;
- `SeverityAssessment`;
- `StandardMapping`;
- `EvidenceArtifactRef`;
- `HashRef`;
- `RedactionMetadata`;
- `EvidenceTimestamps`;
- top-level `SecurityEvidence`.

Use `serde` for deterministic serialization/deserialization.

Wire enums must use the approved stable uppercase values where specified, including:

```text
PASS
FAIL
INCONCLUSIVE
ERROR
```

and severity/redaction vocabularies from the Blueprint.

## Design requirements

- No implicit verdict default.
- No field intended for raw credentials.
- IDs remain strings in the public contract.
- Protocol-specific attributes may only use deliberate generic extension structures approved by the Blueprint.
- Types must be public only where required for future consumers.
- Derives and trait bounds should support equality-based round-trip tests where sensible.

## Suggested source layout

```text
crates/dare-security-evidence/src/
  lib.rs
  model.rs
  verdict.rs
  version.rs
  redaction.rs
```

Exact file split may vary if semantics and crate boundary remain unchanged.

## Tests

Add unit tests for:

- enum wire serialization;
- enum invalid-value rejection;
- canonical model JSON round trip;
- optional-field behavior;
- absence of implicit defaults that weaken semantics.

## Validation gates

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Done when

- the approved model is represented in Rust;
- wire enum formats are stable and tested;
- a representative `SecurityEvidence` record round-trips through JSON;
- no MCP/customer/proprietary concept has leaked into the core model.

## Execution result

- Status: DONE
- Files: `crates/dare-security-evidence/src/{lib.rs,model.rs,verdict.rs,version.rs,redaction.rs}`, workspace `serde`/`serde_json`/`time` deps
- Gates: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` (18 tests) — pass
- Notes: stable uppercase wire enums; no implicit verdict default; `deny_unknown_fields` on the public record; IDs remain strings.
