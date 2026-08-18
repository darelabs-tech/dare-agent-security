# task-004 — Implement schema versioning and semantic validation

> Cycle: `001-evidence-schema`
> Status: PENDING
> Depends on: `task-002`
> Complexity: HIGH

## Objective

Implement typed semantic validation for evidence records beyond JSON Schema structural checks.

## Required implementation

Create semantic validation APIs and typed errors covering at minimum:

- supported schema major version;
- non-empty required semantic identifiers;
- timestamp ordering;
- hash metadata coherence;
- verdict-state prerequisites not owned by structural validation;
- explicit handling of `INCONCLUSIVE` and `ERROR` semantics;
- extension container sanity where present.

Unsupported major versions must fail closed.

## Error model

Use typed errors equivalent to the Blueprint classes:

```text
UnsupportedSchemaVersion
SemanticValidationError
VerdictConsistencyError
RedactionViolation
SerializationError
```

Exact Rust enum/struct organization may vary.

Errors must not echo rejected secret values.

## Versioning rules

- v1-compatible additive optional changes remain within major version 1.
- unknown major versions are rejected.
- validation must not guess semantics for future versions.

## Tests

Cover at minimum:

- accepted `1.x` version according to implemented compatibility rules;
- rejected unsupported major;
- empty semantic IDs rejected;
- invalid timestamp ordering rejected;
- malformed/incoherent hash metadata rejected;
- safe typed error output.

## Validation gates

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Done when

- semantic validation is callable independently from serialization;
- unsupported major versions fail closed;
- errors are typed and secret-safe;
- all semantic invariants defined for this task are covered by tests.
