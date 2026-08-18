# task-007 — Publish PASS/FAIL/INCONCLUSIVE/ERROR synthetic fixtures

> Cycle: `001-evidence-schema`
> Status: DONE
> Depends on: `task-003`, `task-004`, `task-005`, `task-006`
> Complexity: MED

## Objective

Publish the canonical synthetic evidence examples required by the approved Design.

## Required files

Create:

```text
examples/evidence/pass.json
examples/evidence/fail.json
examples/evidence/inconclusive.json
examples/evidence/error.json
```

## Fixture requirements

- Use only synthetic targets and identifiers.
- Do not use customer-derived names, URLs, schemas, credentials or findings.
- Use a consistent synthetic scenario where practical, such as `synthetic-payment-mcp`.
- Include schema/vector versions, expected/observed outcomes, verdict, redaction metadata and timestamps.
- Include standards mappings only if they are synthetic/generic and do not create an unapproved protocol-specific dependency in the core contract.
- Ensure each fixture demonstrates its verdict semantics clearly.

## Required semantics

- `pass.json`: deterministic expected/observed agreement.
- `fail.json`: deterministic mismatch.
- `inconclusive.json`: insufficient evidence without execution infrastructure error.
- `error.json`: evaluation failure with explicit safe error context.

## Tests

Every fixture must:

1. parse as JSON;
2. validate against JSON Schema;
3. deserialize into Rust;
4. pass semantic validation;
5. preserve its intended verdict semantics.

## Validation gates

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Done when

- all four public fixtures exist;
- all four are synthetic and secret-free;
- all four pass structural and semantic validation;
- each fixture documents a distinct verdict meaning.

## Execution result

- Status: DONE
- Files: `examples/evidence/{pass,fail,inconclusive,error}.json`, `crates/dare-security-evidence/tests/fixtures.rs`
- Notes: synthetic-payment-mcp only; all four pass schema + semantic validation.
