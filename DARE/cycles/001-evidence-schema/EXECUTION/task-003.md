# task-003 — Define canonical JSON Schema v1

> Cycle: `001-evidence-schema`
> Status: PENDING
> Depends on: `task-002`
> Complexity: HIGH

## Objective

Create the normative JSON Schema v1 for the public DARE Agent Security evidence contract.

## Scope

Define structural validation only. Semantic invariants remain the responsibility of later Rust validation tasks.

## Required implementation

Create:

```text
schemas/evidence/v1/evidence.schema.json
```

Requirements:

- valid JSON Schema document;
- stable `$id` under the DARE Labs namespace;
- explicit schema version representation;
- required top-level fields matching the approved model;
- strict enum definitions;
- strict object shapes using `additionalProperties: false` where feasible;
- deliberate extension points only;
- digest format constraints;
- timestamp format constraints;
- no network dependency for validation.

## Security constraints

- Do not define credential/token/password/private-key fields.
- Do not add customer-specific properties.
- Do not add MCP/AuthZEN-specific top-level requirements.
- Unknown top-level fields should be rejected unless explicitly routed through an approved extension container.

## Tests

Add schema-validation tests proving that:

- a minimal valid record passes;
- missing required fields fail;
- invalid verdict enum fails;
- malformed digest fails;
- forbidden unknown top-level fields fail;
- malformed timestamps fail structurally where supported by the validator.

The schema must be loaded from the repository, not from the network.

## Validation gates

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Plus schema self-validation using the selected local JSON Schema validator.

## Done when

- `schemas/evidence/v1/evidence.schema.json` is independently usable;
- structural valid/invalid cases are tested;
- the schema matches the approved Rust wire model;
- no protocol/customer-specific coupling exists.
