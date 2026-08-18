# task-009 — Add CI quality gates and evidence contract documentation

> Cycle: `001-evidence-schema`
> Status: DONE
> Depends on: `task-008`
> Complexity: MED

## Objective

Automate the Cycle 001 quality contract and document how contributors and non-Rust consumers use the evidence schema safely.

## Required implementation

Add the minimal GitHub Actions workflow required to run the same checks expected locally:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Also ensure CI exercises:

- JSON Schema validation;
- public fixture validation;
- semantic validation through the Rust test suite;
- repository secret checks if an existing safe mechanism is available without expanding cycle scope.

## Documentation requirements

Document at minimum:

- purpose of the evidence contract;
- canonical schema path;
- schema versioning policy;
- PASS/FAIL/INCONCLUSIVE/ERROR semantics;
- structural versus semantic validation;
- redaction semantics and limitations;
- how to validate evidence without network access;
- how non-Rust implementations can consume the JSON Schema;
- compatibility expectations for released fixtures.

Documentation may live in the crate README or a focused docs file, but should be linked from an appropriate public entry point.

## Scope constraints

- Do not build the future consumer-facing `dare-agent-security` GitHub Action.
- Do not add release automation beyond what is necessary for Cycle 001 validation.
- Do not add SaaS, database or MCP integration.

## Validation gates

Run locally where possible:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Confirm the workflow configuration invokes equivalent gates.

## Done when

- CI enforces the Cycle 001 Rust and contract gates;
- evidence documentation is sufficient for an external implementer to locate and understand the v1 contract;
- no unrelated product capability was introduced.

## Execution result

- Status: DONE
- Files: `.github/workflows/ci.yml`, `crates/dare-security-evidence/README.md`, root `README.md` (schema pointer)
- Notes: CI runs fmt/clippy/test; docs cover schema path, versioning, verdicts, redaction limits, offline validation.
