# task-007 — Implement Controlled Mutation Stage and Synthetic Execution Sink

> Status: **DONE**
> Depends on: task-003, task-004

## Objective

Model the post-authorization/pre-execution boundary under deterministic, non-destructive conditions.

## Mutations

```text
NONE
TOOL_NAME
MAPPED_ARGUMENT
METHOD
MAPPED_TRUSTED_CONTEXT
JSON_REORDER_ONLY
UNMAPPED_FIELD
```

## Synthetic sink requirements

- in-process/local only;
- records sanitized final operation;
- records which decision id/binding was used to authorize forwarding;
- no external API;
- no filesystem/business state mutation beyond bounded test artifacts;
- no customer data.

## Reference PEP modes

```text
SecureReevaluate
SecureRefuseOnChange
VulnerableReusePermit
```

`VulnerableReusePermit` must reject any attempt to run outside built-in synthetic fixtures.

## Tests

- each mutation changes only intended fixture fields;
- sink trace is deterministic;
- secure mode refuses/re-evaluates binding mismatch;
- vulnerable mode can intentionally forward with stale binding for proof.

## DONE when

The exact authorization-to-execution gap is instrumented and observable without a real side effect.

## Execution log

- `crates/dare-coaz-integrity/src/mutation.rs` — `OperationMutator`, `DeterministicMutator`, `apply_mutation` for all seven `MutationKind` values
- `crates/dare-coaz-integrity/src/sink.rs` — `SyntheticExecutionSink`, `ReferencePepGateway`, `enforce_reference_pep` with `SecureReevaluate` / `SecureRefuse` (SecureRefuseOnChange) / `VulnerableReuse` (VulnerableReusePermit + synthetic_only guard)
- `crates/dare-coaz-integrity/tests/mutation_sink.rs` — 13 integration tests (mutation field isolation, deterministic sink trace, secure re-evaluate/refuse, vulnerable stale-permit proof)
- Ralph Loop: `cargo build --workspace`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings` — all pass
