# task-008 — Implement COAZ-INTEGRITY-001 through 007 and Runner

> Status: **DONE**
> Depends on: task-002, task-004, task-005, task-006, task-007

## Objective

Implement the five issue #603 candidate vectors plus two semantic controls as reusable portable fixtures.

## Required vectors

```text
001 unchanged operation
002 mapped tool name change
003 mapped argument change
004 MCP method change
005 mapped trusted context change
006 JSON order/format-only control
007 unmapped field change control
```

## Expected behavior

- 001: existing permit remains usable;
- 002–005: re-evaluate or refuse before sink;
- 006–007: binding remains semantically equal and existing permit remains usable.

## Requirements

- fixture id stable;
- source standards metadata embedded;
- initial/final projection and binding recorded;
- mutation is explicit, not generated fuzz;
- secure reference results PASS;
- vulnerable reference results FAIL for stale-permit cases;
- vector 003 uses a truly mapped synthetic argument.

## Tests

- execute all vectors as unit/integration fixture matrix;
- verify deterministic output across repeated runs excluding timestamps/explicit run ids;
- semantic result validation through task-002 contracts.

## DONE when

All five upstream vectors are implemented and the controls prove correct semantic scoping.

## Execution log

- `vectors/coaz-mcp/authorization-integrity/v1/COAZ-INTEGRITY-001.json` … `007.json` — portable vector fixtures with embedded standards metadata and explicit mutations
- `crates/dare-coaz-integrity/src/runner.rs` — `execute_vector`, `load_builtin_vector`, `RunOptions`, pipeline wiring projector → binding → PDP → mutation → reference PEP → sink
- `crates/dare-coaz-integrity/tests/vectors.rs` — 7 integration tests (secure PASS all vectors; vulnerable FAIL 002–005; binding preserved 006–007; deterministic signatures)
- Ralph Loop: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` — all pass
