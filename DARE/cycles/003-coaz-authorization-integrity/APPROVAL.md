# Cycle 003 — Execution Approval

> Cycle: `003-coaz-authorization-integrity`
> Status: **APPROVED FOR EXECUTION**
> Approved: 2026-08-19
> Issue: #4
> Branch: `agent/cycle-003-coaz-authorization-integrity`
> Depends on: Cycle 001 (merged), Cycle 002 (merged)

## Approval decision

All Cycle 003 planning and execution artifacts are approved for implementation.

Canonical artifacts:

- `DESIGN.md`
- `BLUEPRINT.md`
- `TASKS.md`
- `dare-dag.yaml`
- `dag-graph.mmd`
- `EXECUTION/task-001.md` through `EXECUTION/task-012.md`

The approved implementation scope is COAZ-MCP authorization-to-execution integrity conformance (AuthZEN issue #603 candidate vectors) as described by those artifacts.

## Execution rules

1. Follow `dare-dag.yaml` dependency order (CLI adapter: `dare-dag.exec.yaml`).
2. Read the applicable `EXECUTION/task-NNN.md` before modifying code.
3. Preserve the approved Design and Blueprint invariants.
4. Do not redesign the cycle during Execute.
5. If implementation requires a semantic/architectural deviation, stop and return to DARE Review.
6. Mark a task DONE only after its validation gates pass.
7. task-001 MUST reconcile actual merged Cycle 002 crate/module/CLI names before creating duplicates.

## Mandatory security invariants

Authorization integrity must remain deterministic and synthetic-only:

```text
stale permit forwarding after mapping-relevant change => FAIL
semantic equality MUST NOT be raw JSON byte equality
vulnerable reference mode MUST be synthetic-only
no raw credentials in artifacts/logs/errors
Cycle 001 evidence schema MUST remain COAZ/MCP agnostic
issue #603 MUST be represented as open proposal until verified otherwise
no production/customer target execution
no full arbitrary CEL engine without separate review
```

## Required validation baseline

At minimum:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Task-specific schema, vector, binding, E2E integrity and redaction gates defined in the execution specs are also mandatory.

## Critical final proof

Before the cycle can be marked DONE, automated evidence must demonstrate:

- COAZ-INTEGRITY-001..007 execute deterministically;
- vectors 002–005 FAIL under vulnerable stale-permit forwarding;
- vectors 001, 006, 007 PASS under secure reference mode;
- every vector result emits valid Cycle 001 `SecurityEvidence` v1;
- `validate coaz-integrity` CLI works with stable exit semantics.

The final proof must map the approved Design acceptance criteria to concrete tests/files/results.

## Scope exclusions

This approval does not authorize:

- claiming issue #603 is normative while it remains unresolved upstream;
- real payment APIs or external state mutation;
- customer-specific code, findings, URLs, credentials or confidential architecture;
- copying proprietary NEXORA or DARE Runtime code without an explicit IP/licensing decision;
- weakening Cycle 002 passive discovery invariants.

## Completion handoff

When execution is complete, the implementation agent must return with:

- all 12 task statuses;
- implementation commits/diff on the cycle branch;
- validation output;
- dependency/security audit result;
- secure/vulnerable E2E integrity proof;
- any deviations or unresolved risks;
- final task-012 acceptance matrix and upstream contribution package status.

Cycle 003 becomes DONE only after final DARE Review accepts that evidence.
