# Cycle 004 — Execution Approval

> Cycle: `004-ci-security-gate`
> Status: **APPROVED FOR EXECUTION**
> Approved: 2026-08-20
> Branch: `agent/cycle-004-ci-security-gate`
> Depends on: Cycle 001, 002, 003 (merged)

## Approval decision

All Cycle 004 planning and execution artifacts are approved for implementation.

Canonical artifacts:

- `DESIGN.md`
- `BLUEPRINT.md`
- `TASKS.md`
- `dare-dag.yaml`
- `dag-graph.mmd`
- `EVALUATION.md`
- `EXECUTION/task-001.md` through `EXECUTION/task-011.md`

The approved implementation scope is a deterministic GitHub Actions CI security gate that invokes existing CLI capabilities without duplicating domain logic.

## Execution rules

1. Follow `dare-dag.yaml` dependency order (CLI adapter: `dare-dag.exec.yaml`).
2. Read the applicable `EXECUTION/task-NNN.md` before modifying code.
3. Preserve the approved Design and Blueprint invariants.
4. Do not redesign the cycle during Execute.
5. task-001 MUST reconcile actual merged Cycle 003 CLI/crates/fixtures before Action implementation.
6. Mark a task DONE only after its validation gates pass.
7. Do not declare Marketplace availability or stable `v1` release as part of implementation.

## Mandatory security invariants

```text
Action is adapter only — no duplicated domain engine
default mode passive — no active/state-changing MCP operations
explicit target/fixture only — no implicit discovery
no shell eval of Action inputs
no repository write permission required
evidence uses Cycle 001 schema in and out of CI
CI E2E synthetic/local fixtures only
no secrets in logs, outputs, summaries, or artifacts
aggregate verdict derived from machine evidence — not LLM
```

## Required validation baseline

At minimum:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Task-specific Action E2E, hostile-input, and evidence-bridge gates defined in execution specs are mandatory.

## Scope exclusions

This approval does not authorize:

- Agent Attack Graph implementation;
- SARIF/Check Runs as primary output;
- active remote/customer target validation in default Action mode;
- LLM-as-judge for CI verdict;
- Marketplace publish or stable release tagging;
- copying proprietary NEXORA or DARE Runtime code without explicit IP decision.

## Completion handoff

When execution is complete, return with:

- all 11 task statuses;
- implementation diff on the cycle branch;
- Action E2E workflow evidence;
- hostile-input test results;
- final task-011 acceptance matrix (`PROOF.md`);
- any deviations or unresolved risks.

Cycle 004 becomes DONE only after final DARE Review accepts that evidence. Release/tagging remains a separate human decision.
