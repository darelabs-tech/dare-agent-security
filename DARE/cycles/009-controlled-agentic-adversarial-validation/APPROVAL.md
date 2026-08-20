# Cycle 009 — Execution Approval

> Cycle: `009-controlled-agentic-adversarial-validation`
> Status: **APPROVED FOR EXECUTION**
> Approved: 2026-08-20
> Branch: `agent/cycle-009-controlled-agentic-adversarial-validation`
> Depends on: Cycles 001–008 merged on `main` (through PR #14 / `40cc7f8`)

## Approval decision

All Cycle 009 planning and execution artifacts are approved for implementation.

Canonical artifacts:

- `DESIGN.md`
- `BLUEPRINT.md`
- `TASKS.md`
- `dare-dag.yaml`
- `dag-graph.mmd`
- `EVALUATION.md`
- `EXECUTION/task-001.md` through `EXECUTION/task-020.md`

The approved implementation scope is **Controlled Agentic Adversarial Validation**: turn selected AttackPath hypotheses into authorized, minimum-risk, budgeted runtime proofs — reusing Cycles 001–008 contracts without duplicating evidence, verdict, coverage, property, graph, or path engines.

## Repository baseline

Planning package assumes `main` = Cycles 001–008. That matches current `main` (`40cc7f8`).

No architectural delta to freeze beyond confirming Cycle 008 is present before task-001.

## Execution rules

1. Follow `dare-dag.yaml` dependency order (CLI adapter: `dare-dag.exec.yaml`).
2. Read the applicable `EXECUTION/task-NNN.md` before modifying code.
3. Preserve the approved Design and Blueprint invariants.
4. Do not redesign the cycle during Execute.
5. task-001 MUST reconcile actual Cycles 001–008 on `main` and map paths for tasks 002–020.
6. Mark a task DONE only after its validation gates pass.
7. Default modes: `PLAN_ONLY` / `SIMULATED` / `LOCAL_SYNTHETIC`. `AUTHORIZED_DYNAMIC` requires explicit valid ROE.

## Mandatory security invariants

```text
reuse Cycles 001–008 — no second evidence/verdict/coverage/property/graph/path engine
minimum safe proof only — no autonomous escalation when a planned vector fails
vectors are data, not code — no embedded shell/Python/eval/callbacks
preconditions fail closed
runtime policy checks every operation against approved plan/vector/ROE/budget
execution budget stops deterministically on any bound
kill switch aborts on unexpected state/egress/target/identity/secrets/instability
missing/invalid ROE blocks dynamic execution
no unauthorized third-party dynamic execution
path reclassification creates new revisions — never rewrites history
```

## Required validation baseline

At minimum:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Task-specific schema, fixture, ROE, budget, kill-switch, and adversarial gates defined in execution specs are mandatory.

## Scope exclusions

This approval does not authorize:

- autonomous adaptive escalation beyond the approved vector;
- unauthorized third-party dynamic / state-changing testing;
- Continuous Agent Security Validation (expected Cycle 010);
- destructive proofs when a safer proof class exists;
- dashboard / SaaS product work;
- copying proprietary NEXORA or DARE Runtime code without explicit IP decision;
- Marketplace publish or stable release tagging.

## Completion handoff

When execution is complete, return with:

- all 20 task statuses;
- implementation diff on the cycle branch;
- plan/vector/budget/ROE schemas and controlled runner;
- fixtures + adversarial security tests;
- CLI/CI regression evidence;
- docs/runbook + final task-020 acceptance matrix (`PROOF.md`);
- any deviations or unresolved risks.

Cycle 009 becomes DONE only after final DARE Review accepts that evidence.
