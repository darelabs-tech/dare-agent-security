# Cycle 006 — Execution Approval

> Cycle: `006-assessment-profiles-coverage-engine`
> Status: **APPROVED FOR EXECUTION**
> Approved: 2026-08-20
> Branch: `agent/cycle-006-assessment-profiles-coverage-engine`
> Depends on: Cycle 001, 002, 003, 004 (core); Cycle 005 merged on `main` (PR #10) — adapter only

## Approval decision

All Cycle 006 planning and execution artifacts are approved for implementation.

Canonical artifacts:

- `DESIGN.md`
- `BLUEPRINT.md`
- `TASKS.md`
- `dare-dag.yaml`
- `dag-graph.mmd`
- `EVALUATION.md`
- `EXECUTION/task-001.md` through `EXECUTION/task-014.md`

The approved implementation scope is a deterministic assessment-coverage layer (property registry, profiles, applicability, plan, correlation, reports, CLI/CI thresholds) that reuses Cycles 001–004 contracts and does not replace evidence, discovery, integrity, CI, or the Cycle 005 lab engine.

## Repository delta vs planning zip

The imported package was written against `main` = Cycles 001–004, with Cycle 005 **not assumed**.

At approval time, `main` already contains Cycle 005 (merge `73d6d13`, PR #10).

Frozen execution interpretation:

1. Core Cycle 006 remains independent of the lab corpus: property IDs and coverage math come from Cycles 001–004 capabilities.
2. task-001 must **record** that Cycle 005 is present on `main`; do **not** stop or redesign because the zip baseline is older.
3. Do not treat Cycle 005 files as a second coverage engine. Use them only for the optional adapter.
4. task-013 is **APPLICABLE** (Cycle 005 merged). Map lab scenario IDs to property IDs without changing core coverage semantics.
5. task-014 waits on task-013 in this execution round.

## Execution rules

1. Follow `dare-dag.yaml` dependency order (CLI adapter: `dare-dag.exec.yaml`).
2. Read the applicable `EXECUTION/task-NNN.md` before modifying code.
3. Preserve the approved Design and Blueprint invariants.
4. Do not redesign the cycle during Execute.
5. task-001 MUST reconcile actual merged Cycles 001–005 on `main` and map paths for tasks 002–014.
6. Mark a task DONE only after its validation gates pass.
7. Do not claim completeness of real-world assessments, prevalence, or Marketplace/stable release.

## Mandatory security invariants

```text
coverage is not a second verdict engine — reuse Cycle 001 evidence
profiles are data, not executable code
applicability is deterministic — no LLM-only decisions
CoverageStatus is distinct from Cycle 001 PASS/FAIL
no silent property deletion or denominator manipulation
no customer source, secrets, or production targets in fixtures
Cycle 005 adapter must not change core coverage semantics
```

## Required validation baseline

At minimum:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Task-specific schema, fixture, adversarial, CLI/CI, and (when applicable) Cycle 005 adapter gates defined in execution specs are mandatory.

## Scope exclusions

This approval does not authorize:

- replacing Cycles 001–005 engines;
- Agent Attack Graph implementation;
- dashboard / UI product work;
- copying proprietary NEXORA or DARE Runtime code without explicit IP decision;
- Marketplace publish or stable release tagging;
- using LLM-as-judge for applicability or coverage.

## Completion handoff

When execution is complete, return with:

- all 14 task statuses (task-013 DONE, not NOT_APPLICABLE);
- implementation diff on the cycle branch;
- property registry and profile artifacts;
- coverage report / CI threshold evidence;
- adversarial denominator tests;
- Cycle 005 adapter mapping;
- final task-014 acceptance matrix (`PROOF.md`);
- any deviations or unresolved risks.

Cycle 006 becomes DONE only after final DARE Review accepts that evidence.
