# Cycle 008 — Execution Approval

> Cycle: `008-agent-attack-graph-mvp`
> Status: **APPROVED FOR EXECUTION**
> Approved: 2026-08-20
> Branch: `agent/cycle-008-agent-attack-graph-mvp`
> Depends on: Cycles 001–007 merged on `main` (through PR #13 / `ee4428e`)

## Approval decision

All Cycle 008 planning and execution artifacts are approved for implementation.

Canonical artifacts:

- `DESIGN.md`
- `BLUEPRINT.md`
- `TASKS.md`
- `dare-dag.yaml`
- `dag-graph.mmd`
- `EVALUATION.md`
- `EXECUTION/task-001.md` through `EXECUTION/task-018.md`

The approved implementation scope is an **Agent Attack Graph MVP**: transform inventory, authorization, evidence, coverage, and optional benchmark artifacts into a deterministic attack graph with bounded path derivation and safe Mermaid/DOT views — reusing Cycles 001–007 contracts without duplicating evidence, verdict, coverage, property registry, or benchmark engines.

## Repository baseline

Planning package assumes `main` = Cycles 001–007. That matches current `main` (`ee4428e`).

No architectural delta to freeze beyond confirming Cycle 007 is present before task-001.

## Execution rules

1. Follow `dare-dag.yaml` dependency order (CLI adapter: `dare-dag.exec.yaml`).
2. Read the applicable `EXECUTION/task-NNN.md` before modifying code.
3. Preserve the approved Design and Blueprint invariants.
4. Do not redesign the cycle during Execute.
5. task-001 MUST reconcile actual Cycles 001–007 on `main` and map paths for tasks 002–018.
6. Mark a task DONE only after its validation gates pass.
7. Do not autonomously execute attack paths or state-changing third-party tests (Cycle 009 territory).

## Mandatory security invariants

```text
reuse Cycles 001–007 — no second evidence/verdict/coverage/property/benchmark engine
edge evidence state ≠ PASS/FAIL verdict semantics
inferred edges remain visible (never presented as proven exploitation)
identical source artifacts → identical graph digest (deterministic)
authority context required (who / delegated / credential / tenant / authz)
bounded path engine — max_depth, max_paths, cycle detection; unbounded traversal forbidden
analysis and graph derivation only — NOT autonomous exploitation
credentials as logical node IDs only — never credential material in labels
reuse Cycle 001 redaction for secrets
```

## Required validation baseline

At minimum:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Task-specific schema, fixture, path-bound, redaction, and adversarial gates defined in execution specs are mandatory.

## Scope exclusions

This approval does not authorize:

- autonomous exploit-chain execution;
- unauthorized third-party dynamic / state-changing testing;
- Controlled Agentic Adversarial Validation (expected Cycle 009);
- speculative exploitability scoring in the MVP;
- dashboard / SaaS product work;
- copying proprietary NEXORA or DARE Runtime code without explicit IP decision;
- Marketplace publish or stable release tagging.

## Completion handoff

When execution is complete, return with:

- all 18 task statuses;
- implementation diff on the cycle branch;
- Attack Graph schemas and deterministic builder/path engine;
- synthetic fixtures + adversarial tests;
- CLI/CI regression evidence;
- docs + final task-018 acceptance matrix (`PROOF.md`);
- any deviations or unresolved risks.

Cycle 008 becomes DONE only after final DARE Review accepts that evidence.
