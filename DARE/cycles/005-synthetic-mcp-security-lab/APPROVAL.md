# Cycle 005 — Execution Approval

> Cycle: `005-synthetic-mcp-security-lab`
> Status: **APPROVED FOR EXECUTION**
> Approved: 2026-08-20
> Branch: `agent/cycle-005-synthetic-mcp-security-lab`
> Depends on: Cycle 001, 002, 003, 004 (merged)

## Approval decision

All Cycle 005 planning and execution artifacts are approved for implementation.

Canonical artifacts:

- `DESIGN.md`
- `BLUEPRINT.md`
- `TASKS.md`
- `dare-dag.yaml`
- `dag-graph.mmd`
- `EVALUATION.md`
- `EXECUTION/task-001.md` through `EXECUTION/task-012.md`

The approved implementation scope is a deterministic synthetic MCP security lab and scenario corpus with secure/vulnerable variants that reuse Cycles 001–004 contracts (evidence, discovery, integrity, CI gate) without duplicating those engines.

## Execution rules

1. Follow `dare-dag.yaml` dependency order (CLI adapter: `dare-dag.exec.yaml`).
2. Read the applicable `EXECUTION/task-NNN.md` before modifying code.
3. Preserve the approved Design and Blueprint invariants.
4. Do not redesign the cycle during Execute.
5. task-001 MUST reconcile actual merged Cycle 004 CLI/Action/fixtures before lab implementation.
6. Mark a task DONE only after its validation gates pass.
7. Do not claim prevalence, production coverage, or Marketplace/stable release as part of implementation.

## Mandatory security invariants

```text
synthetic/local fixtures only — no real customer or production targets
secure + vulnerable variants for each security property
reuse Cycles 001–004 contracts — no second evidence/CI/integrity engine
no real network dependency for security semantics
no real credentials in fixtures or logs
expected FAIL + observed FAIL = scenario assertion PASS
lab isolation — no state leakage between scenarios
```

## Required validation baseline

At minimum:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Task-specific scenario, isolation, hostile-fixture, and CI corpus gates defined in execution specs are mandatory.

## Scope exclusions

This approval does not authorize:

- Agent Attack Graph implementation;
- real-world benchmark corpus against production MCP servers;
- dashboard / UI product work;
- copying proprietary NEXORA or DARE Runtime code without explicit IP decision;
- Marketplace publish or stable release tagging;
- using LLM-as-judge for scenario verdicts.

## Completion handoff

When execution is complete, return with:

- all 12 task statuses;
- implementation diff on the cycle branch;
- scenario catalog (MCP-LAB-001..010) secure/vulnerable matrix;
- CI corpus integration evidence;
- hostile/isolation test results;
- final task-012 acceptance matrix (`PROOF.md`);
- any deviations or unresolved risks.

Cycle 005 becomes DONE only after final DARE Review accepts that evidence.
