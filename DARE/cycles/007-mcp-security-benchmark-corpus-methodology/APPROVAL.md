# Cycle 007 — Execution Approval

> Cycle: `007-mcp-security-benchmark-corpus-methodology`
> Status: **APPROVED FOR EXECUTION**
> Approved: 2026-08-20
> Branch: `agent/cycle-007-mcp-security-benchmark-corpus-methodology`
> Depends on: Cycles 001–006 merged on `main` (through PR #12 / `306a260`)

## Approval decision

All Cycle 007 planning and execution artifacts are approved for implementation.

Canonical artifacts:

- `DESIGN.md`
- `BLUEPRINT.md`
- `TASKS.md`
- `dare-dag.yaml`
- `dag-graph.mmd`
- `EVALUATION.md`
- `EXECUTION/task-001.md` through `EXECUTION/task-016.md`

The approved implementation scope is a reproducible MCP security **measurement system**: corpus manifests, pinned revisions, coverage-aware aggregation, safe static/local-passive runner, human-validation ledger, responsible disclosure, and a 25–50 target public OSS pilot — reusing Cycles 001–006 contracts without duplicating evidence, coverage, profile, or CI engines.

## Repository baseline

Planning zip assumes `main` = Cycles 001–006. That matches current `main` (`306a260`).

No architectural delta to freeze beyond confirming Cycle 006 (including CI entrypoint fix) is present before task-001.

## Execution rules

1. Follow `dare-dag.yaml` dependency order (CLI adapter: `dare-dag.exec.yaml`).
2. Read the applicable `EXECUTION/task-NNN.md` before modifying code.
3. Preserve the approved Design and Blueprint invariants.
4. Do not redesign the cycle during Execute.
5. task-001 MUST reconcile actual Cycles 001–006 on `main` and map paths for tasks 002–016.
6. Mark a task DONE only after its validation gates pass.
7. Do not claim ecosystem prevalence, Marketplace coverage, or production scanning authorization.

## Mandatory security invariants

```text
pinned commit SHA per target — never a moving branch alone
reuse Cycles 001–006 — no second evidence/verdict/coverage/profile engine
coverage-aware denominators — never hide NA/OOS/BLOCKED as PASS
static/local-passive by default for third-party public OSS
no unauthorized active/dynamic testing of third-party infrastructure
no automatic publish of secrets, credentials, exploit chains, or production endpoints
dedup/lineage — forks/mirrors must not inflate prevalence
pilot corpus validates methodology (25–50), not ecosystem claims
```

## Required validation baseline

At minimum:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Task-specific schema, fixture, runner-safety, disclosure, and corpus gates defined in execution specs are mandatory.

## Scope exclusions

This approval does not authorize:

- internet-wide active scanning;
- unauthorized third-party dynamic testing;
- Agent Attack Graph implementation (expected Cycle 008);
- dashboard / SaaS product work;
- copying proprietary NEXORA or DARE Runtime code without explicit IP decision;
- Marketplace publish or stable release tagging;
- prevalence claims beyond the documented pilot methodology.

## Completion handoff

When execution is complete, return with:

- all 16 task statuses;
- implementation diff on the cycle branch;
- corpus / run / record schemas and pilot corpus;
- aggregation + disclosure + validation evidence;
- CI regression evidence;
- final task-016 acceptance matrix (`PROOF.md`);
- any deviations or unresolved risks.

Cycle 007 becomes DONE only after final DARE Review accepts that evidence.
