# Cycle 010 — Implementation Notes (task-001 reconciliation)

> Generated: 2026-08-20
> Branch: `agent/cycle-010-continuous-agent-security-validation`
> Baseline merge: `165a0cd` (Cycle 009 merged via PR #15)

Confirms Cycles 001–009 contracts on `main` before Continuous Agent Security Validation work.

## Baseline on main

| Cycle | Evidence |
|-------|----------|
| 001 | `crates/dare-security-evidence/`, `schemas/evidence/v1/` |
| 002 | `crates/dare-mcp-discovery/` — `discover` |
| 003 | `crates/dare-coaz-integrity/` — `validate coaz-integrity` |
| 004 | `action.yml`, `schemas/ci/v1/ci-result.schema.json` (closed) |
| 005 | `crates/dare-mcp-lab/`, `labs/scenarios/` |
| 006 | `crates/dare-coverage/`, `schemas/coverage/v1/registry.json` |
| 007 | `crates/dare-benchmark/`, `validate benchmark` |
| 008 | `crates/dare-attack-graph/`, `validate attack-graph` |
| 009 | `crates/dare-adversarial/`, `validate adversarial` — ROE/budget/kill switch |

MSRV **1.88**. rmcp **3.1.3**. CLI package `dare-agent-security`.

## Reuse — do not fork

| Concern | Reuse |
|---------|-------|
| Verdict / evidence | Cycle 001 |
| Coverage / properties | Cycle 006 |
| Attack graph / paths | Cycle 008 |
| Adversarial validation | Cycle 009 runner/ROE (never weaken) |
| Canonical digests | Cycles 006–009 key-sorted JSON → SHA-256 |
| CI aggregate | Cycle 004 `ci-result.json` stays closed; continuous emits sibling artifacts |

**Cycle 010 must not invent a second evidence, verdict, coverage, property, graph, path, or adversarial engine.**

## Safety freeze

```text
AUTHORIZED_DYNAMIC remains ROE-gated (Cycle 009 authoritative)
reuse only when all security-relevant dependencies unchanged
unknown impact → full fallback
cache never creates PASS by itself
no implicit continuous → dynamic approval escalation
```

## Paths for tasks 002–024

| Task | Intended location |
|------|-------------------|
| 002 | `schemas/continuous/v1/security-state-snapshot.schema.json` |
| 003 | `schemas/continuous/v1/security-changeset.schema.json` |
| 004 | `crates/dare-continuous/src/change_detector.rs` |
| 005 | `crates/dare-continuous/src/dependencies.rs` |
| 006 | `crates/dare-continuous/src/impact.rs` |
| 007 | `schemas/continuous/v1/revalidation-plan.schema.json` |
| 008 | `crates/dare-continuous/src/reuse.rs` |
| 009 | `crates/dare-continuous/src/cache.rs` |
| 010 | `crates/dare-continuous/src/runner.rs` |
| 011 | `crates/dare-continuous/src/fallback.rs` |
| 012 | `crates/dare-continuous/src/drift_property.rs` |
| 013 | `crates/dare-continuous/src/drift_graph.rs` |
| 014 | `crates/dare-continuous/src/drift_validation.rs` |
| 015 | `schemas/continuous/v1/continuous-policy.schema.json` + policy module |
| 016 | `crates/dare-continuous/src/gate.rs` |
| 017 | `crates/dare-continuous/src/history.rs` |
| 018 | CI job + baseline comparison wiring |
| 019 | `fixtures/continuous/` |
| 020 | `crates/dare-continuous/tests/security.rs` |
| 021 | CLI `validate continuous` (snapshot/diff/plan/revalidate/report) |
| 022 | performance baseline tests/docs |
| 023 | `docs/continuous-validation.md` |
| 024 | `PROOF.md` + CORE FEATURE FREEZE |

## CLI direction

```text
dare-agent-security validate continuous \
  --baseline <snapshot.json> \
  --candidate <snapshot.json> \
  --policy <policy.json> \
  --output-dir <path> \
  [--mode plan-only|revalidate]
```

Thin orchestration over dare-continuous. Does not bypass Cycle 009 gates for dynamic execution.

## Invariants for later tasks

- Identical inputs → identical snapshot/plan digests.
- REUSE requires explainable dependency proof.
- UNKNOWN impact forces full revalidation surface.
- After task-024: CORE FEATURE FREEZE before Cycle 011 productization.
