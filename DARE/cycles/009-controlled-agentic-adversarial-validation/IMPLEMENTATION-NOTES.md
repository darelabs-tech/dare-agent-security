# Cycle 009 — Implementation Notes (task-001 reconciliation)

> Generated: 2026-08-20
> Branch: `agent/cycle-009-controlled-agentic-adversarial-validation`
> Baseline merge: `40cc7f8` (Cycle 008 merged via PR #14)

Confirms Cycles 001–008 contracts on `main` before Controlled Agentic Adversarial Validation work.

## Baseline on main

| Cycle | Evidence |
|-------|----------|
| 001 | `crates/dare-security-evidence/`, `schemas/evidence/v1/` — Verdict + redaction |
| 002 | `crates/dare-mcp-discovery/` — `discover` |
| 003 | `crates/dare-coaz-integrity/` — `validate coaz-integrity` |
| 004 | `action.yml`, `schemas/ci/v1/ci-result.schema.json` (closed) |
| 005 | `crates/dare-mcp-lab/`, `labs/scenarios/` |
| 006 | `crates/dare-coverage/`, `schemas/coverage/v1/registry.json` |
| 007 | `crates/dare-benchmark/`, `validate benchmark` |
| 008 | `crates/dare-attack-graph/`, `schemas/attack-graph/v1/`, `validate attack-graph` |

MSRV **1.88**. rmcp **3.1.3**. CLI package `dare-agent-security`.

## Reuse — do not fork

| Concern | Reuse |
|---------|-------|
| Verdict / evidence | Cycle 001 `dare-security-evidence` |
| Coverage / properties | Cycle 006 registry IDs |
| AttackPath / graph | Cycle 008 `dare-attack-graph` |
| Canonical digests | Cycle 006/007/008 key-sorted JSON → SHA-256 |
| Lab / synthetic targets | Cycle 005 fixtures for LOCAL_SYNTHETIC |
| CI aggregate | Cycle 004 `ci-result.json` stays closed; validation emits sibling artifacts |

**Cycle 009 must not invent a second evidence, verdict, coverage, property, graph, or path engine.**

## Safety freeze

```text
Default modes: PLAN_ONLY | SIMULATED | LOCAL_SYNTHETIC
AUTHORIZED_DYNAMIC requires valid ROE + explicit opt-in
vectors are data, not code
no adaptive escalation beyond approved vector steps
preconditions fail closed
budget + kill switch are first-class
```

## Paths for tasks 002–020

| Task | Intended location |
|------|-------------------|
| 002 | `schemas/adversarial/v1/validation-plan.schema.json` |
| 003 | `schemas/adversarial/v1/test-vector.schema.json` |
| 004 | `schemas/adversarial/v1/execution-budget.schema.json` |
| 005 | `crates/dare-adversarial/src/roe.rs` + ROE schema |
| 006 | `crates/dare-adversarial/src/precondition.rs` |
| 007 | `crates/dare-adversarial/src/proof_registry.rs` + builtin registry |
| 008 | `crates/dare-adversarial/src/eligibility.rs` |
| 009 | `crates/dare-adversarial/src/policy.rs` |
| 010 | `crates/dare-adversarial/src/budget.rs` |
| 011 | `crates/dare-adversarial/src/kill_switch.rs` |
| 012 | `crates/dare-adversarial/src/runner.rs` |
| 013 | `crates/dare-adversarial/src/evidence_bridge.rs` |
| 014 | `crates/dare-adversarial/src/reclassify.rs` |
| 015 | `fixtures/adversarial/` |
| 016 | `crates/dare-adversarial/tests/security.rs` |
| 017 | CLI `validate adversarial` |
| 018 | CI job `adversarial-validation` |
| 019 | `docs/adversarial-validation.md` (+ runbook) |
| 020 | `PROOF.md` |

## CLI direction

```text
dare-agent-security validate adversarial \
  --plan <path> \
  --mode plan-only|simulated|local-synthetic|authorized-dynamic \
  --roe <path> \
  --output-dir <path>
```

`authorized-dynamic` without valid ROE → refuse (exit 3).

## Invariants for later tasks

- Identical plan+vector+budget digests → identical validation identity.
- Every executed step emits Cycle 001 evidence.
- Path reclassification creates a new revision; never mutates historical graph digests.
- No secret material in vector labels or evidence payloads.
