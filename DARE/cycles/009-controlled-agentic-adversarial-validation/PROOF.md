# Cycle 009 — Final DARE Proof

**Status:** IMPLEMENTED — tasks 002–020  
**Validation date:** 2026-08-20  
**Scope:** Controlled Agentic Adversarial Validation MVP

## Acceptance evidence

1. Cycles 001–008 reconciled: `IMPLEMENTATION-NOTES.md` and `cycle009_reconcile.rs` (5 tests PASS).
2. Validation plan contract: `schemas/adversarial/v1/validation-plan.schema.json`.
3. Test vector contract: `schemas/adversarial/v1/test-vector.schema.json`.
4. Execution budget contract: `schemas/adversarial/v1/execution-budget.schema.json`.
5–7. ROE required for dynamic mode; target/environment/time are checked: `roe.schema.json`, `roe.rs`, `security.rs`.
8–9. Path/vector/budget/ROE approvals use canonical key-sorted SHA-256; the immutable plan digest is captured before execution: `canonical.rs`, `precondition.rs`, `runner.rs`.
10. Mandatory preconditions fail closed: `precondition.rs`.
11–12. Minimum-safe-proof metadata and bounded data-only vectors: `proof_registry.rs`, `vector.rs`.
13–14. Every bound is checked before a step; exhaustion stops without expansion: `budget_enforce.rs`, `budget-exhausted.json`.
15. Kill switch captures state/egress/target/identity/secret/instability/evidence/operator triggers: `kill_switch.rs`, `kill-switch.json`.
16–18. State changes and network egress are denied by default; fixture operations use synthetic identifiers only: `policy.rs`, `runner.rs`, `fixtures/adversarial/`.
19. Cycle 001 `Verdict` is reused by validation results and evidence bridge: `model.rs`, `evidence_bridge.rs`.
20. Cycle 006 registry property IDs are reused by the minimum-safe-proof registry: `proof_registry.rs`.
21–22. Cycle 008 `Path`/`PathStatus` are reused; reclassification creates a new digest and leaves parent history unchanged: `eligibility.rs`, `reclassify.rs`, `security.rs`.
23–29. Eight deterministic fixture scenarios, including budget, kill, and no-safe-proof: `fixtures/adversarial/`, `fixtures_matrix.rs`.
30. CLI defaults to `plan-only`; dynamic mode requires `--roe`: `adversarial.rs`.
31. CI executes only the local confused-deputy fixture: `.github/workflows/ci.yml`.
32. This proof maps implementation, tests, and gates.

## Security proof

`crates/dare-adversarial/tests/security.rs` proves:

- ROE absence and tampering fail closed;
- digest and target substitution are detected;
- code-like argument fields are rejected;
- retry amplification and budget bypass stop before execution;
- secrets and egress trigger the kill switch;
- an extra step is denied;
- canonical digest order is stable;
- reclassification preserves the parent digest.

The runner iterates only `vector.steps` in approved order. It has no discovery loop, callback, shell, network adapter, retry loop, or budget-expansion path.

## Ralph Loop

```text
cargo fmt --all                                           PASS
cargo clippy --workspace --all-targets -- -D warnings     PASS
cargo test -p dare-adversarial -- --nocapture             PASS (14 tests)
cargo test -p dare-agent-security --test cycle009_reconcile PASS (5 tests)
cargo test --workspace                                    PASS
Test-Path fixtures                                        PASS
.dockerignore bare fixtures exclusion                     ABSENT
Dockerfile COPY fixtures                                  PRESENT
```

## Reconciled design choices

- Cycle 008 exposes `Path` (not `AttackPath`); Cycle 009 re-exports it as the compatibility name `AttackPath` and directly reuses `PathStatus`.
- Cycle 008 `PROVEN` is treated as the approved `STATICALLY_PROVEN` equivalent for eligibility. Runtime outcomes remain separate revisions.
- Evidence records are Cycle 009 structured bridge records carrying the Cycle 001 `Verdict`, canonical digests, and redaction state; no second verdict engine exists.
- `--plan` accepts a self-contained plan/vector/budget bundle in the MVP.
- `AUTHORIZED_DYNAMIC` is ROE-gated but only permits `local_only` synthetic execution. Remote dynamic operation is explicitly refused.
