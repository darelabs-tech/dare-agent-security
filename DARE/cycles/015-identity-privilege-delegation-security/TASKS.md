# Cycle 015 — Tasks

**Status:** COMPLETE — all 35 tasks executed; see `REGRESSION.md` and `PROOF.md`
**Approval:** APPROVED — see `APPROVAL.md`

- [x] task-001 — Reconcile current main/Cycle 014 baseline and freeze compatibility contracts
- [x] task-002 — Record Cycle 014 lessons and current ASI03/AuthZEN/COAZ provenance
- [x] task-003 — Freeze/add Identity Security AGENT.* properties and applicability predicates
- [x] task-004 — Define principal-set schema and principal-kind model
- [x] task-005 — Define authority-ceiling and effective-authority schemas
- [x] task-006 — Define delegation-chain schema and bounded delegation semantics
- [x] task-007 — Define resource/tenant/owner context schema
- [x] task-008 — Define authorization-policy and authorization-decision schemas
- [x] task-009 — Define canonical operation schema and authorization-relevant projection
- [x] task-010 — Define identity-security scenario, corpus-entry and replay-trace schemas
- [x] task-011 — Define closed principal/delegation/source/trust enums and refusal rules
- [x] task-012 — Implement canonical digests and cross-object identity binding
- [x] task-013 — Define normalized Identity Security observation-event model
- [x] task-014 — Define invariant-specific positive PASS coverage contracts
- [x] task-015 — Implement deterministic Identity Security invariant evaluator registry
- [x] task-016 — Implement authority subset/ceiling comparison
- [x] task-017 — Implement delegation-chain validation, acyclicity and validity windows
- [x] task-018 — Integrate Cycle 003 authorization-to-execution semantic binding
- [x] task-019 — Implement bounded trials, principal/delegation/operation counts and depth limits
- [x] task-020 — Implement replay adapter
- [x] task-021 — Implement simulated adapter
- [x] task-022 — Integrate local-synthetic harness with Cycle 009 controls
- [x] task-023 — Build principal-binding/delegation/privilege corpus with paired fixtures
- [x] task-024 — Build tenant/resource/confused-deputy corpus with paired fixtures
- [x] task-025 — Build authorization-mutation/stale-permit corpus with paired fixtures
- [x] task-026 — Add benign controls and false-positive regressions
- [x] task-027 — Add hostile parser/schema/credential-smuggling fixtures and refusal tests
- [x] task-028 — Implement independent multi-violation capture and credential/redaction hygiene
- [x] task-029 — Implement IdentitySecurityResult and Cycle 001 evidence bridge
- [x] task-030 — Add `identity-security-baseline-2026` profile and coverage integration
- [x] task-031 — Add `validate identity-security` CLI integration
- [x] task-032 — Add product/report integration with bounded-claim and synthetic-evidence wording
- [x] task-033 — Add confidential/offline/no-live-identity regressions and dedicated Cycle 015 CI gate; execute actual workflow job locally
- [x] task-034 — Document operator safe-use semantics and contributor extension rules
- [x] task-035 — Run complete compatibility regression and produce final DARE proof

Execute strictly in `dare-dag.exec.yaml` dependency order. Every task is approved; DONE requires task-specific evidence.