# Cycle 020 — Tasks

**Status:** APPROVED FOR EXECUTION  
**Approval:** APPROVED  
**Baseline:** `main @ d2bff1d3789074dffaae45a7ce57a3563daeb1ff`  
**Branch:** `agent/cycle-020-a2a-inter-agent-security`

All implementation tasks below are approved for execution under `APPROVAL.md`. No additional per-task approval is required while execution remains inside the frozen local/offline safety and semantic boundaries.

- [x] task-001 — Freeze Cycle 020 baseline, scope and compatibility contracts
- [x] task-002 — Record verified OWASP ASI07 and A2A 1.0.0 standards/status snapshot
- [x] task-003 — Additive registry design for Cycle 020 A2A properties with compatibility tests
- [x] task-004 — Add A2A applicability predicates and preserve existing coverage denominators
- [ ] task-005 — Define closed Agent Card/security evidence schemas
- [ ] task-006 — Define closed peer identity, principal and endpoint binding model
- [ ] task-007 — Define closed A2A message/task/context envelope model
- [ ] task-008 — Define authentication verification evidence semantics
- [ ] task-009 — Define skill authorization and local policy evidence model
- [ ] task-010 — Reuse Cycle 015 delegation/authority semantics for inter-agent propagation
- [ ] task-011 — Define tenant and resource-owner boundary projection
- [ ] task-012 — Define data-scope/disclosure boundary projection
- [ ] task-013 — Define replay/idempotency evidence and operation-safety model
- [ ] task-014 — Define protocol version/interface negotiation model
- [ ] task-015 — Define extension declaration/use trust boundary
- [ ] task-016 — Define push-notification configuration safety model without network access
- [ ] task-017 — Implement raw-byte/object/run-wide/output admission ledger
- [ ] task-018 — Implement hostile secret/path/bidi/executable/remote-action refusal layer
- [ ] task-019 — Implement bounded Agent Card importer
- [ ] task-020 — Implement bounded captured A2A exchange importer
- [ ] task-021 — Implement canonical peer/card/message/task normalization
- [ ] task-022 — Implement discovery/Agent Card binding invariant
- [ ] task-023 — Implement peer identity binding invariant
- [ ] task-024 — Implement message authenticity invariant
- [ ] task-025 — Implement security requirement satisfaction invariant
- [ ] task-026 — Implement skill authorization invariant
- [ ] task-027 — Implement A2A message authority-boundary invariant without duplicating Cycle 013
- [ ] task-028 — Implement task/context/principal binding invariant
- [ ] task-029 — Implement authority propagation/non-amplification invariant
- [ ] task-030 — Implement tenant boundary invariant
- [ ] task-031 — Implement data-scope boundary invariant
- [ ] task-032 — Implement replay/idempotency invariant
- [ ] task-033 — Implement protocol negotiation/downgrade invariant
- [ ] task-034 — Implement extension trust-boundary invariant
- [ ] task-035 — Implement push-notification local-only boundary invariant
- [ ] task-036 — Implement invariant-specific PASS/INCONCLUSIVE coverage contracts
- [ ] task-037 — Implement deterministic cross-invariant aggregation preserving Cycle 018 semantics
- [ ] task-038 — Implement STATIC adapter
- [ ] task-039 — Implement offline REPLAY adapter that never re-sends captured traffic
- [ ] task-040 — Implement SIMULATED adapter
- [ ] task-041 — Implement LOCAL_SYNTHETIC adapter under bounded local safety rules
- [x] task-042 — Build A2A-LAB discovery/Agent Card corpus
- [x] task-043 — Build A2A-LAB peer/authentication/skill/message corpus
- [x] task-044 — Build A2A-LAB task/context/delegation/tenant/data corpus
- [x] task-045 — Build A2A-LAB replay/protocol/extension/push corpus
- [x] task-046 — Build hostile/refusal/admission corpus
- [x] task-047 — Build explicit missing-evidence INCONCLUSIVE and multi-violation regressions
- [ ] task-048 — Implement `A2ASecurityResult`, bounded artifacts and Cycle 001 evidence bridge
- [ ] task-049 — Add `agentic-a2a-security-2026` profile
- [ ] task-050 — Add `validate a2a` CLI with local-safe flags only
- [ ] task-051 — Add reproducibility/determinism checks and fixture generators where justified
- [ ] task-052 — Add dedicated `a2a-security-2026` CI job
- [ ] task-053 — Run Cycle 012–019, MCP and coverage compatibility regressions
- [ ] task-054 — Run full workspace fmt/clippy/test/audit gates
- [ ] task-055 — Add EN/PT A2A security concepts/reference documentation and build both books
- [ ] task-056 — Produce `REGRESSION.md` with exact executed evidence and discovered corrections
- [ ] task-057 — Produce `PROOF.md` mapping every approved acceptance criterion to executed evidence

## Execution discipline

For every task:

1. stay inside the frozen local/offline boundary;
2. run focused tests for the changed surface;
3. record exact commands/results in `EXECUTION/task-NNN.md`;
4. never claim PASS from code presence or review prose alone;
5. do not introduce network, credential, remote-key-resolution or target-state capabilities;
6. preserve existing property IDs and earlier-cycle semantics;
7. if implementation requires changing an approved invariant/property/safety semantic, stop the affected task and return it to Review rather than silently widening scope.

## Pre-PR release gate

Before opening the final PR:

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo audit` under repository policy
- `python scripts/run-ci-job-locally.py .github/workflows/ci.yml a2a-security-2026`
- Cycle 012–019 regression surfaces green
- MCP baseline green
- EN mdBook build green
- PT mdBook build green
- `REGRESSION.md` complete
- `PROOF.md` complete
- final branch head pushed

Only then open the implementation PR.