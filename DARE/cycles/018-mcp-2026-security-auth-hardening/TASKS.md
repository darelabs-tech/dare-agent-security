# Cycle 018 — Tasks

**Status:** COMPLETE — 48/48 tasks closed, merged as PR #28
**Approval:** APPROVED
**Post-merge:** SECURITY REVIEW APPLIED — see `POST-MERGE-REVIEW.md`

All 48 tasks are closed with recorded evidence. The cycle merged to `main` as
`4e2da94e6738cbecfa7a5243f4928e75c01c2e5b` with 21/21 CI checks green,
`cargo test --workspace` reporting 2799 passing and 0 failing against a 2442
baseline, and `cargo fmt --all --check` and
`cargo clippy --workspace --all-targets -- -D warnings` both clean.

## Post-merge security review

A review after the merge found eleven defects that the 2799 green tests did not
catch, because the tests asserted the behaviour the engine had rather than the
behaviour the cycle claimed. Nine were paths that could produce a **false PASS**
on an authentication or authorization control; two were hygiene.

The corrections are recorded in `POST-MERGE-REVIEW.md`, with the executed
evidence in `REGRESSION.md` §7 and the corrected mappings in `PROOF.md`. The
engine now implements **fifteen** invariants rather than fourteen: the
self-reported metadata boundary was being filed under an invariant about
credential forwarding, and a finding that does not name what it is about sends
an operator to the wrong place.

The history below is kept as it was executed. Nothing in it is deleted, because
a record that is edited to look better afterwards is not a record.

- [x] task-001 — Freeze post-Cycle-017 baseline and compatibility contracts
- [x] task-002 — Record MCP 2026 / OAuth / AuthZEN / COAZ standards status snapshot
- [x] task-003 — Define additive MCP auth properties and applicability semantics
- [x] task-004 — Define protocol/request/header/body evidence schemas
- [x] task-005 — Define Protected Resource Metadata evidence schema
- [x] task-006 — Define Authorization Server Metadata / issuer evidence schema
- [x] task-007 — Define authorization request/response correlation schemas
- [x] task-008 — Define synthetic token claims/resource/audience schema
- [x] task-009 — Define PKCE and redirect/state evidence schemas
- [x] task-010 — Define scope-challenge/step-up evidence schema
- [x] task-011 — Define client-registration metadata trust schema
- [x] task-012 — Define credential-flow separation schema
- [x] task-013 — Define self-reported MCP identity metadata schema
- [x] task-014 — Define scenario/corpus/registry/replay schemas
- [x] task-015 — Implement canonical digests and cross-object semantic bindings
- [x] task-016 — Implement hostile secret/endpoint/executable/control/bidi/path refusal
- [x] task-017 — Define normalized MCP auth observation model
- [x] task-018 — Define invariant-specific positive PASS coverage contracts
- [x] task-019 — Implement deterministic 14-invariant registry
- [x] task-020 — Implement protocol revision + method/name header/body evaluators
- [x] task-021 — Implement PRM/resource binding evaluator
- [x] task-022 — Implement AS metadata + issuer boundary evaluators
- [x] task-023 — Implement authorization-response issuer evaluator
- [x] task-024 — Implement token validity + audience/resource evaluators
- [x] task-025 — Implement PKCE evaluator
- [x] task-026 — Implement redirect/state evaluator
- [x] task-027 — Implement scope step-up + retry-bound evaluator
- [x] task-028 — Implement client-registration trust evaluator
- [x] task-029 — Implement credential separation evaluator
- [x] task-030 — Implement self-reported identity metadata boundary evaluator
- [x] task-031 — Reuse Cycle 015 principal/tenant/delegation semantics
- [x] task-032 — Reuse Cycle 003 final-operation authorization binding
- [x] task-033 — Implement trial ledger and hard/run-wide limits
- [x] task-034 — Implement replay adapter with semantic scenario binding
- [x] task-035 — Implement simulated adapter
- [x] task-036 — Implement local-synthetic adapter under Cycle 009 safety controls
- [x] task-037 — Build protocol/header/PRM/issuer paired corpus
- [x] task-038 — Build token/audience/PKCE/redirect paired corpus
- [x] task-039 — Build scope/registration/credential/identity paired corpus
- [x] task-040 — Add benign controls + missing-evidence INCONCLUSIVE regressions
- [x] task-041 — Add hostile raw-token/secret/endpoint/executable fixtures
- [x] task-042 — Implement independent multi-violation capture and redaction-before-persistence
- [x] task-043 — Implement MCPAuthSecurityResult + Cycle 001 evidence bridge
- [x] task-044 — Add mcp-auth-hardening-2026 profile and coverage integration
- [x] task-045 — Add validate mcp-auth-security CLI + bounded reports
- [x] task-046 — Add dedicated mcp-auth-security-2026 CI job and local workflow execution
- [x] task-047 — Document safe use, identity/auth boundaries, standards status and future DPoP/workload-identity boundary
- [x] task-048 — Run full regression suite and produce REGRESSION.md + PROOF.md (76/76 AC)
