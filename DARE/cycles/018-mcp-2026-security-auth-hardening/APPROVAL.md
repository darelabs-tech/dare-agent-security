# Cycle 018 — Product Owner Approval

**Status:** APPROVED FOR EXECUTION  
**Cycle:** 018 — MCP 2026 Security & Auth Hardening  
**Approved at:** 2026-09-06  
**Base:** `main @ f5906e8b24679b7affffcdc9db5d6116ba9b045d`  
**Planning head:** `f65dc30cb1493777c4720625f130752374f3da0c`  
**Branch:** `agent/cycle-018-mcp-2026-security-auth-hardening`

## Approval

The Product Owner explicitly approves all frozen planning artifacts, all 76 acceptance criteria, and all 48 execution tasks for Cycle 018.

Approved artifacts:
- `EVALUATION.md`
- `DESIGN.md`
- `BLUEPRINT.md`
- `TASKS.md`
- `dare-dag.yaml`

Execution may proceed without intermediate Product Owner approval while remaining strictly inside the approved scope and safety boundary.

## Authorized scope

Implement deterministic, evidence-first MCP `2026-07-28` Security & Auth Hardening using only `REPLAY`, `SIMULATED`, and `LOCAL_SYNTHETIC` modes. Approved surfaces include protocol revision and request/header/body binding, Protected Resource Metadata, authorization-server metadata, issuer binding, synthetic token resource/audience semantics, PKCE, redirect/state correlation, scope challenge/step-up, client-registration metadata trust, credential-flow separation, self-reported MCP identity metadata boundaries, evidence integration, bounded CLI/reporting, profile/coverage integration, documentation and CI.

## Required reuse

- Cycle 001 evidence/verdict/redaction contracts;
- Cycle 002 MCP `2026-07-28` discovery/lifecycle and transport-policy contracts;
- Cycle 003 final-operation authorization-to-execution semantic binding and reference PEP behavior;
- Cycle 006 coverage denominator semantics unchanged;
- Cycle 009 local-synthetic budgets and safety controls;
- Cycle 015 principal, tenant, delegation and authority semantics;
- existing MCP baseline and fail-closed revision handling.

## Explicit exclusions

Not authorized:
- production MCP targets;
- live OAuth/OIDC authorization or token exchange;
- browser login or authorization-code flows;
- live IdP, AS metadata, PRM, JWKS, introspection or registration requests;
- real bearer tokens, refresh tokens, cookies, client secrets or private keys;
- live CIMD/DCR registration;
- remote protected-resource or upstream API calls;
- provider-specific OAuth adapters;
- arbitrary shell, callback or executable fields;
- destructive, persistent or production state-changing actions;
- external egress from the Cycle 018 harness;
- making DPoP, workload identity federation, ID-JAG, token exchange or Enterprise-Managed Authorization mandatory baseline requirements;
- replacing Cycle 003 or Cycle 015 semantics;
- remote authorized dynamic validation, reserved for Cycle 022.

## Security invariants

Protocol metadata is not authenticated identity. Token presence is not token validity. A valid token is not sufficient without correct resource/audience binding. Correct token binding is not authorization for a mutated final operation. Inbound MCP credentials must not be reused as upstream credentials. Scope step-up must not silently discard previously required scopes. PASS requires invariant-specific positive evidence; missing required evidence is `INCONCLUSIVE`. LLM prose, heuristic inference and fixture-declared verdicts are never the final judge.

## Standards status discipline

- MCP `2026-07-28`: current normative baseline for this cycle.
- OpenID AuthZEN Authorization API 1.0: normative where applicable.
- COAZ / COAZ-MCP: DRAFT.
- `openid/authzen#603`: OPEN_PROPOSAL unless upstream status changes and is re-verified during execution.
- DPoP/workload identity/ID-JAG/token exchange: forward-looking surfaces, not required PASS criteria.

## Release gate

Before a PR may be opened:
1. tasks 001–048 complete;
2. all 76 acceptance criteria mapped to executed evidence;
3. `cargo fmt --all --check` green;
4. `cargo clippy --workspace --all-targets -- -D warnings` green;
5. `cargo test --workspace` green;
6. `cargo audit` resolved under project policy;
7. Cycle 002/003/013/014/015/016/017 plus Agentic/MCP regressions green where applicable;
8. English and Portuguese mdBook builds green;
9. `python scripts/run-ci-job-locally.py .github/workflows/ci.yml mcp-auth-security-2026` passes by executing the real workflow job;
10. `REGRESSION.md` and `PROOF.md` complete with 76/76 AC mapped;
11. final branch head pushed before PR;
12. PR opened once, preserving the repository's PR-open-only workflow trigger;
13. if the branch changes after the PR opens, the PR CI is stale and the full local gates must be rerun and documented before merge.
