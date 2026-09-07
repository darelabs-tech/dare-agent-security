# Cycle 018 — Blueprint

## Target architecture

Introduce a new additive crate, expected name `crates/dare-mcp-auth-security`, plus MCP registry/profile/CLI/product/CI integration.

Execution flow:

```text
Scenario / Replay Trace
        ↓
Schema + hostile/secret validation
        ↓
Protocol + MCP header normalization
        ↓
Protected Resource + AS metadata binding
        ↓
Authorization request/response normalization
        ↓
Token/resource/audience + PKCE + redirect/state checks
        ↓
Scope step-up + client-registration + credential-flow checks
        ↓
Cycle 015 principal semantics
        ↓
Cycle 003 final-operation authorization binding
        ↓
Deterministic invariant evaluation
        ↓
Cycle 001 evidence bridge
        ↓
PASS / FAIL / INCONCLUSIVE / ERROR
```

## Modules

Suggested crate modules:

- `source.rs` — closed enums/status types;
- `schema.rs` — compiled-in schemas only;
- `protocol.rs` — MCP revision/header/body projections;
- `metadata.rs` — PRM + AS metadata models;
- `authorization.rs` — request/response correlation and issuer binding;
- `token.rs` — synthetic claims/resource/audience projection only;
- `pkce.rs` — challenge/verifier binding;
- `redirect.rs` — redirect/state binding;
- `scope.rs` — challenge/step-up bounded semantics;
- `registration.rs` — pre-registration/CIMD/DCR trust model;
- `credential.rs` — inbound/upstream credential separation;
- `identity.rs` — self-reported metadata boundary + Cycle 015 reuse;
- `canonical.rs` — stable digests and cross-object binding;
- `observation.rs` — normalized closed event model;
- `coverage.rs` — positive PASS contracts;
- `invariant.rs` — deterministic evaluator registry;
- `trials.rs` — hard/run-wide bounds;
- `replay.rs`;
- `simulated.rs`;
- `local_synthetic.rs`;
- `result.rs`;
- `evidence_bridge.rs`;
- `compat.rs` — Cycle 002/003/015 reuse and non-duplication assertions.

## Expected artifact trees

- `schemas/mcp-auth-security/v1/`
- `corpus/mcp-auth-security/v1/`
- `fixtures/mcp-auth-security/`
- `standards/mcp-auth-security/2026/`
- `profiles/mcp-auth-hardening-2026.json`
- `book/en/src/concepts/mcp-auth-security.md`
- `book/pt/src/concepts/mcp-auth-security.md`
- `book/en/src/reference/extending-mcp-auth-security.md`
- `book/pt/src/reference/extending-mcp-auth-security.md`

## Compatibility rules

1. Do not duplicate MCP discovery/handshake logic from Cycle 002.
2. Do not duplicate stale-permit/final-operation binding from Cycle 003.
3. Do not create a second principal/tenant model; reuse Cycle 015 semantics.
4. Do not change Cycle 006 coverage denominator mathematics.
5. Do not add an Agentic RiskFamily.
6. Do not add live OAuth/OIDC/IdP/JWKS/registration/network dependencies.
7. Do not persist raw credentials/tokens/codes/secrets.
8. Do not treat `clientInfo`/`serverInfo` as authenticated identity.
9. Do not make DPoP/workload identity/ID-JAG/token exchange mandatory baseline controls.
10. Do not add arbitrary executable fields.

## Security boundary

All auth scenarios are replayed, simulated or local-synthetic. All issuer/resource/token/metadata representations are closed fixture evidence. Network egress and state changes remain zero.

## CI strategy

Dedicated job `mcp-auth-security-2026` must test:

- schemas + hostile secret fixtures;
- all 14 invariant PASS/FAIL directions where meaningful;
- missing-evidence INCONCLUSIVE;
- current/legacy protocol isolation;
- header/body method/name mismatch;
- PRM/issuer/resource/audience semantics;
- PKCE/redirect/state semantics;
- scope step-up semantics and bounded retry;
- client-registration trust;
- credential separation;
- self-reported identity metadata boundary;
- Cycle 003 final-operation composition;
- no-live-mode/no-credential/no-endpoint flags;
- secret/redaction hygiene;
- Cycle 002/003/013/014/015/016/017 regressions;
- Agentic/MCP baseline regressions;
- bounded product wording;
- EN/PT docs build.

## Final proof

Task finalization must produce `REGRESSION.md` and `PROOF.md`. Every acceptance criterion must map to executed evidence, not merely code existence or intent.
