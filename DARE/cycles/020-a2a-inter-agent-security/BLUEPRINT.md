# Cycle 020 — Blueprint

## Target architecture

Introduce additive crate `crates/dare-a2a-security`, plus additive registry/profile/CLI/CI/docs integration.

Execution flow:

```text
local Agent Card / captured A2A exchange / local policy / local auth-delegation evidence
        ↓
raw byte admission + schema/version validation
        ↓
hostile/secret/executable/remote-action refusal
        ↓
closed parse into Agent Card + exchange + policy evidence
        ↓
canonical peer/message/task/delegation normalization
        ↓
identity/auth/skill/context/tenant/data/replay/protocol binding
        ↓
deterministic 14-invariant evaluation
        ↓
cross-invariant concrete FAIL aggregation
        ↓
Cycle 001 evidence bridge + Cycle 006 coverage
        ↓
PASS / FAIL / INCONCLUSIVE / ERROR
```

## Suggested modules

- `source.rs`
- `schema.rs`
- `agent_card.rs`
- `peer.rs`
- `message.rs`
- `task.rs`
- `authentication.rs`
- `authorization.rs`
- `delegation.rs`
- `tenant.rs`
- `data_scope.rs`
- `replay.rs`
- `protocol.rs`
- `extension.rs`
- `push_notification.rs`
- `normalize.rs`
- `observation.rs`
- `coverage.rs`
- `invariant.rs`
- `budget.rs`
- `result.rs`
- `evidence_bridge.rs`
- `compat.rs`
- `adapters/static.rs`
- `adapters/replay.rs`
- `adapters/simulated.rs`
- `adapters/local_synthetic.rs`

## Expected artifact trees

- `schemas/a2a-security/v1/`
- `corpus/a2a-security/v1/`
- `fixtures/a2a-security/`
- `standards/a2a-security/2026/`
- `profiles/agentic-a2a-security-2026.json`
- `book/en/src/concepts/a2a-security.md`
- `book/pt/src/concepts/a2a-security.md`
- `book/en/src/reference/extending-a2a-security.md`
- `book/pt/src/reference/extending-a2a-security.md`

## Registry strategy

Reuse:

- `INSECURE_INTER_AGENT_COMMUNICATION`
- `AGENT.A2A.MESSAGE_AUTHENTICITY`
- `AGENT.A2A.AUTHORITY_PROPAGATION`

Add the ten properties proposed in `DESIGN.md` only if registry compatibility tests prove they are additive.

No top-level `A2A.*` namespace.

## Parser boundary

Imported Agent Cards and traces are data only. The parser may not:

- resolve remote Agent Cards;
- connect to advertised endpoints;
- fetch JWKS/JWK/JWS key URLs;
- obtain OAuth/OIDC tokens;
- perform authentication handshakes;
- verify remote TLS;
- send messages/tasks/cancellations;
- invoke push notification callbacks;
- execute artifacts/scripts/tools.

## Admission boundary

Frozen order:

```text
raw input
→ byte admission
→ parse/schema
→ item/part/task/card admission
→ normalized object admission
→ evidence/result admission
→ invariant evaluation
→ output admission before write
```

No over-budget evidence may influence a deciding verdict.

## Authority boundary

The implementation must keep all of these separate:

- descriptive Agent Card text;
- identity claims;
- authentication evidence;
- authorization evidence;
- delegated authority;
- peer message content;
- protocol/extension metadata.

Authenticated data is still data. A valid signature does not convert peer-controlled content into a local privileged instruction.

## Compatibility rules

1. Reuse Cycle 001 evidence/verdict/redaction.
2. Preserve Cycle 006 applicability math.
3. Reuse Cycle 012 risk family/property registry conventions.
4. Delegate generic prompt injection to Cycle 013.
5. Delegate tool execution authorization to Cycle 014.
6. Reuse Cycle 015 principal/delegation/tenant distinctions.
7. Preserve Cycle 018 concrete FAIL aggregation.
8. Reuse Cycle 019 offline trust-evidence semantics and output admission discipline.
9. Do not implement Cycle 021 adaptive multi-turn attack loops.
10. Do not implement Cycle 022 live/remote A2A validation.
11. Do not implement Cycle 023 attack-path graph construction.
12. Add no network, credential, shell or state-changing capability.

## CLI

Primary command:

`dare-agent-security validate a2a`

The CLI must expose local-path/policy/mode/budget/output flags only.

## CI strategy

Add dedicated job `a2a-security-2026` covering:

- schema/version rejection;
- Agent Card parsing and normalization;
- the 14 invariant directions;
- positive PASS coverage requirements;
- missing-evidence INCONCLUSIVE;
- invalid auth evidence FAIL;
- peer/message/task/context/delegation binding;
- tenant/data-scope boundaries;
- replay/idempotency;
- protocol downgrade/version/interface checks;
- extensions;
- push notification local-only safety;
- hostile/refusal/admission fixtures;
- exact JSON assertions rather than substring grep;
- registry/profile compatibility;
- Cycle 012–019 regressions;
- MCP baseline;
- full workspace fmt/clippy/test/audit;
- EN/PT mdBook builds.

Before PR:

`python scripts/run-ci-job-locally.py .github/workflows/ci.yml a2a-security-2026`

## Final proof

Execution ends with:

- `REGRESSION.md`
- `PROOF.md`

Every acceptance criterion must map to executed evidence.