# Cycle 020 — Design

## Objective

Implement deterministic, bounded, offline validation for insecure inter-agent communication, centered on A2A protocol evidence and OWASP ASI07.

The engine answers a narrow question:

> Given local A2A discovery documents, captured messages/tasks, local policy and local authentication/delegation evidence, is there sufficient evidence that the peer, message, authority, tenant and protocol context remained correctly bound?

It does **not** answer whether a live remote agent is secure.

## Proposed crate

Add:

`crates/dare-a2a-security`

The crate is additive and must not absorb Cycle 013 prompt-injection, Cycle 014 tool security or Cycle 015 identity engines.

## Canonical model

### Peer identity

`PeerIdentity` must separate:

- logical agent id;
- Agent Card subject/provider identity;
- endpoint/interface identity;
- authenticated principal;
- delegated subject;
- tenant;
- effective authority.

No two fields may be silently substituted for another.

### Agent Card

Normalize local Agent Card evidence into a bounded structure containing only security-relevant fields:

- name/description as untrusted descriptive metadata;
- supported interfaces and protocol versions;
- security schemes;
- security requirements;
- skills and skill identifiers;
- capabilities;
- extensions;
- provider metadata;
- signature metadata/evidence;
- push notification declarations when present.

Descriptive text never grants authority.

### Message/task envelope

Normalize local traces into:

- message id;
- role/source;
- sender identity claim;
- task id;
- context id;
- tenant id;
- requested skill;
- protocol version;
- transport/interface;
- security scheme used;
- auth verification status;
- authority/delegation chain reference;
- data classification/scope labels;
- idempotency/replay key when present;
- extensions used;
- push notification config reference;
- bounded parts/artifacts metadata.

Content is retained only under bounded/redacted evidence rules. Content is never treated as privileged instruction merely because it came from an authenticated peer.

## Closed verification status

Use a closed enum:

- `VALID`
- `INVALID`
- `INDETERMINATE`
- `UNRECORDED`

Only `VALID` may satisfy positive authentication/signature evidence. `INVALID` is concrete FAIL evidence. `INDETERMINATE` and `UNRECORDED` cannot produce PASS.

This intentionally mirrors the corrected Cycle 019 trust-evidence semantics.

## Local evidence types

- `AgentCardEvidence`
- `PeerAuthenticationEvidence`
- `MessageAuthenticationEvidence`
- `DelegationEvidence`
- `AuthorizationPolicy`
- `TenantPolicy`
- `ProtocolPolicy`
- `ReplayPolicy`
- `PushNotificationPolicy`
- `CapturedExchange`

Evidence may refer to external identities/endpoints but may not cause remote resolution.

## Proposed Agentic properties

Preserve existing:

- `AGENT.A2A.MESSAGE_AUTHENTICITY`
- `AGENT.A2A.AUTHORITY_PROPAGATION`

Additive properties proposed for Cycle 020:

- `AGENT.A2A.PEER_IDENTITY_BINDING`
- `AGENT.A2A.DISCOVERY_TRUST_BOUNDARY`
- `AGENT.A2A.SKILL_AUTHORIZATION`
- `AGENT.A2A.MESSAGE_CONTEXT_BINDING`
- `AGENT.A2A.TENANT_BOUNDARY`
- `AGENT.A2A.DATA_SCOPE_BOUNDARY`
- `AGENT.A2A.REPLAY_BOUNDARY`
- `AGENT.A2A.PROTOCOL_NEGOTIATION_INTEGRITY`
- `AGENT.A2A.EXTENSION_TRUST_BOUNDARY`
- `AGENT.A2A.PUSH_NOTIFICATION_BOUNDARY`

No separate top-level `A2A.*` namespace is authorized. The public namespace remains `AGENT.A2A.*`.

## Deterministic invariant set

### I01 — Discovery/Agent Card binding

A peer discovered or selected from local evidence must bind to the expected local policy identity/card digest/interface set. A changed card, unexpected provider or incompatible interface cannot be silently accepted.

### I02 — Peer identity binding

Authenticated peer evidence must bind to the intended logical agent/provider and expected audience/tenant. Service identity cannot silently substitute for user/delegated identity.

### I03 — Message authenticity

A message requiring authentication must have positive valid authentication/signature evidence bound to the exact normalized message/task envelope. Invalid evidence is FAIL; missing deciding evidence is INCONCLUSIVE.

### I04 — Security requirement satisfaction

The security mechanism used by the captured exchange must satisfy one of the locally approved Agent Card/policy security requirements. Merely declaring OAuth/API key/etc. is not evidence that it was satisfied.

### I05 — Skill authorization

Authentication does not imply permission to invoke a skill. The effective principal/delegation must authorize the selected remote skill under local policy.

### I06 — Message authority boundary

Peer-controlled message text, metadata, artifacts and extension payloads remain untrusted data. They must not become authority that overrides local system/application policy. Cycle 020 detects A2A-specific boundary violations but delegates generic prompt-injection semantics to Cycle 013.

### I07 — Task/context binding

Message/task transitions must preserve the expected `taskId`, `contextId`, initiating principal and authorized objective. Cross-task/context substitution is FAIL.

### I08 — Authority propagation

Across each inter-agent delegation edge, authority may remain equal or narrow, never widen subject, audience, tenant, purpose, skill/resource scope or validity beyond the upstream grant.

### I09 — Tenant boundary

Tenant claims/routing fields are not authorization evidence. The effective principal, resource/skill and captured task must remain inside the locally approved tenant boundary.

### I10 — Data-scope boundary

Data labels/scopes carried across the A2A exchange must not widen disclosure or destination scope beyond local policy/delegation.

### I11 — Replay/idempotency boundary

A repeated message/action may PASS only when replay/idempotency evidence proves it is allowed/safe for that operation. Duplicate state-changing intent without deciding idempotency evidence cannot PASS.

### I12 — Protocol negotiation integrity

Protocol version and selected interface/transport must satisfy local policy and the overlap declared by evidence. Downgrade to a disallowed version/interface is FAIL; inability to establish a supported overlap is INCONCLUSIVE or ERROR depending on evidence validity.

### I13 — Extension trust boundary

Used A2A extensions must be declared, locally approved and non-authoritative beyond their contract. Unknown/required authority-bearing extensions fail closed when safe interpretation is impossible.

### I14 — Push notification boundary

Push notification configuration is analyzed only as local data. Destination URL/provider id/credentials are never contacted. A configuration that would delegate or disclose beyond approved callback/tenant/data scope is FAIL; missing verification evidence is INCONCLUSIVE.

## Aggregation

Preserve Cycle 018 semantics:

- any concrete invariant FAIL survives aggregation;
- PASS in one invariant cannot mask FAIL in another;
- missing evidence must not be collapsed to PASS;
- inapplicable invariants are excluded from the denominator according to Cycle 006;
- malformed/unobservable inputs may produce ERROR without manufacturing a security verdict.

## Modes

Supported local modes:

- `STATIC` — Agent Cards + policies + captured documents;
- `REPLAY` — captured A2A exchanges evaluated against local policy without network replay;
- `SIMULATED` — deterministic scenario descriptions converted into normalized local evidence;
- `LOCAL_SYNTHETIC` — synthetic A2A messages/cards generated locally and passed through the same parsers/evaluator.

No mode may establish network connections.

## A2A-LAB corpus

Create at least 44 scenarios:

- 001–006 discovery/card controls and attacks;
- 007–012 peer/authentication controls and attacks;
- 013–018 skill/message authority controls and attacks;
- 019–024 task/context/delegation controls and attacks;
- 025–030 tenant/data-scope controls and attacks;
- 031–035 replay/idempotency controls and attacks;
- 036–039 protocol downgrade/version/interface scenarios;
- 040–042 extension trust scenarios;
- 043–044 push-notification safety scenarios;
- additional explicit missing-evidence INCONCLUSIVE and malformed/refusal vectors as needed.

A fixture stores scenario class and evidence, not the expected verdict. Expectations belong to the harness contract.

## Hostile/refusal corpus

Must include bounded local fixtures for:

- oversized Agent Cards/messages/parts/artifacts;
- deeply nested JSON/object bombs;
- duplicate/conflicting identity/security fields;
- Unicode bidi/control characters in authority-bearing identifiers;
- path traversal in local file references;
- URL/JWKS/jku/token-endpoint/webhook strings proving no fetch occurs;
- secret-like values proving redaction/refusal rules;
- executable/script-like payload metadata proving no execution;
- conflicting auth verification records;
- conflicting tenant/delegation records;
- extension structures whose authority cannot be safely interpreted.

## CLI

Primary command:

`dare-agent-security validate a2a`

Allowed flag classes:

- local Agent Card path;
- local trace path;
- local policy path;
- local auth/delegation evidence path;
- local output directory;
- adapter/mode;
- bounded resource limits.

Forbidden flag classes:

- endpoint/base URL;
- token/API key/client secret;
- username/password;
- private key/certificate/key store;
- OAuth/OIDC login/token acquisition;
- remote Agent Card/JWKS fetch;
- webhook probe;
- command/shell/plugin execution.

## Output artifacts

Suggested:

- `a2a-result.json`
- `a2a-peers.json`
- `a2a-exchanges.json`
- `a2a-evidence.json`
- `a2a-findings.json`
- `summary.md`

Every persisted artifact must pass the run-wide output admission budget before write, including accounting for the result artifact itself.

## Compatibility

Cycle 020 must prove that it:

1. preserves all existing property IDs;
2. does not change earlier profile denominators silently;
3. reuses Cycle 015 identity/delegation semantics instead of weakening them;
4. does not reinterpret Cycle 014 tool authorization as A2A skill authorization;
5. does not reinterpret Cycle 019 external-agent inventory as trust;
6. does not absorb generic prompt-injection verdict authority from Cycle 013;
7. preserves Cycle 018 aggregation;
8. preserves Cycle 001 evidence/redaction/verdict contracts;
9. preserves PR-open-only CI convention;
10. adds no network/credential capability.

## Completion rule

No acceptance criterion is satisfied by code existence or review prose alone. Every criterion must map to executed evidence in `PROOF.md`, and observed defects/corrections must be recorded in `REGRESSION.md`.