# Cycle 018 — Evaluation

**Title:** MCP 2026 Security & Auth Hardening  
**Status:** READY FOR REVIEW  
**Approval:** PENDING  
**Baseline:** `main @ f5906e8b24679b7affffcdc9db5d6116ba9b045d`

## 1. Problem

DARE Agent Security already understands the MCP `2026-07-28` lifecycle and has strong local authorization-to-execution integrity from Cycle 003, but it does not yet expose a dedicated deterministic security engine for the modern MCP authentication and authorization surface.

The missing layer is not “can an OAuth server issue a token?” It is whether recorded MCP protocol/auth evidence proves that the request, authorization metadata, issuer, resource, audience, client registration, PKCE, scope step-up and downstream credential boundaries remained bound to the operation actually being assessed.

Cycle 018 closes that gap without introducing a live OAuth client, live identity-provider integration or production token handling.

## 2. Security question

Given a bounded static, replayed, simulated or local-synthetic MCP `2026-07-28` auth trace, can DARE deterministically prove whether the modern MCP protocol/authentication boundary held for:

- protocol revision;
- HTTP method/name header-to-body binding;
- per-request auth context under the stateless protocol core;
- Protected Resource Metadata;
- authorization-server discovery;
- authorization-response issuer binding;
- resource indicators;
- access-token audience/resource binding;
- inbound token vs upstream credential separation;
- PKCE and redirect/state integrity;
- scope challenge / step-up semantics;
- client registration metadata trust;
- self-reported MCP identity metadata;
- authorization-to-final-operation composition with Cycle 003.

## 3. Current standards baseline

### Normative / current

- Model Context Protocol specification revision `2026-07-28`.
- MCP Authorization specification for the `2026-07-28` revision.
- OAuth 2.1 / bearer-token and metadata standards referenced normatively by the MCP authorization specification, including the MCP requirements around Protected Resource Metadata, authorization-server metadata, resource indicators, PKCE and issuer validation.
- OpenID AuthZEN Authorization API 1.0 remains a final specification where externalized authorization semantics are reused.

### Draft / open proposal

- COAZ Framework / COAZ-MCP remain draft inputs and must retain their published status.
- `openid/authzen#603` remains an `OPEN_PROPOSAL` for authorization-to-execution binding. Cycle 003 already implements the deterministic proof pattern; Cycle 018 must compose with it without rewriting the proposal as normative text.

### Forward-looking, not baseline requirements

The MCP roadmap currently discusses areas such as DPoP, workload identity federation, ID-JAG and standardized token exchange. These are important future hardening surfaces but are not made mandatory Cycle 018 PASS conditions.

Enterprise-Managed Authorization may be represented as an optional extension surface, not a baseline requirement.

## 4. Existing implementation to reuse

### Cycle 001 — evidence

Reuse verdict/evidence vocabulary, stable digests, redaction and bounded product wording.

### Cycle 002 — MCP discovery

Reuse:

- `CURRENT_WIRE_REVISION = 2026-07-28`;
- explicit revision selection;
- current `server/discover` lifecycle;
- legacy `2024-11-05` isolation;
- passive policy gates;
- HTTPS-only production defaults;
- disabled redirects;
- bounded response/time behavior;
- fail-closed unsupported revision handling.

Do not reimplement discovery.

### Cycle 003 — COAZ authorization integrity

Reuse final-operation semantic binding and the reference PEP model. A valid token/permit must not survive a relevant method/name/argument/context mutation without re-evaluation or refusal.

Do not build a second stale-permit engine.

### Cycle 009 — local adversarial safety

Reuse synthetic-only safety controls, hard budgets, zero production state change and zero external egress.

### Cycle 015 — identity / delegation

Reuse principal, delegated subject, tenant and authority concepts. Token claims or MCP metadata must not silently create a second identity model.

## 5. In scope

- MCP `2026-07-28` protocol/auth evidence model;
- method/name header ↔ JSON-RPC body binding;
- stateless per-request authorization-context evidence;
- Protected Resource Metadata evidence;
- authorization-server metadata/discovery evidence;
- issuer mix-up defenses;
- resource indicator binding;
- token audience/resource verification observations;
- inbound-token / upstream-token separation;
- PKCE evidence, including S256 capability where required by the fixture;
- redirect URI and state binding evidence;
- 401 / 403 / insufficient-scope challenge semantics;
- scope step-up union and bounded retry behavior;
- CIMD/pre-registration/DCR trust-policy modeling;
- DCR represented as backwards-compatibility/deprecated path where current MCP guidance says so;
- self-reported `clientInfo` / `serverInfo` treated as metadata, not authenticated identity;
- local replay/simulated/synthetic conformance vectors;
- registry/profile/CLI/reporting/CI/docs integration;
- composition tests with Cycles 002, 003, 015 and existing MCP baseline.

## 6. Out of scope

- logging into a real identity provider;
- browser authorization flows;
- exchanging real authorization codes;
- using real bearer/refresh tokens;
- fetching a live JWKS or authorization-server metadata endpoint;
- live CIMD/DCR registration;
- real client secrets/private keys;
- production MCP endpoints;
- remote protected-resource calls;
- remote token introspection;
- production token revocation;
- arbitrary OAuth provider adapters;
- mandatory DPoP / workload identity / ID-JAG / token exchange support;
- remote authorized dynamic validation, which belongs to Cycle 022;
- replacing Cycle 003 authorization-to-execution integrity;
- replacing Cycle 015 identity/delegation semantics.

## 7. Safety boundary

Cycle 018 is local and deterministic.

Allowed execution modes:

- `REPLAY`
- `SIMULATED`
- `LOCAL_SYNTHETIC`

Hard safety properties:

- production state changes: `0`;
- external egress: `0`;
- remote auth requests: `0`;
- real credentials/tokens: `0`;
- real identity-provider interaction: `0`.

Any scenario or trace that asks DARE to contact an authorization server, token endpoint, metadata URL, JWKS endpoint, registration endpoint, MCP server or upstream API is refused.

## 8. Key design rule

Cycle 018 must preserve these distinctions:

`protocol metadata != authenticated identity`

`token presence != token validity`

`valid token != correct audience`

`correct audience != authorization for final operation`

`MCP inbound token != upstream API credential`

`scope challenge != permission to drop prior scopes`

`same scenario_id != same authorization semantics`

## 9. Verdict semantics

- `PASS`: required positive evidence exists and the invariant held for the tested vector.
- `FAIL`: recorded evidence deterministically proves a security-boundary violation.
- `INCONCLUSIVE`: required evidence is missing or insufficient.
- `ERROR`: the harness could not evaluate the vector.
- parser/refusal outcomes remain separate from security `FAIL`.

No absence-only PASS is allowed.

## 10. Residual risks after Cycle 018

Even a clean Cycle 018 result will not prove:

- a production IdP is correctly configured;
- a real token signature was verified by a production server;
- a production JWKS endpoint is trustworthy;
- a live MCP server enforces the recorded behavior;
- a production gateway does not mutate requests outside recorded evidence;
- DPoP/workload identity/token exchange controls are deployed;
- remote authorized runtime behavior is safe.

Those require deployment-specific evidence and, where authorized, later dynamic validation.
