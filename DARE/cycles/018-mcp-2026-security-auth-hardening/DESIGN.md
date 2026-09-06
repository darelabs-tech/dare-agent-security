# Cycle 018 — Design

**Status:** READY FOR REVIEW  
**Approval:** PENDING

## 1. Objective

Implement a deterministic, evidence-first MCP 2026 Security & Auth Hardening engine that evaluates bounded local evidence for modern MCP authentication and authorization boundaries without contacting real identity providers, authorization servers, JWKS endpoints, registration endpoints, MCP servers or upstream APIs.

## 2. Core principles

`protocol metadata != authenticated identity`

`token presence != token validity`

`valid token != correct audience`

`correct audience != authorization for final operation`

`MCP inbound token != upstream credential`

`scope challenge != permission to discard prior scopes`

`same scenario_id != same authorization semantics`

## 3. Additive MCP security properties

Add specialized properties under the existing MCP namespace. Proposed exact IDs:

1. `MCP.AUTH.PROTOCOL_BINDING`
2. `MCP.AUTH.PROTECTED_RESOURCE_METADATA`
3. `MCP.AUTH.AUTHORIZATION_SERVER_BINDING`
4. `MCP.AUTH.TOKEN_AUDIENCE_RESOURCE_BINDING`
5. `MCP.AUTH.PKCE_REDIRECT_STATE_INTEGRITY`
6. `MCP.AUTH.SCOPE_STEP_UP_INTEGRITY`
7. `MCP.AUTH.CLIENT_REGISTRATION_TRUST`
8. `MCP.AUTH.CREDENTIAL_SEPARATION`
9. `MCP.IDENTITY.SELF_REPORTED_METADATA_BOUNDARY`
10. `MCP.AUTH.FINAL_OPERATION_BINDING`

Do not rename or weaken existing MCP properties from Cycles 001–003/006.

Do not add a new Agentic `RiskFamily` for these properties.

## 4. Standards status

Each property must carry versioned standards provenance.

### NORMATIVE

- MCP `2026-07-28` protocol.
- MCP `2026-07-28` authorization specification.
- OAuth-related normative dependencies referenced by MCP where the property directly evaluates those semantics.
- OpenID AuthZEN Authorization API 1.0 only where an externalized authorization mapping is actually used.

### DRAFT

- COAZ Framework / COAZ-MCP published draft text.

### OPEN_PROPOSAL

- `openid/authzen#603` for permit-to-final-operation binding clarification.

### INFORMATIVE / FUTURE

- MCP roadmap items such as DPoP, workload identity federation, ID-JAG and standardized token exchange. They must not become baseline PASS requirements.

## 5. Applicability predicates

Introduce only closed, explicit predicates needed to determine target shape or evidence availability. Candidate additions:

- `mcp_current_protocol_present`
- `mcp_http_transport_present`
- `mcp_auth_flow_present`
- `protected_resource_metadata_present`
- `authorization_server_metadata_present`
- `token_claims_present`
- `pkce_context_present`
- `scope_challenge_present`
- `client_registration_present`
- `credential_forwarding_present`
- `mcp_identity_metadata_present`

Important semantic rule:

- target-shape predicates may produce `NOT_APPLICABLE` when the relevant surface truly does not exist;
- missing control/evidence predicates MUST NOT convert an applicable auth surface into `NOT_APPLICABLE` merely because the control is absent;
- missing required evidence on an applicable surface generally yields `INCONCLUSIVE` or a deterministic `FAIL` where absence itself is a violated mandatory control.

## 6. Typed evidence model

Define versioned, closed schemas for:

- MCP auth scenario;
- protocol request envelope;
- MCP header projection;
- JSON-RPC method/name projection;
- Protected Resource Metadata snapshot;
- Authorization Server Metadata snapshot;
- authorization request context;
- authorization response context;
- token claims projection;
- resource indicator / audience context;
- PKCE context;
- redirect URI / state context;
- scope challenge / step-up context;
- client registration metadata context;
- credential forwarding context;
- MCP self-reported identity metadata;
- final-operation authorization binding;
- replay trace;
- scenario registry / corpus entry.

No raw secrets are required.

Token evidence must use only bounded synthetic/derived claims such as:

- synthetic token id/digest;
- issuer;
- subject id;
- audience/resource ids;
- scope set;
- expiry/not-before status;
- token type/class;
- verification-status enum supplied by deterministic fixture evidence;
- binding references/digests.

Never store raw bearer/refresh tokens, authorization codes, client secrets, private keys or cookies.

## 7. Protocol binding model

For MCP `2026-07-28`, model the transport-level method/name routing metadata and JSON-RPC body semantics as two independently observed sides.

Security decision compares normalized semantics, not raw byte equality.

At minimum record:

- declared/observed MCP method header;
- declared/observed MCP name header where applicable;
- JSON-RPC method;
- JSON-RPC operation/tool name where applicable;
- normalized request digest;
- protocol revision.

A mismatch that changes routed semantics must never PASS.

## 8. Protected Resource Metadata / AS discovery model

Protected Resource Metadata and Authorization Server Metadata are evidence, not implicit trust.

Model:

- protected resource identifier;
- advertised authorization server issuer(s);
- metadata source/binding digest;
- authorization endpoint/token endpoint identifiers as synthetic URIs/ids;
- supported code challenge methods;
- registration method/trust class;
- metadata issuer consistency;
- resource/audience expectations.

No live fetch occurs in Cycle 018.

## 9. Issuer and authorization-response binding

A client must not accept an authorization response from a different authorization server context than the one selected for the protected resource/request.

Record and compare:

- selected authorization-server issuer;
- authorization-response issuer evidence where applicable;
- token issuer;
- metadata issuer;
- client/request correlation id.

Issuer mix-up evidence is a deterministic violation.

## 10. Token audience/resource binding

A token that is synthetically marked signature/claims-valid may still be invalid for the assessed MCP resource.

The evaluator must independently verify from evidence:

- expected MCP protected resource;
- resource indicator requested;
- token audience/resource claim(s);
- target MCP resource actually receiving the request.

A token minted for resource B must not authorize resource A.

## 11. Credential separation

An inbound MCP credential must not be reused blindly as an upstream API credential.

Model credential flow only as digests/classes:

- inbound credential reference;
- credential class;
- upstream credential reference;
- exchange/delegation evidence if applicable;
- forwarding decision.

Invariant:

`inbound_mcp_token != upstream_service_token`

unless explicit typed exchange/delegation evidence proves the relationship and the relevant policy permits it.

Cycle 018 does not perform real token exchange.

## 12. PKCE / redirect / state integrity

Model deterministic authorization-flow evidence for:

- PKCE required/present;
- challenge method;
- verifier/challenge digest binding;
- redirect URI registered/requested/returned binding;
- state/correlation preservation;
- authorization response bound to the original request.

No browser or authorization code exchange occurs.

Where a scenario declares modern public-client authorization-code semantics requiring PKCE, absence or downgrade from the required method is a violation.

## 13. Scope challenge / step-up integrity

A scope challenge may ask the client to retry with more privilege, but existing required/requested scope cannot be silently discarded.

Model:

- initial scope set;
- challenge required scope set;
- retried scope set;
- granted token scope set;
- retry count;
- resource/method/name binding.

Required relationship:

`retry_scopes >= initial_required_scopes ∪ challenge_required_scopes`

subject to the declared fixture semantics.

Hard cap retries; no loops.

## 14. Client registration trust

Model client registration as typed metadata with trust source:

- pre-registered;
- CIMD / client metadata document;
- dynamic registration legacy/deprecated path;
- unknown/untrusted.

The security engine evaluates trust/binding of recorded registration metadata. It does not perform registration.

A redirect URI/client identifier cannot be accepted solely because an untrusted trace says it is registered.

## 15. Self-reported MCP identity metadata

`clientInfo`, `serverInfo`, titles/names/versions and related protocol metadata are not authenticated identity by themselves.

A scenario may record them for inventory/correlation, but they cannot establish:

- principal identity;
- tenant identity;
- OAuth subject;
- workload identity;
- authorization scope.

Reuse Cycle 015 identity semantics for authoritative principal context.

## 16. Final-operation authorization composition

Cycle 018 must compose with Cycle 003 rather than duplicate it.

After MCP auth evidence is validated, any authorization result/permit represented by the scenario remains bound to the final normalized operation.

Relevant changes to:

- MCP method;
- operation/tool name;
- mapped arguments;
- resource/audience context;
- trusted principal/tenant context;
- authorization-relevant scope/context

require re-evaluation or refusal according to the Cycle 003 reference PEP contract.

## 17. Normalized observations

Use a closed model including at least:

- `MCP_PROTOCOL_CONTEXT`
- `MCP_HEADER_CONTEXT`
- `JSONRPC_OPERATION_CONTEXT`
- `PROTECTED_RESOURCE_METADATA`
- `AUTHORIZATION_SERVER_METADATA`
- `AUTHORIZATION_REQUEST_CONTEXT`
- `AUTHORIZATION_RESPONSE_CONTEXT`
- `TOKEN_CLAIMS_CONTEXT`
- `RESOURCE_AUDIENCE_CONTEXT`
- `PKCE_CONTEXT`
- `REDIRECT_STATE_CONTEXT`
- `SCOPE_CHALLENGE_CONTEXT`
- `CLIENT_REGISTRATION_CONTEXT`
- `CREDENTIAL_FLOW_CONTEXT`
- `MCP_IDENTITY_METADATA`
- `FINAL_OPERATION_BINDING`
- `HARNESS_ERROR`

Adapters cannot assert final verdict.

## 18. Deterministic invariants

Implement exactly these initial 14 invariants unless Review finds a concrete missing security dimension before approval:

1. `MCP_PROTOCOL_REVISION_PRESERVED`
2. `MCP_METHOD_HEADER_BODY_BINDING_PRESERVED`
3. `MCP_NAME_HEADER_BODY_BINDING_PRESERVED`
4. `PROTECTED_RESOURCE_METADATA_BOUND_TO_RESOURCE`
5. `AUTHORIZATION_SERVER_ISSUER_BOUNDARY_PRESERVED`
6. `AUTHORIZATION_RESPONSE_ISSUER_PRESERVED`
7. `TOKEN_RESOURCE_AUDIENCE_BOUNDARY_PRESERVED`
8. `TOKEN_VALIDITY_EVIDENCE_PRESENT`
9. `PKCE_BINDING_PRESERVED`
10. `REDIRECT_STATE_BINDING_PRESERVED`
11. `SCOPE_STEP_UP_DOES_NOT_DROP_REQUIRED_SCOPE`
12. `CLIENT_REGISTRATION_METADATA_TRUST_PRESERVED`
13. `INBOUND_CREDENTIAL_NOT_REUSED_AS_UPSTREAM_AUTHORITY`
14. `FINAL_OPERATION_AUTHORIZATION_BINDING_PRESERVED`

## 19. Positive PASS coverage

PASS is property/invariant-specific and requires positive evidence.

Examples:

- method/name binding requires both header-side and body-side normalized semantics;
- token audience requires expected protected resource plus token audience/resource projection;
- issuer binding requires selected AS metadata plus response/token issuer evidence;
- PKCE requires declared requirement plus challenge/verifier binding observations;
- scope step-up requires initial/challenge/retry scope observations;
- credential separation requires inbound and upstream credential-flow observations;
- final-operation binding requires Cycle 003-compatible initial and final authorization projections/bindings.

Missing required channels -> `INCONCLUSIVE`, never PASS.

## 20. Independent violation collection

One trace may simultaneously prove method mismatch, issuer mismatch, wrong audience and credential forwarding. Preserve every independent applicable violation before any later-trial stop condition.

`stop_on_first_fail` may only stop subsequent trials after current-trial evidence has been retained.

## 21. Modes

Only:

- `REPLAY`
- `SIMULATED`
- `LOCAL_SYNTHETIC`

No live OAuth/OIDC/IdP/MCP auth mode.

## 22. Hard bounds

Initial defaults/maxima:

- default_trials: 3
- hard_max_trials: 10
- hard_max_requests_per_trial: 8
- hard_max_total_requests: 24
- hard_max_metadata_documents: 8
- hard_max_authorization_servers: 8
- hard_max_audiences_per_token: 16
- hard_max_scopes_per_context: 32
- hard_max_scope_step_up_retries: 2
- hard_max_registration_redirect_uris: 16
- hard_max_claim_fields: 64
- max_output_bytes_per_trial: 16384
- max_total_output_bytes: 65536
- max_duration_seconds_per_trial: 30
- max_state_changes: 0
- external_egress_bytes: 0

Over-limit inputs are refused; never clamp upward. Run-wide counters cannot reset per trial.

## 23. Parser / secret safety

Refuse or sanitize before persistence:

- raw `Authorization` header values;
- bearer/refresh tokens;
- authorization codes;
- client secrets;
- private keys;
- cookies/session tokens;
- raw PKCE verifier values if fixture can use digests instead;
- live endpoint instructions requiring network access;
- executable/callback/command fields;
- expected-verdict fields;
- arbitrary remote URLs outside the bounded synthetic metadata model;
- control characters/bidi spoofing in ids/issuers/resources;
- path traversal;
- malformed object references;
- oversized arbitrary claims/blobs.

Synthetic URI-like metadata may be represented only through a closed, non-fetchable fixture schema.

## 24. Minimum MCP-AUTH-LAB corpus

Create at least 28 local scenarios:

1. current protocol + matching method/name PASS
2. unsupported/downgraded protocol REFUSE/FAIL-CLOSED
3. method header/body mismatch FAIL
4. name header/body mismatch FAIL
5. PRM bound to expected resource PASS
6. PRM resource mismatch FAIL
7. selected AS issuer consistent PASS
8. AS/metadata issuer mismatch FAIL
9. authorization response issuer consistent PASS
10. authorization response issuer mix-up FAIL
11. correct token audience/resource PASS
12. wrong audience/resource FAIL
13. token validity evidence present PASS
14. missing validity evidence INCONCLUSIVE
15. PKCE S256 binding PASS
16. missing/downgraded required PKCE FAIL
17. redirect/state preserved PASS
18. redirect URI or state substitution FAIL
19. scope step-up union preserved PASS
20. retry drops initial required scope FAIL
21. retry limit exceeded REFUSE
22. trusted pre-registration/CIMD metadata PASS
23. untrusted registration metadata substitution FAIL
24. inbound credential isolated from upstream credential PASS
25. inbound bearer forwarded as upstream authority FAIL
26. self-reported client/server metadata not promoted to identity PASS
27. self-reported metadata used as authoritative principal FAIL
28. auth permit mutated before final operation FAIL
29. multiple independent auth violations retained
30. hostile raw token/secret/remote-endpoint/executable fields REFUSE

Minimum requirement is 28; scenarios 29–30 are recommended and should be included unless execution discovers a concrete architecture reason not to.

## 25. Reuse contracts

- Cycle 001 owns evidence vocabulary/redaction.
- Cycle 002 owns MCP discovery and revision negotiation.
- Cycle 003 owns authorization-to-execution mutation/binding.
- Cycle 009 owns local-synthetic safety budget concepts.
- Cycle 015 owns principal/tenant/delegation semantics.
- Cycle 017 retrieval semantics remain independent.

No duplicate engines.

## 26. Profile

Add `profiles/mcp-auth-hardening-2026.json` selecting Cycle 018 MCP properties.

Do not change prior profiles or Cycle 006 denominator semantics.

## 27. CLI

Add:

`dare-agent-security validate mcp-auth-security`

Allowed local flags may include:

- `--scenario`
- `--mode replay|simulated|local-synthetic`
- `--trace`
- `--trials`
- `--output-dir`
- `--json`

Prohibited flags/surfaces include:

- `--url`
- `--endpoint`
- `--authorization-server`
- `--token-endpoint`
- `--jwks-url`
- `--issuer-url`
- `--client-secret`
- `--access-token`
- `--refresh-token`
- `--authorization-code`
- `--private-key`
- `--cookie`
- `--remote`
- `--command`

## 28. Outputs

Expected artifacts:

- `mcp-auth-security-result.json`
- `mcp-auth-security-trials.json`
- `mcp-auth-security-evidence.json`
- `summary.md`

Approved bounded PASS wording:

`No MCP 2026 authentication/authorization hardening invariant violation was observed for the tested vectors under the recorded conditions.`

Never emit universal claims such as “MCP Auth Secure”.

## 29. CI

Add dedicated job:

`mcp-auth-security-2026`

It must run under the repository's existing PR-open-only CI policy.

Before PR creation execute the actual job locally using:

`python scripts/run-ci-job-locally.py .github/workflows/ci.yml mcp-auth-security-2026`

Mandatory regression surfaces:

- MCP discovery/current + legacy isolation;
- Cycle 003 COAZ integrity;
- Cycle 013 prompt injection;
- Cycle 014 tool security;
- Cycle 015 identity security;
- Cycle 016 memory security;
- Cycle 017 RAG security;
- Agentic registry/coverage;
- MCP baseline;
- full workspace;
- docs EN/PT.

## 30. Acceptance criteria

Execution must map every criterion to concrete executed evidence in `PROOF.md`.

AC-01 baseline is pinned to `f5906e8b24679b7affffcdc9db5d6116ba9b045d`.  
AC-02 current MCP revision remains `2026-07-28`.  
AC-03 legacy `2024-11-05` remains isolated and unsupported revisions fail closed.  
AC-04 standards statuses distinguish NORMATIVE/DRAFT/OPEN_PROPOSAL/FUTURE.  
AC-05 ten exact Cycle 018 properties are additive.  
AC-06 prior MCP property IDs remain unchanged.  
AC-07 no Agentic RiskFamily is added.  
AC-08 applicability does not turn missing auth controls/evidence into incorrect NOT_APPLICABLE.  
AC-09 typed scenario schema exists.  
AC-10 typed replay trace schema exists.  
AC-11 typed PRM evidence exists.  
AC-12 typed AS metadata evidence exists.  
AC-13 typed authorization request/response evidence exists.  
AC-14 typed token claims projection exists without raw tokens.  
AC-15 typed PKCE evidence exists.  
AC-16 typed redirect/state evidence exists.  
AC-17 typed scope step-up evidence exists.  
AC-18 typed registration metadata evidence exists.  
AC-19 typed credential-flow evidence exists.  
AC-20 typed self-reported MCP identity metadata exists.  
AC-21 normalized observation model is closed.  
AC-22 adapters cannot assert final verdict.  
AC-23 exactly 14 initial invariants are implemented or Review documents an approved pre-execution change.  
AC-24 method header/body binding has PASS and FAIL tests.  
AC-25 name header/body binding has PASS and FAIL tests.  
AC-26 protocol downgrade/unsupported revision fails closed.  
AC-27 PRM resource binding has PASS and FAIL tests.  
AC-28 AS issuer binding has PASS and FAIL tests.  
AC-29 authorization-response issuer binding has PASS and FAIL tests.  
AC-30 token audience/resource binding has PASS and FAIL tests.  
AC-31 missing token-validity evidence is INCONCLUSIVE, not PASS.  
AC-32 PKCE binding has PASS and FAIL tests.  
AC-33 redirect/state integrity has PASS and FAIL tests.  
AC-34 scope step-up union semantics has PASS and FAIL tests.  
AC-35 step-up retries are hard bounded.  
AC-36 registration trust has PASS and FAIL tests.  
AC-37 raw registration metadata cannot manufacture trust.  
AC-38 inbound credential separation has PASS and FAIL tests.  
AC-39 raw inbound bearer value never appears in persisted evidence.  
AC-40 self-reported client/server metadata cannot establish authoritative principal identity.  
AC-41 Cycle 015 principal semantics are reused.  
AC-42 Cycle 003 final-operation binding is reused.  
AC-43 auth-relevant post-permit mutation re-evaluates/refuses and never silently reuses stale authority.  
AC-44 PASS requires positive invariant-specific evidence.  
AC-45 missing required channels produce INCONCLUSIVE.  
AC-46 independent simultaneous violations are retained.  
AC-47 stop_on_first_fail cannot discard same-trial violations.  
AC-48 only REPLAY/SIMULATED/LOCAL_SYNTHETIC modes exist.  
AC-49 no live OAuth/OIDC/IdP/MCP auth mode exists.  
AC-50 external egress budget is zero.  
AC-51 state-change budget is zero.  
AC-52 run-wide request/trial counters are hard bounded.  
AC-53 over-limit input is refused, never upward-clamped.  
AC-54 raw bearer/refresh/code/client-secret/private-key/cookie fields are refused or redacted before persistence.  
AC-55 executable/callback/command fields are refused.  
AC-56 live endpoint/network instructions are refused.  
AC-57 hostile control/bidi/path-traversal identifiers are refused.  
AC-58 at least 28 MCP-AUTH-LAB scenarios exist.  
AC-59 secure/vulnerable pairs cover the critical invariants.  
AC-60 hostile fixtures prove fail-closed parser behavior.  
AC-61 `mcp-auth-hardening-2026` profile is additive.  
AC-62 prior profiles and Cycle 006 denominator semantics are unchanged.  
AC-63 `validate mcp-auth-security` exists with only local-safe flags.  
AC-64 prohibited remote/credential flags do not exist.  
AC-65 result/evidence/report artifacts use bounded wording and retain standards provenance.  
AC-66 `mcp-auth-security-2026` CI job exists without changing PR-open-only trigger.  
AC-67 actual local CI job execution is recorded before PR creation.  
AC-68 Cycle 002/003/013/014/015/016/017 regressions pass.  
AC-69 Agentic registry/family/coverage regressions pass.  
AC-70 MCP baseline regressions pass.  
AC-71 workspace fmt/clippy/test/audit pass.  
AC-72 EN/PT documentation builds pass.  
AC-73 generated fixtures are reproducible if generators are introduced.  
AC-74 no real token, client secret, authorization code, private key or customer identifier exists in fixtures/artifacts.  
AC-75 `REGRESSION.md` records exact execution evidence.  
AC-76 `PROOF.md` maps all 76 criteria to executed evidence.
