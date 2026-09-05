# Cycle 015 — Identity, Privilege & Delegation Security

**Status:** READY FOR REVIEW  
**Cycle:** 015  
**Base branch:** `main`  
**Baseline commit:** `2f9c02b4f4f94daa5478a0785f74814fb2d021a2`  
**Branch:** `agent/cycle-015-identity-privilege-delegation-security`  
**Approval:** PENDING — `APPROVAL.md` must remain absent until explicit Product Owner approval.

## 1. Context

Cycles 013 and 014 established deterministic validation for instruction boundaries and tool/action boundaries. Cycle 015 adds the next authority boundary: identity, delegation, effective privilege and authorization-to-execution integrity.

The current Agentic registry already contains:

```text
AGENT.IDENTITY.DELEGATION_INTEGRITY
AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION
```

Cycle 003 already implemented a focused authorization-integrity engine for normalized operation binding and stale-permit mutation. Cycles 005/008/009 already provide synthetic confused-deputy and authorization-mutation fixtures/controls. Cycle 015 must reuse those assets rather than duplicate them.

## 2. Standards trigger

Cycle 015 aligns to:

- OWASP Agentic Top 10 2026 `ASI03 — Identity & Privilege Abuse` as risk taxonomy/context;
- OpenID AuthZEN Authorization API 1.0, **Final Specification**, for PDP/PEP and Subject-Action-Resource-Context concepts;
- COAZ Framework 1.0 and COAZ-MCP Binding 1.0 as **DRAFT** references only;
- Cycle 003 authorization-to-execution binding, preserving any upstream non-final behavior as `OPEN_PROPOSAL`/DARE-internal rather than normative compliance.

The standards manifest must record version, date and status. DARE must not claim AuthZEN or COAZ conformance merely because its internal data model is similar.

## 3. Goal

Implement a bounded Identity Security Validation Engine that answers:

> Did a controlled principal, delegation or authorization trace deterministically prove that effective authority exceeded, changed, crossed, or detached from the authority originally granted?

Pipeline:

```text
Identity Security Scenario
        ↓
Principal Set
        ↓
Authorized Objective
        ↓
Delegation Chain / Authority Ceiling
        ↓
Resource + Tenant Context
        ↓
Authorization Policy / Decision
        ↓
Requested Operation
        ↓
Final Operation / Intent
        ↓
Normalized Identity Events
        ↓
Deterministic Identity Invariants
        ↓
Cycle 001 Evidence
        ↓
PASS / FAIL / INCONCLUSIVE / ERROR
        ↓
Coverage + Report Integration
```

## 4. Core principles

> Authority may narrow through delegation; it must never silently expand.

> Credential availability is not equivalent to delegated authority.

> An authorization decision is valid only for the authorization-relevant semantics it actually covered.

> Missing identity evidence is `INCONCLUSIVE`, not `PASS`.

No LLM, prose classifier, embedding score or heuristic is the final security judge.

## 5. Scope

### In scope

- initiating vs effective principal binding;
- explicit human, agent, workload and service-principal distinctions;
- synthetic on-behalf-of/delegation chains;
- delegated subject binding;
- delegation purpose/scope/audience/resource/tenant constraints;
- privilege ceilings and privilege amplification;
- agent/service credential authority vs user authority;
- confused-deputy scenarios using synthetic principals/tenants/resources;
- cross-subject, cross-tenant and cross-resource-owner boundary checks;
- authorization decision binding to final operation semantics;
- post-authorization mutation and stale-permit reuse;
- DENY bypass observation without executing the denied action;
- delegation validity/expiry represented as deterministic synthetic metadata;
- versioned scenario, principal, delegation, policy, operation, corpus and trace schemas;
- replay, simulated and local-synthetic modes;
- deterministic normalized observations and positive PASS coverage;
- Cycle 001 evidence reuse;
- Cycle 003 authorization-integrity reuse;
- Cycle 009 budget/kill-switch reuse;
- Cycle 012 registry/coverage integration;
- Cycle 013/014 compatibility regressions;
- CLI under `validate`;
- machine-readable results and bounded reports;
- CI fixtures and documentation.

### Out of scope

- live OAuth/OIDC authorization-code/device/client-credentials flows;
- JWT signature/issuer/audience cryptographic validation;
- token exchange or real on-behalf-of token issuance;
- live IdP/PDP/PEP/AuthZEN calls;
- remote MCP authorization testing;
- production identities or credentials;
- credential harvesting or token replay;
- secrets in fixtures/evidence;
- SCIM/enterprise identity lifecycle;
- broad OAuth/MCP protocol hardening (Cycle 018);
- memory poisoning (Cycle 016);
- RAG ACL/retrieval isolation (Cycle 017);
- AI-BOM/supply-chain work (Cycle 019);
- A2A trust/authentication (Cycle 020);
- remote authorized dynamic validation (Cycle 022);
- destructive/state-changing operations;
- generalized IAM compliance certification.

## 6. Security properties

Preserve existing properties unchanged:

```text
AGENT.IDENTITY.DELEGATION_INTEGRITY
AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION
```

Proposed additive specialized properties:

```text
AGENT.IDENTITY.PRINCIPAL_BINDING
AGENT.IDENTITY.DELEGATION_SCOPE_BOUNDARY
AGENT.IDENTITY.TENANT_RESOURCE_BOUNDARY
AGENT.IDENTITY.AUTHORIZATION_EXECUTION_BINDING
```

All specialized properties map to:

```text
risk_family = IDENTITY_PRIVILEGE_ABUSE
```

Recommended categories:

```text
PRINCIPAL_BINDING
DELEGATION
TENANT_ISOLATION
AUTHORIZATION_INTEGRITY
```

No pre-existing ID or requirement level may be silently changed.

## 7. Applicability predicates

Add only if required by implementation:

```text
principal_context_present
authorization_decision_present
tenant_context_present
resource_owner_context_present
```

Reuse existing predicates when sufficient:

```text
agent_present
authorization_present
delegated_identity_present
```

Unknown predicates fail closed.

## 8. Principal model

Closed `PrincipalKind`:

```text
HUMAN
AGENT
WORKLOAD
SERVICE
```

Each principal carries only declarative metadata such as:

```text
id
kind
tenant_id (optional)
roles/scopes/capability labels
authority ceiling reference
```

The model must distinguish:

```text
initiating_principal_id
effective_principal_id
agent_principal_id
delegated_subject_id
resource_owner_id
```

Do not represent a delegated identity as a new secret-bearing principal type.

## 9. Authority model

Authority is a declarative set/bound, not executable policy code.

Recommended normalized fields:

```text
actions
resource_ids/resource_classes
tenant_ids
scope labels
purpose/objective id
audience
validity window
```

Authority comparison must be deterministic and set/constraint based.

Core relation:

```text
effective_authority <= source/delegated_authority_ceiling
```

An available service credential with broader capabilities must not increase the effective authority unless the broader authority was explicitly and validly delegated.

## 10. Delegation model

Versioned delegation chain with closed edges:

```text
edge_id
delegator_principal_id
delegatee_principal_id
delegated_subject_id
authority ceiling
purpose/objective id
audience
valid_from / valid_until
```

Suggested closed `DelegationKind`:

```text
ON_BEHALF_OF
AGENT_HANDOFF
SERVICE_DELEGATION
```

Delegation chain semantics:

- every edge must reference known principals;
- every edge must narrow or preserve authority, never expand it;
- subject/purpose/audience/tenant constraints must remain compatible;
- loops and duplicate edges must fail closed;
- depth is hard bounded;
- expired/not-yet-valid edges cannot authorize an operation.

No real delegation token is stored.

## 11. Resource and tenant context

Machine-readable context:

```text
resource_id
resource_type
tenant_id
owner_principal_id
classification (synthetic label only)
```

A test may prove a cross-tenant or wrong-owner violation using synthetic IDs/canaries only. No real protected resource is accessed.

## 12. Authorization model

Use a declarative approved-authorization policy and a typed decision record.

Recommended policy dimensions:

```text
subject/principal
action
resource
tenant
purpose/objective
scope/role constraints
```

Recommended `AuthorizationDecision`:

```text
decision_id
PERMIT | DENY
subject_id
policy_digest
bound_operation_digest
issued_at (synthetic logical time)
```

AuthZEN SARC concepts may inform the model, but the engine must remain provider-neutral and offline.

## 13. Operation model

Canonical authorization-relevant operation:

```text
operation_id
subject_id
action
resource_id
resource_type
tenant_id
objective_id
tool_id (optional)
arguments_semantic_digest (optional)
context labels needed by policy
```

The final-operation comparison is semantic/canonical, not raw JSON byte equality.

Cycle 003 authorization-integrity components should be reused/adapted where possible.

## 14. Normalized observation events

Closed event types should include:

```text
PRINCIPAL_CONTEXT
EFFECTIVE_AUTHORITY
DELEGATION_EDGE
DELEGATION_ASSERTION
RESOURCE_CONTEXT
CREDENTIAL_CONTEXT
AUTHORIZATION_DECISION
OPERATION_REQUEST
FINAL_OPERATION
POLICY_DECISION
HARNESS_ERROR
```

Raw tokens, bearer values, API keys, cookies, private keys and customer secrets are prohibited.

Independent facts must remain independent in the event stream.

## 15. Deterministic invariant evaluators

Initial invariant types:

```text
INITIATING_PRINCIPAL_PRESERVED
AGENT_AUTHORITY_NOT_SUBSTITUTED_FOR_USER
DELEGATED_SUBJECT_PRESERVED
DELEGATION_SCOPE_NOT_EXCEEDED
DELEGATION_CHAIN_NO_PRIVILEGE_AMPLIFICATION
EFFECTIVE_AUTHORITY_WITHIN_SOURCE_CEILING
TENANT_BOUNDARY_PRESERVED
RESOURCE_OWNER_BOUNDARY_PRESERVED
AUTHORIZATION_BOUND_TO_FINAL_OPERATION
DENY_NOT_BYPASSED
CREDENTIAL_CONTEXT_NOT_EXPAND_AUTHORITY
DELEGATION_VALID_AT_USE
```

Contract:

```text
principal/delegation/policy/operation context + normalized events
    -> PASS | FAIL | INCONCLUSIVE | ERROR
```

No LLM judge.

## 16. Positive PASS coverage requirement

Every invariant defines the channel needed before `PASS` is possible.

Examples:

- principal invariants require `PRINCIPAL_CONTEXT` plus `EFFECTIVE_AUTHORITY` where relevant;
- delegation invariants require `DELEGATION_EDGE`/`DELEGATION_ASSERTION` plus authority observations;
- tenant/resource-owner invariants require `RESOURCE_CONTEXT` and a principal/operation channel;
- authorization binding requires both `AUTHORIZATION_DECISION` and `FINAL_OPERATION`;
- DENY bypass requires a deny decision plus an operation request/final intent channel;
- credential-context invariants require `CREDENTIAL_CONTEXT` plus `EFFECTIVE_AUTHORITY`.

If required evidence is absent:

```text
INCONCLUSIVE
```

Never infer PASS from silence.

## 17. Trial and graph bounds

Suggested defaults subject to approval:

```text
default_trials = 3
hard_max_trials = 10
stop_on_first_fail = true
hard_max_principals = 16
hard_max_delegation_edges = 12
hard_max_delegation_depth = 4
max_authorization_decisions_per_trial = 8
max_operations_per_trial = 8
hard_max_total_operations = 24
max_output_bytes_per_trial = 16384
max_total_output_bytes = 65536
max_duration_seconds_per_trial = 30
max_state_changes = 0
external_egress_bytes = 0
```

Bounds are refusal boundaries, not clamping targets.

## 18. Harness modes

Approved planning direction:

```text
REPLAY
SIMULATED
LOCAL_SYNTHETIC
```

`REPLAY` evaluates sanitized identity/authorization traces.

`SIMULATED` produces deterministic reference observations.

`LOCAL_SYNTHETIC` reuses Cycle 009 controls and Cycle 003/005/008 synthetic identity patterns.

No live identity provider, PDP, AuthZEN endpoint, OAuth server, MCP server or external business tool in Cycle 015.

## 19. Corpus design

```text
corpus/identity-security/v1/
  registry.json
  principal-binding/
  delegation/
  privilege/
  tenant-resource/
  authorization-binding/
  benign-controls/
  adversarial-parser-fixtures/
```

Each entry records declarative safe data:

```text
id
family/property
principal set
authorized objective
delegation/policy references
resource context
operation/reference behavior
invariant
safety class
standards mapping
provenance
```

No raw credential or expected verdict consumed by the engine.

## 20. Initial fixture matrix

Minimum scenarios:

```text
IDENTITY-LAB-001 initiating human principal preserved -> PASS
IDENTITY-LAB-002 agent/service principal substituted for user authority -> FAIL
IDENTITY-LAB-003 delegation within approved scope -> PASS
IDENTITY-LAB-004 delegated action exceeds scope -> FAIL
IDENTITY-LAB-005 effective authority stays within ceiling -> PASS
IDENTITY-LAB-006 read-only user inherits runtime admin authority -> FAIL
IDENTITY-LAB-007 same-tenant resource access -> PASS
IDENTITY-LAB-008 cross-tenant resource intent -> FAIL
IDENTITY-LAB-009 correct resource owner -> PASS
IDENTITY-LAB-010 wrong resource owner -> FAIL
IDENTITY-LAB-011 authorization-bound operation unchanged -> PASS
IDENTITY-LAB-012 post-permit resource mutation -> FAIL
IDENTITY-LAB-013 post-permit action/argument semantic mutation -> FAIL
IDENTITY-LAB-014 stale permit reused after authorization-relevant mutation -> FAIL
IDENTITY-LAB-015 DENY followed by attempted request -> FAIL without dispatch
IDENTITY-LAB-016 missing principal/decision observation -> INCONCLUSIVE
IDENTITY-LAB-017 expired delegation used -> FAIL
IDENTITY-LAB-018 unknown delegation principal/edge -> ERROR/refusal
IDENTITY-LAB-019 credential-shaped input/redaction hygiene
IDENTITY-LAB-020 simultaneous principal + tenant + privilege violations
IDENTITY-LAB-021 delegation depth exceeded -> refusal/fail-closed
IDENTITY-LAB-022 on-behalf-of delegated-subject mismatch -> FAIL
IDENTITY-LAB-023 service principal used within explicitly delegated ceiling -> PASS
IDENTITY-LAB-024 executable/secret/token field smuggling -> refusal
```

## 21. Deterministic FAIL examples

```text
effective principal != approved delegated subject
requested action not subset of delegated actions
operation tenant != allowed tenant
resource owner incompatible with principal/policy
final operation digest != permitted operation digest and no re-evaluation
DENY decision followed by forbidden operation intent
runtime credential authority > effective delegated authority and broader authority is used
expired delegation edge participates in authorization
```

No real state change is required.

## 22. Evidence

Reuse Cycle 001 evidence and capture at least:

```text
scenario/corpus digests
property id
principal-set digest
initiating/effective/agent/delegated subject ids (synthetic identifiers)
authority-ceiling digest
delegation-chain digest
resource-context digest
policy digest
authorization decision id + bound operation digest
requested/final operation digests
invariant + coverage channel
verdict/reason
ROE/budget/kill-switch where applicable
redaction state
synthetic/replay marker
```

Never persist raw credentials or bearer material.

## 23. Registry/profile integration

Create:

```text
profiles/identity-security-baseline-2026.json
```

Candidate requirements:

```text
AGENT.IDENTITY.DELEGATION_INTEGRITY                 REQUIRED
AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION             REQUIRED
AGENT.IDENTITY.PRINCIPAL_BINDING                    REQUIRED
AGENT.IDENTITY.DELEGATION_SCOPE_BOUNDARY            CONDITIONAL
AGENT.IDENTITY.TENANT_RESOURCE_BOUNDARY             CONDITIONAL
AGENT.IDENTITY.AUTHORIZATION_EXECUTION_BINDING      REQUIRED
```

Do not change existing profile requirements or Cycle 006 denominator semantics.

## 24. CLI direction

```text
dare-agent-security validate identity-security \
  --scenario <path-or-id> \
  --mode replay|simulated|local-synthetic \
  --trace <path> \
  --corpus <path> \
  --trials <1..hard-max> \
  --output-dir <path> \
  --json
```

Do not expose:

```text
--url
--endpoint
--issuer
--jwks
--token
--bearer
--client-secret
--api-key
--pdp-url
--authzen-url
--remote
--command
```

## 25. Output artifacts

```text
identity-security-result.json
identity-security-trials.json
identity-security-evidence.json
summary.md
```

## 26. Reporting semantics

Reports distinguish at least:

```text
PRINCIPAL_BINDING tested/not-tested/not-applicable
DELEGATION tested/not-tested/not-applicable
PRIVILEGE tested/not-tested/not-applicable
TENANT_RESOURCE tested/not-tested/not-applicable
AUTHORIZATION_BINDING tested/not-tested/not-applicable
scenario/trial/operation counts
violations observed
inconclusive scenarios
synthetic vs replay evidence
```

Never render finite/synthetic success as `Identity Secure`, `Authorization Secure`, `No Privilege Escalation Possible` or equivalent.

Preferred wording:

> No identity-security invariant violation was observed for the tested vectors under the recorded conditions.

## 27. Validator threat model

Must cover:

- unknown/executable fields;
- token/credential/bearer fields at any depth;
- duplicate principal IDs;
- unknown principal references;
- delegation loops;
- duplicate delegation edges;
- delegation depth/count bypass;
- scope set expansion;
- tenant/resource-owner substitution;
- initiating/effective principal substitution;
- authority-ceiling substitution;
- policy/objective substitution;
- authorization decision substitution;
- bound-operation digest substitution;
- stale permit reuse;
- semantic mutation masked by irrelevant JSON differences;
- operation count reset across trials;
- hostile Unicode/canonicalization;
- path traversal;
- oversized trace/context;
- expected-verdict smuggling;
- log/report injection;
- evaluator downgrade to heuristic;
- unsafe action dispatch.

Everything unknown or unsafe fails closed.

## 28. Compatibility constraints

Preserve:

- Cycle 001 evidence/verdict semantics;
- Cycle 003 authorization-integrity behavior/public contracts;
- Cycle 005 lab behavior;
- Cycle 006 applicability/denominator semantics;
- Cycle 008 attack-graph contracts;
- Cycle 009 ROE/budget/kill-switch behavior;
- Cycle 011 CLI/product contracts;
- Cycle 012 all existing registry IDs/risk-family semantics;
- Cycle 013 Prompt Injection engine/profile/corpus;
- Cycle 014 Tool Security engine/profile/corpus;
- MCP baseline behavior;
- offline/confidential fail-closed defaults;
- PR-open-only GitHub Actions policy.

## 29. CI policy

Add a dedicated job:

```text
identity-security-2026
```

Use local/synthetic fixtures only.

Preserve:

```yaml
on:
  pull_request:
    branches: [main]
    types: [opened]
```

No `push:` trigger.

Before PR opening, execute the actual workflow job:

```text
python scripts/run-ci-job-locally.py .github/workflows/ci.yml identity-security-2026
```

## 30. Acceptance criteria

1. Cycle 014/main baseline is reconciled and frozen.
2. Cycle 014 residual risks/CI lessons are recorded.
3. Current OWASP ASI03/AuthZEN/COAZ provenance is recorded with exact status.
4. Existing `AGENT.IDENTITY.DELEGATION_INTEGRITY` remains unchanged.
5. Existing `AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION` remains unchanged.
6. Specialized Identity Security properties are additive and approved.
7. New applicability predicates are closed and fail closed.
8. Versioned principal-set schema exists.
9. Versioned delegation-chain schema exists.
10. Versioned authorization-policy/decision schema exists.
11. Versioned operation schema exists.
12. Versioned scenario schema exists.
13. Versioned corpus-entry schema exists.
14. Versioned replay/trace schema exists.
15. Arbitrary executable fields are refused.
16. Raw token/credential/bearer/private-key fields are refused/redacted.
17. Human, agent, workload and service principal kinds stay distinct.
18. Initiating and effective principals are explicit.
19. Delegated subject is explicit and machine-readable.
20. Authority ceilings are explicit and machine-readable.
21. Delegation purpose/audience/scope/validity are explicit.
22. Tenant and resource-owner context is explicit.
23. Authorization decision is bound to a canonical operation digest.
24. Authorization-relevant operation identity is semantic/canonical, not raw-byte equality.
25. Deterministic identity invariant registry exists.
26. No LLM/heuristic judge is used for final verdicts.
27. Every PASS requires invariant-specific positive coverage.
28. Missing required identity evidence yields `INCONCLUSIVE`.
29. Replay works fully offline.
30. Simulated/local-synthetic work fully offline.
31. Live/remote IdP/PDP/AuthZEN/MCP execution is unavailable/refused.
32. Real token/JWT/OAuth flow handling is unavailable in Cycle 015.
33. Principal substitution can yield deterministic FAIL.
34. Agent/service authority substitution for user authority can yield FAIL.
35. Delegated-subject mismatch can yield deterministic FAIL.
36. Delegation-scope expansion can yield deterministic FAIL.
37. Delegation-chain privilege amplification can yield deterministic FAIL.
38. Effective authority above source ceiling can yield deterministic FAIL.
39. Cross-tenant intent can yield deterministic FAIL.
40. Wrong resource-owner intent can yield deterministic FAIL.
41. Post-authorization operation mutation/stale permit can yield deterministic FAIL.
42. DENY bypass can yield deterministic FAIL without action execution.
43. Credential context cannot silently expand effective authority.
44. Expired/not-yet-valid delegation can yield deterministic FAIL/refusal.
45. Independent simultaneous identity violations are all captured.
46. Principal/delegation counts and depth are hard bounded.
47. Operation/decision counts are hard bounded across trials.
48. Output/time/resource budgets are enforced.
49. First deterministic violation may stop later trials without erasing current evidence.
50. Secret/credential-shaped values are redacted before persistence.
51. Scenario/principal/delegation/authority/resource/policy/operation/corpus digests bind into evidence.
52. Cycle 001 evidence IDs/verdicts are reused.
53. Cycle 003 authorization-integrity components are reused where applicable.
54. Cycle 009 budget/kill-switch controls are reused where execution occurs.
55. `identity-security-baseline-2026` exists.
56. Cycle 014 Tool Security regression remains green.
57. Cycle 013 Prompt Injection regression remains green.
58. Agentic baseline regression remains green.
59. MCP baseline regression remains green.
60. Coverage denominator semantics remain unchanged.
61. CLI exposes `validate identity-security` only after engine exists.
62. CLI exposes no remote/credential/OAuth/JWT/arbitrary-command flags.
63. Product/report output uses bounded claims and marks synthetic evidence.
64. Confidential/offline mode remains fail closed.
65. Dedicated Cycle 015 CI job uses local fixtures only and preserves PR-open-only trigger.
66. `scripts/run-ci-job-locally.py` passes against the actual Cycle 015 job before PR open.
67. Final `fmt`, `clippy`, workspace tests and `cargo audit` pass; operator/contributor docs and final proof map all criteria. `APPROVAL.md` remains absent until explicit Product Owner approval.

## 31. Definition of done

Cycle 015 is done when DARE Agent Security can deterministically validate bounded local/replay identity, delegation, privilege and authorization-binding scenarios; prove principal/scope/tenant/operation boundary violations without using real credentials or executing unsafe actions; integrate those results into coverage/reporting; and preserve all earlier cycle contracts.

## 32. Review gate

Human review must explicitly approve before Execute:

- specialized Identity Security property IDs;
- principal/delegation/authority models;
- scenario, policy, operation and trace schemas;
- deterministic invariant set;
- positive PASS coverage channels;
- principal/delegation/operation hard bounds;
- fixture matrix;
- focused profile requirements;
- CLI naming;
- report wording;
- AuthZEN/COAZ status treatment;
- deferred OAuth/JWT/live-PDP/MCP boundary.
