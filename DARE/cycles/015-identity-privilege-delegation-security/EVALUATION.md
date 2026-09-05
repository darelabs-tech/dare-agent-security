# Cycle 015 — Evaluation

**Cycle:** 015 — Identity, Privilege & Delegation Security
**Status:** READY FOR REVIEW
**Planning date:** 2026-09-05
**Baseline:** `main` at `2f9c02b4f4f94daa5478a0785f74814fb2d021a2`

## 1. Why this cycle now

Cycle 013 established deterministic instruction/goal boundaries. Cycle 014 established deterministic tool-selection, argument, output-trust and chaining boundaries. The next missing authority boundary is identity: who the agent is acting for, what authority was delegated, and whether that authority remains valid for the final operation.

The current registry already contains the parent properties:

- `AGENT.IDENTITY.DELEGATION_INTEGRITY`
- `AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION`

Cycle 015 turns those passive registry concepts into bounded executable validation.

## 2. Baseline inherited from Cycle 014

Cycle 014 is merged through PR #21. Its final proof records:

- 31/31 tasks complete;
- 61/61 acceptance criteria mapped;
- 1,315 workspace tests passing;
- 340 Cycle 014 tests across 10 suites;
- 28/28 steps of the actual `tool-security-2026` workflow job passing locally;
- v2 Agentic registry expanded to 26 properties;
- four focused profiles now exist: MCP, Agentic, Prompt Injection and Tool Security.

The Cycle 015 baseline must freeze these numbers before implementation and treat any movement as explicit/additive.

## 3. Lessons inherited from Cycles 013 and 014

1. **Positive PASS coverage is mandatory.** Missing principal/delegation/authz evidence must become `INCONCLUSIVE`, never `PASS`.
2. **Facts are independent.** Principal substitution, tenant crossing and privilege amplification may all be true in one trace; all must be recorded.
3. **Synthetic observations are not production evidence.** Simulated/local-synthetic results must be marked synthetic and bounded in reports.
4. **Never execute the risky action to prove the violation.** A structured attempted operation is enough when the invariant can be decided deterministically.
5. **Execute the actual CI job artifact locally before opening the PR.** Do not validate a paraphrase of workflow assertions.
6. **Exact structured assertions beat substring searches.** Cycle 013/014 proved that loose grep-style checks can create false CI failures.
7. **No raw credentials in evidence.** Identity testing must use synthetic credential descriptors, hashes and authority metadata, never bearer tokens or secret material.

## 4. Existing components to reuse

### Cycle 003 — COAZ Authorization Integrity

Cycle 003 already implements the important authorization-to-execution integrity pattern:

- normalized operation identity;
- authorization projection identity;
- pre-authorization snapshot;
- controlled post-permit mutation;
- final-operation recomputation;
- re-evaluate/refuse when authorization-relevant semantics change.

Cycle 015 must reuse this concept and code where practical rather than inventing a second stale-permit engine.

### Cycle 005 — Synthetic MCP Security Lab

Already contains safe confused-deputy and authorization-mutation fixtures.

### Cycle 008 — Agent Attack Graph MVP

Already models synthetic paths such as:

`Human A -> Agent -> Service Credential B -> Tenant B Resource`

This topology is useful for deterministic privilege/tenant fixtures.

### Cycle 009 — Controlled Agentic Adversarial Validation

Reuse ROE, budgets, kill switch, canonical binding and synthetic execution controls.

### Cycles 013/014

Reuse the successful engine shape:

- versioned schema/corpus;
- replay/simulated/local-synthetic;
- typed normalized events;
- invariant-specific positive coverage;
- deterministic evaluator;
- Cycle 001 evidence bridge;
- bounded reporting;
- local workflow-job verification.

## 5. Standards snapshot

### OWASP Agentic Top 10 2026

Current taxonomy confirms:

`ASI03 — Identity & Privilege Abuse`

This is a risk taxonomy/context source, not a substitute for evidence.

### OpenID AuthZEN Authorization API 1.0

Status: **FINAL**, approved January 2026.

Useful as a normative reference for PDP/PEP authorization requests and the Subject-Action-Resource-Context information model.

Cycle 015 does not claim AuthZEN conformance merely because it uses a SARC-like internal representation.

### COAZ Framework 1.0 / COAZ-MCP Binding 1.0

Current status: **Working Group Drafts**.

They may inform mapping of protocol operations to authorization context, but all mappings must remain marked `DRAFT`.

Any authorization-to-execution permit-binding behavior that is not part of a final upstream standard must remain `OPEN_PROPOSAL` or DARE-internal behavior; do not promote it to normative compliance.

## 6. Core design boundary

Cycle 015 answers:

> Did a bounded principal/delegation/authorization trace deterministically prove that effective authority exceeded, changed, crossed, or detached from the authority originally granted?

The engine does **not** answer:

- whether an OAuth/OIDC token is cryptographically valid;
- whether a live MCP authorization endpoint is correctly configured;
- whether a remote PDP is trustworthy;
- whether a production identity provider issued the right claim.

Those belong to Cycle 018 or later authorized runtime work.

## 7. Proposed specialized properties

Preserve unchanged:

- `AGENT.IDENTITY.DELEGATION_INTEGRITY`
- `AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION`

Additive candidates:

- `AGENT.IDENTITY.PRINCIPAL_BINDING`
- `AGENT.IDENTITY.DELEGATION_SCOPE_BOUNDARY`
- `AGENT.IDENTITY.TENANT_RESOURCE_BOUNDARY`
- `AGENT.IDENTITY.AUTHORIZATION_EXECUTION_BINDING`

All map to `IDENTITY_PRIVILEGE_ABUSE`.

## 8. Principal distinctions that must remain explicit

The model must not collapse:

- human/user principal;
- agent principal;
- workload/service principal;
- initiating principal;
- effective principal;
- delegated subject;
- tenant/resource owner.

A service credential available to the runtime is evidence of capability availability, not automatic evidence that the user delegated its full authority.

## 9. Recommended engine boundary

Preferred crate:

`crates/dare-identity-security/`

The crate should own identity-specific schemas, normalization, coverage contracts, invariants, traces and result composition while reusing generic evidence/budget/authorization-integrity components.

## 10. Review conclusion

Cycle 015 is justified and should proceed as a bounded local/offline validation engine. The highest-value tests are principal substitution, confused deputy, delegation-scope expansion, privilege amplification, tenant/resource crossing, stale permit reuse and post-authorization operation mutation.

No runtime target interaction is authorized by this planning package. Execution remains blocked until explicit Product Owner approval creates `APPROVAL.md` and execution specs.
