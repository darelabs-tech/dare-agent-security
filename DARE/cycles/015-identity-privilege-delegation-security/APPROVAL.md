# Cycle 015 — Execution Approval

> Cycle: `015-identity-privilege-delegation-security`
> Status: **APPROVED FOR EXECUTION**
> Approved: **2026-09-05**
> Branch: `agent/cycle-015-identity-privilege-delegation-security`
> Baseline: `main` at `2f9c02b4f4f94daa5478a0785f74814fb2d021a2`

## Product Owner decision

The Product Owner explicitly approves all Cycle 015 planning artifacts and authorizes execution of `task-001` through `task-035` in DAG order.

Approved planning artifacts:

- `EVALUATION.md`
- `DESIGN.md`
- `BLUEPRINT.md`
- `TASKS.md`
- `dare-dag.yaml`
- `dare-dag.exec.yaml`
- `EXECUTION/task-001.md` through `EXECUTION/task-035.md`

`APPROVAL.md` and `dare-dag.exec.yaml` are authoritative for execution state. Material scope expansion requires a return to Design/Review and new approval.

## Approved objective

Implement a bounded, evidence-first, local/offline-first Identity Security Validation Engine that deterministically answers whether a controlled principal, delegation, privilege or authorization trace proves that effective authority exceeded, changed, crossed or detached from the authority originally granted.

## Approved property model

Existing properties must remain semantically unchanged:

- `AGENT.IDENTITY.DELEGATION_INTEGRITY`
- `AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION`

Approved additive properties:

- `AGENT.IDENTITY.PRINCIPAL_BINDING`
- `AGENT.IDENTITY.DELEGATION_SCOPE_BOUNDARY`
- `AGENT.IDENTITY.TENANT_RESOURCE_BOUNDARY`
- `AGENT.IDENTITY.AUTHORIZATION_EXECUTION_BINDING`

All specialized properties map to `IDENTITY_PRIVILEGE_ABUSE`. New applicability predicates must be closed, typed, additive and fail closed.

## Approved identity model

Closed principal kinds:

- `HUMAN`
- `AGENT`
- `WORKLOAD`
- `SERVICE`

The model must distinguish at least initiating principal, effective principal, agent principal, delegated subject and resource owner.

Authority is declarative data, never executable policy code. Effective authority must remain within the source/delegated authority ceiling. Credential availability is not authority.

Approved delegation kinds:

- `ON_BEHALF_OF`
- `AGENT_HANDOFF`
- `SERVICE_DELEGATION`

Delegation must preserve or narrow authority and maintain compatible subject, purpose, audience, tenant and validity constraints. Loops, duplicate/unknown edges and invalid time windows fail closed.

## Approved deterministic invariant set

- `INITIATING_PRINCIPAL_PRESERVED`
- `AGENT_AUTHORITY_NOT_SUBSTITUTED_FOR_USER`
- `DELEGATED_SUBJECT_PRESERVED`
- `DELEGATION_SCOPE_NOT_EXCEEDED`
- `DELEGATION_CHAIN_NO_PRIVILEGE_AMPLIFICATION`
- `EFFECTIVE_AUTHORITY_WITHIN_SOURCE_CEILING`
- `TENANT_BOUNDARY_PRESERVED`
- `RESOURCE_OWNER_BOUNDARY_PRESERVED`
- `AUTHORIZATION_BOUND_TO_FINAL_OPERATION`
- `DENY_NOT_BYPASSED`
- `CREDENTIAL_CONTEXT_NOT_EXPAND_AUTHORITY`
- `DELEGATION_VALID_AT_USE`

Final security verdicts must come from deterministic evaluators over normalized typed evidence. LLM prose, semantic similarity, embeddings or heuristic classifiers are never the final judge.

## Positive PASS coverage — mandatory

Every invariant must define the evidence channel required for `PASS`.

Examples:

- principal invariants require `PRINCIPAL_CONTEXT` and, where relevant, `EFFECTIVE_AUTHORITY`;
- delegation invariants require `DELEGATION_EDGE`/`DELEGATION_ASSERTION` plus authority evidence;
- tenant/resource-owner invariants require `RESOURCE_CONTEXT` plus principal/operation evidence;
- authorization binding requires both `AUTHORIZATION_DECISION` and `FINAL_OPERATION`;
- DENY bypass requires a DENY plus operation-request/final-intent evidence;
- credential-context invariants require `CREDENTIAL_CONTEXT` plus `EFFECTIVE_AUTHORITY`.

If required evidence is missing, verdict is `INCONCLUSIVE`, never `PASS`.

Independent simultaneous violations must all be captured. Stopping later trials must never erase evidence already observed in the current trial.

## Approved reuse contracts

Reuse rather than duplicate:

- Cycle 001 evidence/verdict semantics;
- Cycle 003 canonical authorization-to-execution semantic binding and stale-permit protections;
- Cycle 005 synthetic MCP confused-deputy patterns;
- Cycle 006 applicability/coverage denominator semantics;
- Cycle 008 attack-graph synthetic identity/tenant fixtures where useful;
- Cycle 009 ROE, execution budgets and kill switch;
- Cycle 011 CLI/product conventions;
- Cycle 012 registry/risk-family semantics;
- Cycle 013 Prompt Injection contracts;
- Cycle 014 Tool Security contracts.

Do not create a competing authorization-integrity engine when Cycle 003 components can be reused or adapted.

## Approved hard bounds

- `default_trials = 3`
- `hard_max_trials = 10`
- `stop_on_first_fail = true`
- `hard_max_principals = 16`
- `hard_max_delegation_edges = 12`
- `hard_max_delegation_depth = 4`
- `max_authorization_decisions_per_trial = 8`
- `max_operations_per_trial = 8`
- `hard_max_total_operations = 24`
- `max_output_bytes_per_trial = 16384`
- `max_total_output_bytes = 65536`
- `max_duration_seconds_per_trial = 30`
- `max_state_changes = 0`
- `external_egress_bytes = 0`

Inputs exceeding hard limits must be refused rather than silently widened or clamped upward. Counters must not reset in a way that bypasses run-wide limits.

## Approved execution modes

Only:

- `REPLAY`
- `SIMULATED`
- `LOCAL_SYNTHETIC`

No live/remote IdP, OAuth/OIDC server, PDP, AuthZEN endpoint, MCP server, provider or business tool is authorized by Cycle 015.

## Approved standards treatment

- OWASP Agentic Top 10 2026 `ASI03 — Identity & Privilege Abuse`: risk taxonomy/context; record exact current source/version/date.
- OpenID AuthZEN Authorization API 1.0: Final Specification; may inform provider-neutral SARC-style modeling.
- COAZ Framework / COAZ-MCP Binding: DRAFT only.
- authorization-to-execution permit-binding proposals that are not final must remain explicitly `OPEN_PROPOSAL`/DARE-internal and must not be represented as normative compliance.

The implementation must not claim AuthZEN, COAZ or MCP conformance merely because internal structures resemble those specifications.

## Approved CLI

`dare-agent-security validate identity-security`

Approved bounded inputs include:

- `--scenario`
- `--mode replay|simulated|local-synthetic`
- `--trace`
- `--corpus`
- `--trials`
- `--output-dir`
- `--json`

Prohibited surface includes remote/credential/protocol execution options such as:

- `--url`
- `--endpoint`
- `--issuer`
- `--jwks`
- `--token`
- `--bearer`
- `--client-secret`
- `--api-key`
- `--pdp-url`
- `--authzen-url`
- `--remote`
- `--command`

## Approved profile

Create `identity-security-baseline-2026` with:

- `AGENT.IDENTITY.DELEGATION_INTEGRITY` — REQUIRED
- `AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION` — REQUIRED
- `AGENT.IDENTITY.PRINCIPAL_BINDING` — REQUIRED
- `AGENT.IDENTITY.DELEGATION_SCOPE_BOUNDARY` — CONDITIONAL
- `AGENT.IDENTITY.TENANT_RESOURCE_BOUNDARY` — CONDITIONAL
- `AGENT.IDENTITY.AUTHORIZATION_EXECUTION_BINDING` — REQUIRED

Do not change existing profile requirements or Cycle 006 denominator semantics.

## Safety and data restrictions

Cycle 015 must use synthetic identifiers/data only for active/local-synthetic proofs. It must not persist or collect raw credentials, bearer tokens, session cookies, client secrets, private keys, JWTs or customer secrets.

Structured risky/denied operations may be represented as inert events and may deterministically produce `FAIL`; they must never be dispatched to a real system.

Treat scenario, corpus, principal set, delegation chain, resource context, policy, decision, operation and trace inputs as untrusted.

Use closed enums and fail-closed schema parsing. Refuse executable fields, token/secret fields, unknown schema versions, invalid references, path traversal, hostile over-bounds inputs and expected-verdict smuggling.

## Explicitly deferred / excluded

Not authorized in Cycle 015:

- live OAuth/OIDC flows or token exchange;
- JWT signature/issuer/audience cryptographic validation;
- live IdP/PDP/AuthZEN integration;
- remote MCP authorization testing;
- production identities/credentials;
- credential harvesting/replay;
- SCIM identity lifecycle;
- broad OAuth/MCP protocol hardening (Cycle 018);
- Memory Security (Cycle 016);
- RAG Security (Cycle 017);
- AI-BOM/Supply Chain (Cycle 019);
- A2A Security (Cycle 020);
- remote authorized dynamic validation (Cycle 022);
- destructive/persistent/state-changing actions;
- generalized IAM compliance certification.

## Reporting semantics

Never render finite/synthetic success as `Identity Secure`, `Authorization Secure`, `No Privilege Escalation Possible`, `immune`, `fully protected` or equivalent.

Preferred bounded wording:

> No identity-security invariant violation was observed for the tested vectors under the recorded conditions.

Reports must distinguish principal binding, delegation, privilege, tenant/resource and authorization-binding coverage and clearly mark synthetic vs replay evidence.

## GitHub Actions / execution rule

Preserve the repository policy:

```yaml
on:
  pull_request:
    branches: [main]
    types: [opened]
```

Do not add a `push:` trigger.

Add the dedicated job `identity-security-2026` using only local fixtures.

Before opening a PR, run the actual workflow job artifact:

```bash
python scripts/run-ci-job-locally.py .github/workflows/ci.yml identity-security-2026
```

Also run:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
```

and dedicated Cycle 015 tests plus Cycle 003, Cycle 013, Cycle 014, Agentic and MCP regressions and docs builds.

Do not open the PR until all mandatory local gates are green. Since CI is `types: [opened]`, avoid post-open commits; if one is unavoidable, rerun all gates locally and document the exact head covered by PR-open CI.

## Definition of completion

Cycle 015 becomes DONE only when:

- all 35 tasks are complete;
- all 67 DESIGN acceptance criteria are mapped to concrete evidence;
- `PROOF.md` and full regression evidence exist;
- mandatory local gates are green;
- the actual `identity-security-2026` workflow job passes locally;
- compatibility with earlier cycles is evidenced;
- residual risks/deviations are recorded;
- the final branch is pushed before the single PR is opened;
- the PR-open CI result is inspected and recorded.
