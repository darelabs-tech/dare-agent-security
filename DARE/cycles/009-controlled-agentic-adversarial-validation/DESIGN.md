# Cycle 009 — Controlled Agentic Adversarial Validation

**Status:** APPROVED FOR EXECUTION  
**Cycle:** 009  
**Name:** Controlled Agentic Adversarial Validation  
**Base branch:** `main`  
**Planning baseline:** Cycles 001–008 delivered on `main`  
**Branch:** `agent/cycle-009-controlled-agentic-adversarial-validation`  
**Approval:** APPROVED (2026-08-20) — see `APPROVAL.md`.

## 1. Context

Delivered foundation:

```text
001 Evidence Kernel
002 Passive MCP Discovery
003 Authorization-to-Execution Integrity
004 CI Security Gate
005 Synthetic MCP Security Lab
006 Assessment Profiles & Coverage Engine
007 MCP Security Benchmark & Corpus Methodology
008 Agent Attack Graph MVP
```

DARE Agent Security can now discover, plan, validate, produce deterministic evidence, measure coverage, benchmark real targets, and derive attack graphs/paths.

Cycle 009 adds the next capability:

> **turn selected attack-path hypotheses into controlled, authorized, minimum-risk adversarial validations.**

## 2. Problem

An Attack Graph can identify relationships and paths that are `INFERRED`, `STATICALLY_PROVEN`, or `NOT_TESTED`, but analysis alone cannot always answer whether a path can actually be exercised.

Uncontrolled execution introduces risk:

- destructive actions;
- state mutation;
- cross-tenant impact;
- credential exposure;
- production disruption;
- accidental exfiltration;
- scope expansion;
- excessive chaining.

Cycle 009 must enforce a strict boundary between:

```text
attack-path hypothesis
```

and:

```text
authorized minimum safe proof
```

## 3. Goal

Create this pipeline:

```text
Attack Path Candidate
        ↓
Security Property
        ↓
Authorization + ROE Gate
        ↓
Precondition Evaluation
        ↓
Minimum Safe Proof Plan
        ↓
Execution Budget
        ↓
Controlled Test Vector
        ↓
Runtime Enforcement
        ↓
Deterministic Evidence
        ↓
Validation Result
        ↓
Attack Path Reclassification
```

## 4. Core principle

> **Execute only the minimum non-destructive action required to prove or disprove the security property.**

The goal is not to maximize exploit impact. The goal is to produce sufficient evidence with minimum risk.

## 5. Non-goals

Cycle 009 is not:

- an autonomous exploit framework;
- a persistence framework;
- a credential-harvesting system;
- a lateral-movement engine;
- an internet-wide scanner;
- a denial-of-service engine;
- malware execution;
- a post-exploitation framework.

## 6. Controlled validation object model

Introduce:

```text
AdversarialValidationPlan
AdversarialTestVector
ExecutionBudget
ExecutionRecord
ValidationResult
PathReclassification
```

### 6.1 AdversarialValidationPlan

```yaml
schema_version: "1"
validation_plan:
  id: avp-0001
  target:
    id: target-001
    version: <sha>
  attack_path:
    id: path-001
    digest: sha256:...
  property:
    id: MCP.IDENTITY.CONFUSED_DEPUTY
  authorization:
    roe_id: ROE-2026-001
    approved_by: security-engineer@example
    approved_at: <timestamp>
  proof:
    objective: >
      Determine whether delegated identity A can cause
      access under service identity B.
    minimum_safe_condition: >
      Read synthetic canary resource only.
```

### 6.2 AdversarialTestVector

```yaml
vector:
  id: vector-001
  mode: AUTHORIZED_DYNAMIC
  preconditions:
    - synthetic_test_data_present
    - test_identity_active
    - target_environment == staging
  operation:
    method: tools/call
    tool: customer.lookup
    arguments:
      customer_id: synthetic-canary-001
  expected:
    secure: DENY
    vulnerable: ALLOW
  stop_condition:
    on_first_proof: true
```

### 6.3 ExecutionBudget

```yaml
budget:
  max_operations: 3
  max_duration_seconds: 30
  max_state_changes: 0
  max_bytes_read: 8192
  max_bytes_written: 0
  max_external_egress_bytes: 0
  max_retries: 0
  max_chain_depth: 2
```

### 6.4 ExecutionRecord

Append-only record of exactly what was attempted and observed.

### 6.5 ValidationResult

```yaml
validation_result:
  vector_id: vector-001
  property: MCP.IDENTITY.CONFUSED_DEPUTY
  verdict: FAIL
  confidence: CONFIRMED
  evidence_ids:
    - evidence-123
```

### 6.6 PathReclassification

Examples:

```text
INFERRED + controlled runtime proof -> OBSERVED
INFERRED + disproval -> REJECTED / REMOVED
STATICALLY_PROVEN + runtime contradiction -> REVIEW_REQUIRED
```

Exact vocabulary must reconcile with Cycle 008.

## 7. Authorization and ROE gate

Dynamic execution requires explicit authorization.

The gate evaluates:

```text
target identity
environment
allowed categories
allowed capabilities
allowed identities
allowed data classes
prohibited operations
time window
rate limits
egress constraints
state-change constraints
kill procedure
evidence retention
```

No valid ROE:

```text
NO EXECUTION
```

The system may remain in `STATIC`, `PASSIVE`, or `PLAN_ONLY` mode.

## 8. Precondition evaluation

Before execution, validate deterministic preconditions:

```text
target == authorized target
environment == authorized environment
test identity exists
synthetic data exists
tool is allowed by ROE
operation is not destructive
budget is valid
network boundary matches plan
attack path digest matches approved path
validation plan digest matches approved plan
```

Any failed mandatory precondition:

```text
BLOCK
```

## 9. Minimum safe proof

Each property defines the minimum proof needed.

### Confused deputy

Use synthetic tenant identities and canary resources only. Do not read real tenant data.

### Argument mutation

Use a harmless semantic field and synthetic target. Prove `authorized args != executed args` without destructive values.

### Tool-name mutation

Use harmless synthetic tools with different authorization requirements.

### Credential-boundary failure

Do not extract credential values. Prove only that credential identity/scope can authorize an unintended synthetic resource.

### Unauthorized state change

Prefer dry-run, rollback, synthetic resources, or no-op operations. If no safe proof exists, return `INCONCLUSIVE` or no execution rather than escalating risk.

## 10. Test-vector taxonomy

Candidate families:

```text
IDENTITY_CONFUSION
CONFUSED_DEPUTY
PER_OPERATION_AUTHZ_BYPASS
TOOL_NAME_MUTATION
ARGUMENT_MUTATION
TRUSTED_CONTEXT_MUTATION
TENANT_BOUNDARY_VIOLATION
CREDENTIAL_SCOPE_REUSE
HEADER_BODY_SEMANTIC_DIVERGENCE
MRTR_AUTHORIZATION_MUTATION
DANGEROUS_CHAINING
UNAUTHORIZED_STATE_CHANGE
```

Exact IDs must reuse actual Cycle 003/005/006/008 names where available.

## 11. Attack-path selection

A path is eligible only when:

```text
path evidence status in {INFERRED, STATICALLY_PROVEN}
AND path contains security-relevant property
AND minimum safe proof exists
AND ROE authorizes validation
AND preconditions are satisfiable
```

Automatic rejection:

```text
requires destructive proof
requires real-user data exposure
crosses unauthorized target
exceeds budget
requires credential extraction
```

## 12. Execution modes

Supported:

```text
PLAN_ONLY
SIMULATED
LOCAL_SYNTHETIC
AUTHORIZED_DYNAMIC
```

Cycle 009 should default to `PLAN_ONLY` or `LOCAL_SYNTHETIC` unless authorization explicitly permits dynamic execution.

## 13. Runtime enforcement

Do not rely on the agent remembering the ROE.

```text
Agent
  ↓
Validation Plan
  ↓
Runtime Policy
  ↓
Budget Check
  ↓
ROE Check
  ↓
Operation
```

A prohibited operation must be denied deterministically.

## 14. Execution budget

Budget is a security boundary. It may cap:

```text
operations
duration
bytes read
bytes written
state changes
external egress
tool depth
path hops
retry count
```

Budget exhaustion means `STOP`, never automatic expansion.

## 15. Kill switch

Dynamic validation requires deterministic abort triggers:

- unexpected state mutation;
- unapproved endpoint;
- unexpected identity;
- secret detected;
- unexpected egress;
- rate-limit anomaly;
- target instability;
- budget breach;
- evidence pipeline failure;
- operator stop.

Kill state is captured in evidence.

## 16. Evidence

Reuse Cycle 001.

Each validation captures:

```text
plan digest
vector digest
attack path digest
target version
ROE reference
preconditions
operation attempted
allow/deny decision
observed result
budget before/after
kill-switch state
redaction state
evidence IDs
```

## 17. Validation semantics

Example:

```text
Expected secure behavior: DENY
Observed: ALLOW
Verdict: FAIL
Confidence: CONFIRMED
```

If preconditions are unavailable:

```text
Execution: BLOCKED
Verdict: null
```

Reuse Cycle 006 semantics.

## 18. Path reclassification

Runtime evidence creates a new graph revision. Never silently rewrite historical graph evidence.

Provenance should link:

```text
parent_graph_digest
validation_result_digest
new_graph_digest
```

## 19. Safe chaining

Bounded chaining is allowed only when:

```text
each step is individually authorized
each step is non-destructive
the chain fits budget
stop conditions are explicit
synthetic data is used
```

No recursive autonomous exploration.

## 20. Human approval boundaries

Suggested policy:

### Low-risk modes

`PLAN_ONLY`, `SIMULATED`, and `LOCAL_SYNTHETIC` may be auto-approved by local policy.

### Explicit approval required

```text
AUTHORIZED_DYNAMIC
cross-tenant validation
state-changing test
external egress
privileged credential use
multi-step chain
```

## 21. Test-data policy

Prefer:

```text
synthetic identities
synthetic tenants
canary resources
test credentials
staging data
ephemeral resources
```

Avoid real PII, production secrets, customer content, and irreversible mutations.

## 22. Safety taxonomy

Each vector should carry safety metadata:

```text
READ_ONLY
REVERSIBLE_STATE_CHANGE
IRREVERSIBLE
EXFILTRATION_RISK
CROSS_TENANT
PRIVILEGED
EXTERNAL_EGRESS
```

Default allowed class is `READ_ONLY`, plus reviewed synthetic/reversible operations where explicitly authorized.

## 23. Synthetic validation fixtures

Initial fixtures:

```text
ADV-LAB-001 Confused deputy
ADV-LAB-002 Tool mutation
ADV-LAB-003 Argument mutation
ADV-LAB-004 Tenant boundary
ADV-LAB-005 Credential scope reuse
ADV-LAB-006 Budget exhaustion
ADV-LAB-007 Kill switch
ADV-LAB-008 No safe proof
```

## 24. Controlled Validation Runner

Responsibilities:

```text
load approved plan
verify digests
verify ROE
check preconditions
apply budget
execute allowed vector
capture evidence
stop on proof
stop on violation
emit result
```

It must not invent a stronger test when a planned vector fails.

## 25. Determinism

Agent reasoning may help select candidates, but once a plan is approved, execution is deterministic.

The agent cannot alter method, tool, arguments, target, budget, or scope without re-approval.

## 26. CLI direction

Candidate naming:

```text
dare-agent-security adversarial-validate
```

or equivalent current CLI convention.

Avoid naming that implies unrestricted exploitation.

## 27. CI

CI should validate:

```text
plan schema
vector schema
ROE gate
preconditions
budget enforcement
kill switch
digest mismatch
state-change denial
egress denial
evidence capture
path reclassification
fixtures
```

CI must use local deterministic fixtures only.

## 28. Security of the validator itself

Threats:

- malicious vector file;
- argument injection;
- path/target substitution;
- digest downgrade;
- ROE tampering;
- budget bypass;
- retry amplification;
- secret leakage;
- egress through allowed tool;
- agent modifying plan at runtime.

Controls:

- schema validation;
- immutable approved plan;
- canonical digests;
- runtime policy;
- strict allowlists;
- bounds;
- redaction;
- no arbitrary code in vectors;
- isolated execution;
- audit trail.

## 29. Scope

### In scope

- post-Cycle-008 reconciliation;
- validation-plan schema;
- test-vector schema;
- execution-budget schema;
- ROE authorization gate;
- deterministic preconditions;
- minimum-safe-proof registry;
- candidate eligibility;
- runtime enforcement;
- budget enforcement;
- kill switch;
- controlled runner;
- evidence integration;
- path reclassification;
- synthetic fixtures;
- CLI integration;
- CI regression;
- docs and final proof.

### Out of scope

- autonomous exploit loops;
- persistence;
- credential theft;
- uncontrolled lateral movement;
- internet-wide attack execution;
- destructive payloads;
- DoS;
- malware;
- continuous monitoring;
- enterprise orchestration.

## 30. Acceptance criteria

Cycle 009 is complete only when:

1. Post-Cycle-008 `main` is reconciled.
2. Versioned AdversarialValidationPlan schema exists.
3. Versioned AdversarialTestVector schema exists.
4. Versioned ExecutionBudget schema exists.
5. Dynamic execution requires valid authorization/ROE.
6. Missing/invalid ROE blocks execution.
7. Target/environment identity is validated before execution.
8. Attack-path digest is verified.
9. Validation-plan digest is verified.
10. Preconditions are deterministic and fail closed.
11. Minimum-safe-proof metadata is required.
12. Vector operations are bounded and non-arbitrary.
13. Execution budget is enforced.
14. Budget exhaustion stops execution.
15. Kill switch is implemented and tested.
16. Prohibited state-changing operations are denied by default.
17. External egress is denied by default unless explicitly authorized.
18. Synthetic/test data is preferred and enforced where applicable.
19. Cycle 001 evidence is reused.
20. Cycle 006 applicability/scope/execution/verdict are reused.
21. Cycle 008 path evidence can be reclassified from runtime evidence.
22. Original graph evidence is not silently rewritten.
23. Confused-deputy fixture works.
24. Tool-mutation fixture works.
25. Argument-mutation fixture works.
26. Tenant-boundary fixture works.
27. Budget-exhaustion fixture works.
28. Kill-switch fixture works.
29. No-safe-proof scenario performs no dynamic execution.
30. CLI defaults to safe/non-live mode.
31. CI uses only local deterministic fixtures.
32. Final DARE proof maps all criteria to files/tests/results.
33. `APPROVAL.md` remains absent until explicit human approval.

## 31. Exit gate

Human review must confirm:

- dynamic execution modes;
- ROE schema;
- minimum-safe-proof contract;
- budget defaults;
- kill-switch triggers;
- allowed safety classes;
- cross-tenant handling;
- state-change policy;
- egress policy;
- CLI naming;
- path reclassification vocabulary;
- fixture set.
