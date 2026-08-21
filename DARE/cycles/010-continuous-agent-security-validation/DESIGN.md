# Cycle 010 — Continuous Agent Security Validation

**Status:** APPROVED FOR EXECUTION  
**Cycle:** 010  
**Name:** Continuous Agent Security Validation  
**Base branch:** `main`  
**Planning baseline:** Cycles 001–009 delivered on `main`  
**Branch:** `agent/cycle-010-continuous-agent-security-validation`  
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
009 Controlled Agentic Adversarial Validation
```

DARE Agent Security can now discover, plan, validate, produce deterministic evidence, measure coverage, benchmark, derive attack graphs and safely validate selected attack paths.

Cycle 010 adds the final major core capability:

> **continuously determine what changed, what must be revalidated, and whether agentic security posture drifted.**

## 2. Problem

A point-in-time assessment becomes stale after code, configuration, inventory, authorization, credentials, policies, profiles, dependencies, runtime behavior or attack-path evidence changes.

Re-running everything blindly is expensive. Not re-running is unsafe.

Cycle 010 must answer:

```text
what changed?
what security properties are affected?
what attack paths are affected?
what validations must rerun?
what can be reused safely?
did security posture improve, regress, or become unknown?
```

## 3. Goal

```text
Baseline Security State
        ↓
Change Event / New Snapshot
        ↓
Change Detector
        ↓
Impact Resolver
        ↓
Affected Properties / Paths / Vectors
        ↓
Revalidation Plan
        ↓
Static / Passive / Controlled Validation
        ↓
New Evidence + Coverage
        ↓
Security State Diff
        ↓
CI / Report
```

The system must prefer **minimal deterministic revalidation** over blind full rescans while preserving correctness.

## 4. Core principle

> **Revalidate the smallest security-relevant surface whose assumptions changed.**

A reused result is valid only if all security-relevant inputs remain unchanged.

## 5. SecurityStateSnapshot

Introduce a canonical immutable snapshot:

```yaml
schema_version: "1"
security_state:
  id: state-2026-001
  target:
    id: target-001
    version: <sha>
  inventory_digest: sha256:...
  property_registry_digest: sha256:...
  profile_digest: sha256:...
  assessment_plan_digest: sha256:...
  evidence_bundle_digest: sha256:...
  coverage_digest: sha256:...
  attack_graph_digest: sha256:...
  validation_results_digest: sha256:...
  policies:
    coverage: sha256:...
    severity: sha256:...
    confidence: sha256:...
    continuous_validation: sha256:...
```

A new assessment produces a new snapshot; snapshots are never mutated.

## 6. SecurityChangeSet

Introduce normalized change classes:

```text
SOURCE_CODE_CHANGED
INVENTORY_CHANGED
CAPABILITY_ADDED
CAPABILITY_REMOVED
CAPABILITY_CLASS_CHANGED
AUTHORIZATION_CHANGED
CREDENTIAL_CHANGED
TENANT_MODEL_CHANGED
DEPENDENCY_CHANGED
PROFILE_CHANGED
PROPERTY_REGISTRY_CHANGED
COVERAGE_POLICY_CHANGED
SEVERITY_POLICY_CHANGED
CONFIDENCE_POLICY_CHANGED
ROE_CHANGED
ATTACK_GRAPH_CHANGED
VALIDATION_VECTOR_CHANGED
RUNTIME_EVIDENCE_CHANGED
```

Exact vocabulary must reconcile with the actual post-Cycle-009 schemas.

## 7. Change detection

Compare previous snapshot vs current inputs using security-relevant facts. A README change should not automatically trigger full security validation; a tool implementation or authorization policy change should.

Prefer semantic digests to raw timestamps.

## 8. Impact Resolver

Map changes to affected artifacts:

```text
TOOL_IMPLEMENTATION_CHANGED
    ↓
capability inventory
    ↓
authorization properties
    ↓
execution-integrity properties
    ↓
related graph edges / paths
    ↓
related validation vectors
```

Example output:

```yaml
impact:
  properties:
    - MCP.AUTHZ.PER_OPERATION
  attack_paths:
    - path-001
  validations:
    - vector-003
```

## 9. ContinuousRevalidationPlan

Introduce:

```yaml
revalidation_plan:
  id: crp-001
  baseline_state: state-001
  candidate_state: state-002
  change_set_digest: sha256:...
  required:
    properties:
      - MCP.AUTHZ.PER_OPERATION
    paths:
      - path-001
    vectors:
      - vector-003
  reusable:
    properties:
      - MCP.PASSIVE.DISCOVERY.ALLOWLIST
```

Actions must be explicit:

```text
REVALIDATE
REUSE
INVALIDATE
UNKNOWN
```

## 10. Safe result reuse

A result may be reused only when all relevant dependencies remain stable:

```text
property ID/version
+
target artifact digest
+
inventory facts
+
profile digest
+
policy digests
+
vector digest
+
environment assumptions
```

If a mandatory dependency is unknown, reuse is denied.

## 11. Cache semantics

Cache is an optimization, not evidence.

```text
cache references original evidence
cache never creates PASS by itself
cache reuse must be explainable
cache invalidation must be deterministic
```

## 12. Drift model

Use:

```text
IMPROVED
REGRESSED
UNCHANGED
UNKNOWN
```

`UNKNOWN` is mandatory when a previously proven state cannot currently be re-established.

## 13. Property drift

Track transitions such as:

```text
PASS -> FAIL
FAIL -> PASS
PASS -> INCONCLUSIVE
PASS -> ERROR
TESTED -> BLOCKED
NOT_APPLICABLE -> APPLICABLE
OUT_OF_SCOPE -> IN_SCOPE
```

## 14. Coverage drift

Track:

```text
assessment_coverage_delta
blocked_delta
not_tested_delta
error_delta
```

A lower finding count with worse coverage is not automatically an improvement.

## 15. Attack Graph drift

Track:

```text
NODE_ADDED
NODE_REMOVED
EDGE_ADDED
EDGE_REMOVED
EDGE_STATUS_CHANGED
AUTHORITY_CONTEXT_CHANGED
PATH_ADDED
PATH_REMOVED
PATH_STATUS_CHANGED
IMPACT_FACTOR_CHANGED
```

A new privileged or cross-tenant path may be a regression even before an explicit FAIL.

## 16. Validation drift

Revalidate Cycle 009 results when path, vector, target, ROE, proof preconditions or environment assumptions change.

Do not rerun dynamic validation for unrelated changes.

## 17. ContinuousValidationPolicy

Example:

```yaml
continuous_validation:
  version: "1.0.0"
  triggers:
    source_change: true
    inventory_change: true
    profile_change: true
    policy_change: true
  revalidation:
    prefer_incremental: true
    fallback_full_on_unknown: true
  dynamic:
    auto_modes:
      - PLAN_ONLY
      - SIMULATED
      - LOCAL_SYNTHETIC
    require_approval:
      - AUTHORIZED_DYNAMIC
  gates:
    fail_on_regression:
      severity: [CRITICAL, HIGH]
    fail_on_new_attack_path:
      destructive: true
      cross_tenant: true
```

## 18. Trigger model

Core engine should support deterministic invocation from:

```text
Git commit / PR
manual invocation
new assessment snapshot
profile update
policy update
inventory update
runtime evidence import
```

Cycle 010 does not need to build a scheduler service.

## 19. CI integration

```text
PR
 ↓
detect security change set
 ↓
derive revalidation plan
 ↓
run affected validations
 ↓
compare trusted baseline
 ↓
gate
```

Report new/resolved failures, coverage delta, new/removed paths, reuse decisions and unknown posture.

## 20. Baseline selection

Baseline must be explicit and trustworthy, e.g.:

```text
explicit state ID
```

or policy-driven:

```text
last successful main-branch state
```

Do not silently select arbitrary latest state.

## 21. Unknown propagation

Unknown propagates conservatively:

```text
inventory completeness unknown
→ graph completeness unknown

affected property blocked
→ drift UNKNOWN

missing baseline
→ comparison unavailable
```

Never convert unknown to PASS.

## 22. Incremental execution

For an isolated tool change, revalidate only relevant inventory facts, authorization/integrity properties, graph edges/paths and vectors when the impact mapping is complete.

## 23. Full fallback

```text
impact resolution == UNKNOWN
    ↓
FULL REVALIDATION
```

Correctness dominates optimization.

## 24. Runtime evidence import

Cycle 010 may ingest trusted runtime evidence to update graph/path assurance, but it is not a runtime sensor platform.

## 25. Longitudinal history

Persist immutable transitions:

```text
State A
  ↓ ChangeSet + Plan + Result
State B
  ↓ ChangeSet + Plan + Result
State C
```

## 26. Regression semantics

Configurable regressions include:

```text
new FAIL
severity increase
confidence increase on existing FAIL
coverage drop below threshold
new BLOCKED/ERROR required property
new risky attack path
new privileged credential edge
new cross-tenant path
new destructive capability
```

## 27. Remediation verification

```text
FAIL
↓
fix
↓
change detection
↓
same property/vector revalidation
↓
PASS
```

This is part of continuous validation; full remediation workflow is future product scope.

## 28. Example report

```text
DARE Continuous Security Validation
────────────────────────────────────────
Baseline: state-a1b2
Current:  state-c3d4
Security Drift: REGRESSED

Changed security inputs:      4
Properties revalidated:       7
Properties reused:           31
Properties invalidated:       2

New FAIL:                     1
Resolved FAIL:                0

Assessment Coverage:
  before: 94%
  after:  92%

Attack Paths:
  new:                         2
  removed:                     0
  changed:                     1

CI Gate: FAIL
```

## 29. Determinism and provenance

Every run records baseline digest, candidate input digests, change-set digest, revalidation-plan digest, engine commit, profile/policy digests, evidence digests, graph digests and validation-result digests.

## 30. Security threats

Threats include stale baseline substitution, cache poisoning, false reuse, omitted changed inputs, dependency bypass, profile/policy downgrade, evidence substitution and implicit dynamic-approval escalation.

Controls: immutable snapshots, canonical digests, explicit baseline, fail-safe invalidation, ROE preservation, and no cache-only PASS creation.

## 31. Synthetic fixtures

```text
CONT-LAB-001 Unrelated documentation change
CONT-LAB-002 Tool implementation change
CONT-LAB-003 New destructive capability
CONT-LAB-004 Authorization fix
CONT-LAB-005 Coverage degradation
CONT-LAB-006 Unknown impact → full fallback
CONT-LAB-007 Invalid cache reuse attempt
CONT-LAB-008 Dynamic validation remains approval-gated
```

## 32. CLI direction

Potential operations:

```text
snapshot
diff
plan
revalidate
report
```

Exact naming must follow actual post-Cycle-009 CLI architecture.

## 33. Scope

### In scope

- post-Cycle-009 reconciliation;
- SecurityStateSnapshot;
- SecurityChangeSet;
- change detector;
- impact resolver;
- ContinuousRevalidationPlan;
- safe result reuse;
- deterministic cache invalidation;
- property/coverage/graph/path/validation drift;
- continuous policy;
- explicit baseline selection;
- incremental revalidation;
- full fallback on unknown;
- CI integration;
- longitudinal state history;
- synthetic fixtures;
- CLI integration;
- documentation and final proof.

### Out of scope

- SaaS scheduler;
- fleet orchestration;
- runtime sensor agent;
- multi-tenant control plane;
- SSO/RBAC;
- dashboards;
- alert-delivery services;
- ticketing integrations;
- new attestation subsystem;
- enterprise remediation workflow;
- autonomous policy generation.

## 34. Acceptance criteria

1. Post-Cycle-009 `main` reconciled.
2. Versioned SecurityStateSnapshot schema exists.
3. Versioned SecurityChangeSet schema exists.
4. Versioned ContinuousRevalidationPlan schema exists.
5. Baseline selection is explicit and deterministic.
6. Security-relevant changes are classified.
7. Unrelated changes avoid unnecessary revalidation.
8. Impact Resolver maps changes to properties.
9. Impact Resolver maps changes to attack paths.
10. Impact Resolver maps changes to validation vectors.
11. Plan distinguishes REVALIDATE/REUSE/INVALIDATE/UNKNOWN.
12. Reuse requires unchanged security dependencies.
13. Unknown reuse dependency denies reuse.
14. Cache cannot create PASS without original evidence.
15. Cache invalidation is deterministic.
16. Property drift is reported.
17. Coverage drift is reported.
18. Attack Graph drift is reported.
19. Attack Path drift is reported.
20. Validation-result drift is reported.
21. New risky paths can trigger regression.
22. Coverage degradation can trigger regression.
23. UNKNOWN is not treated as unchanged/PASS.
24. Unknown impact falls back to full revalidation.
25. Dynamic validation remains ROE/approval-gated.
26. Incremental execution works for isolated tool changes.
27. Remediation verification can show FAIL -> PASS.
28. Continuous policy is versioned/digested.
29. CI can compare current state to trusted baseline.
30. Report includes new/resolved findings and coverage/path deltas.
31. Longitudinal transition records are immutable/reproducible.
32. Synthetic fixtures cover change, regression, improvement, unknown, cache and dynamic-gate cases.
33. CI tests use deterministic local fixtures.
34. Final DARE proof maps all criteria to files/tests/results.
35. `APPROVAL.md` remains absent until explicit human approval.

## 35. Exit gate

Human review must confirm snapshot schema, change taxonomy, impact rules, reuse/cache semantics, full-fallback conditions, regression policy, baseline selection, graph-drift semantics, dynamic automation limits, CLI naming and fixture set.

## 36. Core feature freeze

After successful Cycle 010 completion:

```text
CORE FEATURE FREEZE
```

Recommended next cycle:

> **Cycle 011 — Productization & v1.0 Release Readiness**

Cycle 011 focuses on installation, onboarding, CLI UX, configuration stability, reporting, documentation, diagnostics, packaging, compatibility, release automation and v1.0 acceptance testing.

After v1.0, roadmap decisions should be driven primarily by real external usage and operator/customer feedback.
