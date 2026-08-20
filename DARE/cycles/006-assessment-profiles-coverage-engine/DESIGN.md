# Cycle 006 — Assessment Profiles & Coverage Engine

**Status:** DESIGN READY FOR REVIEW  
**Cycle:** 006  
**Name:** Assessment Profiles & Coverage Engine  
**Base branch:** `main`  
**Confirmed planning baseline:** Cycles 001–004 delivered on `main`  
**Cycle 005:** not assumed to be merged; integration is optional/conditional  
**Proposed branch:** `agent/cycle-006-assessment-profiles-coverage-engine`  
**Approval:** PENDING — do not create `APPROVAL.md` before explicit human approval.

## Context

This revision is intentionally based on the repository state **before Cycle 005 is merged**.

The baseline assumed on `main` is:

```text
Cycle 001 — Evidence Kernel
Cycle 002 — Passive MCP Discovery
Cycle 003 — Authorization-to-Execution Integrity
Cycle 004 — CI Security Gate
```

Cycle 005 — Synthetic MCP Security Lab & Scenario Corpus — may exist on another branch, but Cycle 006 must not depend on its files, schemas, runner, or scenario IDs being present on `main`.

## Problem

DARE Agent Security can already:

```text
discover
+
validate
+
produce deterministic evidence
+
run in CI
```

But deterministic evidence alone does not answer:

> **Did the assessment test every security property it was expected to test?**

A run with:

```text
0 FAIL
```

does not prove:

```text
all applicable properties were evaluated
```

## Goal

Introduce a deterministic assessment-coverage layer:

```text
Discovery Inventory
        ↓
Security Property Registry
        ↓
Assessment Profile
        ↓
Applicability Engine
        ↓
Assessment Plan
        ↓
Existing Security Engine
        ↓
Coverage Correlation
        ↓
Evidence + Coverage Report
```

## Core principle

> **The system must prove not only what failed or passed, but also what should have been tested and what was not tested.**

## Independence from Cycle 005

Cycle 006 must be implementable and testable without Cycle 005.

Required strategy:

```text
Cycle 006 core tests
    -> local unit/property fixtures owned by Cycle 006

Cycle 005 integration
    -> optional adapter/integration task only if Cycle 005 is present
```

Cycle 006 must not copy Cycle 005 scenario implementations into its own domain model.

If Cycle 005 is merged before or during Cycle 006 execution, an optional integration task may map scenario IDs to property IDs.

If Cycle 005 remains unmerged, Cycle 006 still completes against its own deterministic fixtures.

## Separate dimensions

### Coverage Status

```text
APPLICABLE
NOT_APPLICABLE
NOT_TESTED
OUT_OF_SCOPE
BLOCKED
```

### Verdict

Existing evidence verdict vocabulary remains:

```text
PASS
FAIL
INCONCLUSIVE
ERROR
```

The two dimensions must remain distinct.

Valid:

```yaml
property: MCP.DISCOVERY.PASSIVE_BOUNDARY
coverage_status: APPLICABLE
verdict: PASS
```

Valid:

```yaml
property: MCP.AUTHZ.PER_TOOL
coverage_status: BLOCKED
reason: dynamic authorization testing prohibited by ROE
verdict: null
```

Invalid:

```yaml
coverage_status: NOT_TESTED
verdict: PASS
```

## Security Property Registry

Create a versioned registry with stable security-property identifiers.

Initial property groups should derive only from capabilities already delivered on `main`:

```text
DISCOVERY
IDENTITY
AUTHENTICATION
AUTHORIZATION
AUTHZ_EXECUTION_INTEGRITY
CAPABILITY_EXPOSURE
CREDENTIAL_BOUNDARIES
EVIDENCE
```

Do not introduce MRTR/lab-specific properties unless the current `main` already supports them or they are explicitly marked future/unsupported.

Candidate IDs:

```text
MCP.DISCOVERY.PASSIVE_BOUNDARY
MCP.DISCOVERY.EXPLICIT_TARGET
MCP.AUTHZ.PER_OPERATION
MCP.AUTHZ.EXECUTION_INTEGRITY.TOOL_NAME
MCP.AUTHZ.EXECUTION_INTEGRITY.ARGUMENTS
MCP.AUTHZ.EXECUTION_INTEGRITY.CONTEXT
MCP.IDENTITY.CONFUSED_DEPUTY
MCP.EVIDENCE.REDACTION
```

Exact IDs must be reconciled against the real Cycle 001–004 implementation during Task 001.

## Assessment Profile

A profile is a versioned declaration of expected properties.

Example:

```yaml
schema_version: "1"

id: mcp-security-baseline
version: "1.0.0"

properties:
  - id: MCP.DISCOVERY.PASSIVE_BOUNDARY
    requirement: REQUIRED

  - id: MCP.AUTHZ.PER_OPERATION
    requirement: REQUIRED

  - id: MCP.AUTHZ.EXECUTION_INTEGRITY.TOOL_NAME
    requirement: CONDITIONAL
```

A profile defines expected assessment scope.

It does not define findings or verdicts.

## Applicability Engine

Applicability must be deterministic and based on typed facts.

Examples:

```text
tools.count > 0
    -> per-operation authorization property may be APPLICABLE

transport == stdio
    -> HTTP-specific property NOT_APPLICABLE

authorization-integrity capability unavailable
    -> applicable property may become NOT_TESTED

dynamic test prohibited by ROE
    -> BLOCKED
```

Never relabel:

```text
BLOCKED
```

as:

```text
NOT_APPLICABLE
```

to improve coverage.

## Assessment Plan

The assessment plan must exist **before security execution**.

For every profile property:

```text
property id
requirement level
applicability
planned execution mode
deterministic rationale
blocking/out-of-scope reason
```

Example:

```yaml
assessment_plan:
  - property: MCP.DISCOVERY.PASSIVE_BOUNDARY
    requirement: REQUIRED
    coverage_status: APPLICABLE
    execution_mode: passive

  - property: MCP.AUTHZ.PER_OPERATION
    requirement: REQUIRED
    coverage_status: BLOCKED
    reason: dynamic authorization validation not allowed by ROE
```

## Coverage math

The denominator must be explicit.

Recommended baseline:

```text
eligible =
    properties finalized with verdict
  + NOT_TESTED
  + BLOCKED

tested =
    eligible properties with verdict

coverage = tested / eligible
```

Exclude:

```text
NOT_APPLICABLE
OUT_OF_SCOPE
```

from the baseline denominator.

Any alternative denominator must be documented and covered by tests.

## Required vs optional coverage

Profiles may use:

```text
REQUIRED
CONDITIONAL
OPTIONAL
```

At minimum, reporting should distinguish:

```text
required_coverage
overall_coverage
```

If this adds undue complexity to the existing design, `required_coverage` takes priority over additional metrics.

## Evidence correlation

A final evaluated property must correlate to existing evidence.

Example:

```yaml
property_result:
  property_id: MCP.AUTHZ.EXECUTION_INTEGRITY.TOOL_NAME
  coverage_status: APPLICABLE
  verdict: FAIL
  evidence_ids:
    - evidence-123
```

Do not create a second evidence format.

Cycle 001 remains the evidence contract.

## CI integration

Cycle 004 must be extended rather than replaced.

Example summary:

```text
Profile: mcp-security-baseline@1.0.0

Required coverage: 90%
Overall coverage: 86%

Verdicts
PASS: 24
FAIL: 2
INCONCLUSIVE: 1
ERROR: 0

Coverage
NOT_TESTED: 3
BLOCKED: 2
OUT_OF_SCOPE: 4
NOT_APPLICABLE: 6
```

Potential deterministic gates:

```text
FAIL present                  -> fail
ERROR present                 -> fail
required coverage < threshold -> configurable fail
required property BLOCKED     -> configurable fail
```

## Optional Cycle 005 integration

If Cycle 005 has been merged before Task 010 begins, the cycle may add a mapping layer:

```text
MCP-LAB-* scenario
    ↓
Security Property ID
```

This integration must:

- reuse Cycle 005 schemas;
- not redefine lab semantics;
- remain optional to Cycle 006 completion.

Cycle 006 acceptance must not depend on a branch outside `main`.

## Scope

### In scope

- reconcile real post-Cycle-004 `main`;
- property registry;
- assessment-profile schema;
- typed applicability engine;
- assessment-plan artifact;
- coverage-status model;
- coverage math;
- evidence correlation;
- CLI integration;
- Cycle 004 CI extension;
- deterministic local fixtures;
- adversarial profile/coverage tests;
- optional Cycle 005 adapter if available;
- docs and final DARE proof.

### Out of scope

- depending on unmerged Cycle 005 artifacts;
- public benchmark corpus;
- Agent Attack Graph;
- expanded adversarial engine;
- SaaS/dashboard;
- enterprise profile service;
- compliance certification;
- external policy distribution.

## Acceptance criteria

1. The real Cycle 001–004 `main` contracts are reconciled.
2. No core Cycle 006 file depends on Cycle 005 being present.
3. A versioned Security Property Registry exists.
4. A versioned Assessment Profile schema exists.
5. A deterministic Applicability Engine exists.
6. Assessment Plan is generated before execution.
7. Coverage status and verdict are separate domain types.
8. Contradictory status/verdict combinations fail validation.
9. NOT_APPLICABLE, NOT_TESTED, OUT_OF_SCOPE, and BLOCKED remain distinct.
10. Coverage denominator semantics are documented and tested.
11. Required coverage is measurable.
12. Property results correlate to Cycle 001 evidence.
13. CI reports profile, coverage, and verdict summary.
14. Coverage threshold behavior is deterministic.
15. A ROE-blocked property never becomes NOT_APPLICABLE.
16. An applicable untested property cannot silently become PASS.
17. Every property inclusion/exclusion decision has deterministic rationale.
18. Profile data cannot execute arbitrary code.
19. Local deterministic fixtures validate coverage behavior without Cycle 005.
20. Optional Cycle 005 integration does not become a hidden prerequisite.
21. Final DARE proof maps all criteria to implementation/tests/results.

## Exit gate

Before `APPROVAL.md`, human review must confirm:

- Cycle 006 is intentionally based on post-Cycle-004 `main`;
- Cycle 005 is optional for this cycle;
- taxonomy direction;
- coverage denominator;
- profile requirement vocabulary;
- CI coverage policy;
- CLI integration direction.

