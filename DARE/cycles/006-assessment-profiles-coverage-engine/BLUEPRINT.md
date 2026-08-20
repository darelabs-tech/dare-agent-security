# Cycle 006 — Blueprint

**Status:** ARCHITECTURE PROPOSED  
**Approval:** PENDING

## Baseline

This blueprint assumes only:

```text
Cycle 001
Cycle 002
Cycle 003
Cycle 004
```

are available on `main`.

Cycle 005 is not a dependency.

## Architecture

```text
Property Registry
      +
Assessment Profile
      +
Discovery Inventory
      +
Scope / ROE
        ↓
Applicability Engine
        ↓
Assessment Plan
        ↓
Existing Analyzers
        ↓
Cycle 001 Evidence
        ↓
Coverage Correlator
        ↓
Coverage Report
        ↓
Cycle 004 CI Gate
```

## Component boundaries

### Property Registry

Owns stable property definitions.

### Profile

Owns property selection and requirement levels.

### Applicability Engine

Owns deterministic target-specific applicability decisions.

### Assessment Plan

Owns the pre-execution expected test set.

### Existing analyzers

Own security analysis.

### Coverage Correlator

Owns plan/result/evidence reconciliation.

### CI Adapter

Owns threshold and process-result behavior.

## Property registry schema

Candidate:

```yaml
schema_version: "1"

id: MCP.AUTHZ.PER_OPERATION
title: Per-operation authorization
category: AUTHORIZATION

applicability:
  predicates:
    - tools_present

supported_modes:
  - static
  - dynamic

evidence:
  required_for_confirmed_verdict: true
```

No arbitrary code.

## Constrained applicability predicates

Examples:

```text
tools_present
resources_present
prompts_present
transport_http
transport_stdio
authorization_present
dynamic_authorization_allowed
execution_integrity_supported
```

Typed predicate evaluation should be implemented in code.

Profile/property files reference known predicate names.

Do not evaluate arbitrary expressions.

## Profile schema

Candidate:

```yaml
schema_version: "1"
id: mcp-security-baseline
version: "1.0.0"

properties:
  - id: MCP.DISCOVERY.PASSIVE_BOUNDARY
    requirement: REQUIRED

  - id: MCP.AUTHZ.PER_OPERATION
    requirement: REQUIRED
```

## Domain model

```text
CoverageStatus
├── Applicable
├── NotApplicable
├── NotTested
├── OutOfScope
└── Blocked
```

Verdict remains the Cycle 001 type.

## State constraints

During planning:

```text
APPLICABLE + verdict:null
```

is allowed.

At finalization:

```text
APPLICABLE + verdict:null
```

must transition to:

```text
NOT_TESTED
```

or:

```text
BLOCKED
```

with reason.

Invalid final states:

```text
NOT_APPLICABLE + PASS
OUT_OF_SCOPE + FAIL
NOT_TESTED + PASS
BLOCKED + INCONCLUSIVE
```

## Local deterministic fixtures

Because Cycle 005 is not assumed to exist, Cycle 006 owns only minimal **coverage fixtures**, not a security lab.

Examples:

```text
Fixture A:
inventory has tools
profile requires per-operation auth
ROE allows static only
expected applicability/status known

Fixture B:
stdio transport
HTTP-only property
expected NOT_APPLICABLE

Fixture C:
dynamic property applicable
ROE blocks dynamic
expected BLOCKED
```

These fixtures validate coverage logic, not vulnerability detection.

## Coverage math

Recommended:

```text
eligible =
  finalized evaluated properties
  + NOT_TESTED
  + BLOCKED

tested =
  finalized properties with verdict

coverage = tested / eligible
```

Required coverage:

```text
required_tested / required_eligible
```

Exclude NOT_APPLICABLE and OUT_OF_SCOPE from denominator.

## Evidence bridge

The Coverage Engine references Cycle 001 evidence IDs or paths.

It does not duplicate evidence payloads.

## CLI direction

Prefer:

```text
dare-agent-security validate --profile <profile>
```

Potential:

```text
dare-agent-security plan
```

only if current CLI architecture benefits from exposing the plan explicitly.

Do not add a `coverage` command merely to create a new command.

## CI direction

Cycle 004 is extended with optional inputs such as:

```text
profile
min-required-coverage
fail-on-required-blocked
```

Exact input names must follow the actual Action contract on `main`.

## Threat model

### Profile injection

Mitigation:
- schema validation;
- known property IDs;
- known predicates.

### Property deletion

Mitigation:
- versioned profile;
- profile digest;
- CI logs exact profile/version.

### Applicability bypass

Mitigation:
- deterministic predicate traces;
- no LLM-only applicability decisions.

### Denominator manipulation

Mitigation:
- fixed documented formula;
- semantic validation;
- tests.

### Status relabeling

Mitigation:
- typed state transitions;
- immutable rationale audit in final report.

## Optional Cycle 005 adapter

If Cycle 005 later exists on `main`, a small adapter may map:

```text
scenario id -> property id
```

This must be isolated from core coverage code.

Suggested location:

```text
integrations/cycle-005/
```

or repository-equivalent.

If absent, all core Cycle 006 acceptance tests still pass.

