# Cycle 005 — Blueprint

**Status:** ARCHITECTURE APPROVED  
**Approval:** APPROVED

## Dependency statement

Cycle 005 depends on the delivered contracts of:

```text
001 Evidence Kernel
002 Passive MCP Discovery
003 Authorization-to-Execution Integrity
004 CI Security Gate
```

The lab must reuse those contracts.

It must not create:

- a second evidence model;
- a second authorization-integrity engine;
- a second CI result model.

## Task 001 gate

Before implementation:

- inspect actual `main`;
- identify current CLI;
- identify Cycle 004 Action/CI contract;
- identify evidence schemas;
- identify current synthetic labs;
- identify MCP SDK/revision support;
- identify test conventions.

If current code contradicts this blueprint, return to Review.

## Architecture

```text
Scenario Manifest
      |
      v
Scenario Loader
      |
      +-------------------+
      |                   |
      v                   v
secure variant      vulnerable variant
      |                   |
      +---------+---------+
                |
                v
      Synthetic MCP Runtime
                |
                v
    Existing DARE Security Engine
      /        |         \
 discover   validate    evidence
      \        |         /
       +-------+--------+
               |
               v
      Scenario Assertion Layer
               |
        +------+------+
        |             |
        v             v
 expected         observed
        \             /
         +-----+-----+
               |
               v
      deterministic result
               |
               v
             CI
```

## Component boundaries

### A. Scenario manifest

Owns:

- scenario identity;
- property identity;
- variants;
- expected coverage status;
- expected verdict;
- test inputs;
- standards mappings;
- limitations.

The manifest must not contain executable shell snippets that bypass the runner safety model.

### B. Synthetic target

Owns:

- implementation behavior;
- secure/vulnerable distinction;
- local synthetic state;
- deterministic responses.

It must not own verdict logic.

### C. DARE security engine

Owns all real security analysis.

The lab must call existing:

- discovery;
- authorization integrity;
- evidence;
- CI result contracts.

### D. Assertion layer

Compares:

```text
expected scenario outcome
vs
observed machine outcome
```

It does not perform security analysis itself.

### E. CI integration

Uses existing Cycle 004 gate.

Expected vulnerable results should be represented as test assertions:

```text
expected: FAIL
observed: FAIL
scenario test: PASS
```

This distinction is mandatory.

## Scenario schema

Recommended structure:

```yaml
schema_version: "1"

id: MCP-LAB-005
title: Argument mutation after PERMIT
family: authorization-integrity

mcp:
  revision: "2026-07-28"

property:
  id: AUTHZ_EXECUTION_INTEGRITY_ARGUMENTS
  description: >
    Authorization-relevant arguments must remain bound
    to the final forwarded operation.

variants:
  secure:
    target: secure
    expected:
      coverage_status: APPLICABLE
      verdict: PASS

  vulnerable:
    target: vulnerable
    expected:
      coverage_status: APPLICABLE
      verdict: FAIL

standards:
  - source: COAZ-MCP
    reference: authorization-to-execution binding
    status: DRAFT_OR_OPEN_PROPOSAL

safety:
  destructive: false
  external_network: false
  real_credentials: false
```

Use an actual schema definition if repository conventions already support one.

## Coverage model

Cycle 005 should consume, not fully generalize, coverage semantics.

At minimum a scenario may use:

```text
APPLICABLE
NOT_APPLICABLE
NOT_TESTED
OUT_OF_SCOPE
BLOCKED
```

If Cycle 006 later formalizes coverage engine semantics, Cycle 005 manifests should remain forward-compatible.

## Scenario isolation

Every scenario should:

- use temporary/in-memory state;
- use unique local endpoints or test harness handles;
- reset state deterministically;
- avoid ordering dependencies;
- avoid shared mutable global state;
- run repeatedly.

Parallel execution is allowed only where isolation is proven.

## Scenario families

### Family A — Passive boundary

Targets Cycle 002 properties.

Key assertion:

```text
passive mode never dispatches active operations
```

### Family B — Authorization presence

Targets missing/coarse authorization.

Key assertion:

```text
authentication != authorization
```

### Family C — Confused deputy

Targets principal/agent/service identity separation.

### Family D — Authorization-to-execution integrity

Targets Cycle 003:

- tool name mutation;
- mapped argument mutation;
- trusted context mutation;
- representation/control scenarios.

### Family E — Modern MCP routing semantics

Targets modern request metadata and semantic consistency.

### Family F — Modern authorization semantics

Targets issuer validation / credential binding in synthetic form.

### Family G — MRTR

Targets security-relevant input introduced after an initial decision.

## Header/body divergence safety

The lab may model inconsistent metadata/body behavior only inside a synthetic target.

It must not send malformed or adversarial requests to real external servers.

The goal is to validate the security engine against a known-bad local implementation.

## MRTR safety

MRTR scenarios must use synthetic data and deterministic interaction scripts.

No model-generated secret or customer data should be involved.

## Standards mapping

Mappings are metadata.

They do not determine verdicts.

Each mapping must include status:

```text
FINAL
DRAFT
OPEN_PROPOSAL
INFORMATIVE
```

Never represent a draft/open issue as normative.

## Versioning

A scenario result should identify:

```text
scenario schema version
scenario id
scenario revision
repository commit
DARE engine version/commit
MCP revision/profile
```

This enables reproducible retest.

## Directory proposal

```text
labs/mcp-security/
├── README.md
├── schema/
│   └── scenario.schema.json
├── scenarios/
│   ├── MCP-LAB-001/
│   │   ├── scenario.yaml
│   │   ├── secure/
│   │   └── vulnerable/
│   └── ...
├── shared/
│   ├── fixtures/
│   ├── identities/
│   └── policies/
└── runner/
```

Adapt to the actual repository.

## Runner strategy

Prefer a thin scenario orchestrator.

The runner should:

1. load scenario manifest;
2. start selected local variant;
3. invoke the real DARE engine;
4. read machine evidence;
5. compare observed vs expected;
6. produce scenario-test result;
7. teardown target.

Do not replicate security checks in the runner.

## Scenario test result

Important distinction:

```text
Security verdict:
FAIL

Scenario assertion:
PASS
```

This means:

```text
the intentionally vulnerable fixture was correctly detected
```

## Final proof

Cycle completion requires a matrix similar to:

| Scenario | Secure | Vulnerable | CI |
|---|---|---|---|
| MCP-LAB-001 | PASS | FAIL | PASS |
| MCP-LAB-002 | PASS | FAIL | PASS |
| ... | ... | ... | ... |

The last column means the scenario test itself behaved as expected.

