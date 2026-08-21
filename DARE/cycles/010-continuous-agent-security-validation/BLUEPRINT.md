# Cycle 010 — Blueprint

**Status:** APPROVED FOR EXECUTION  
**Approval:** APPROVED (2026-08-20)

## Dependency statement

Cycle 010 reuses Cycles 001–009. It must not create parallel evidence, coverage, verdict, attack graph/path, adversarial validation or property-registry models.

## Architecture

```text
Baseline SecurityStateSnapshot
          +
Current Target / Config / Policy Inputs
          ↓
Security Change Detector
          ↓
SecurityChangeSet
          ↓
Impact Resolver
          ↓
ContinuousRevalidationPlan
          ↓
REUSE / REVALIDATE / INVALIDATE / UNKNOWN
          ↓
Existing DARE Validation Engine
          ↓
New Evidence + Coverage + Graph
          ↓
New SecurityStateSnapshot
          ↓
Drift Engine
          ↓
Continuous Validation Report
```

## Components

- **Snapshot Builder** — immutable state from existing artifacts.
- **Change Detector** — semantic security change facts.
- **Impact Resolver** — affected properties, paths, vectors and policies.
- **Revalidation Planner** — reuse/revalidate/invalidate/full fallback.
- **Result Reuse Validator** — proves old evidence remains valid.
- **Drift Engine** — property/coverage/graph/path/validation transitions.
- **Continuous Gate** — applies versioned regression policy.

## Snapshot identity

Use existing canonicalization/digest conventions. Snapshot inputs include target revision, inventory, registry, profile, plan, coverage, evidence, graph, validation results and policies.

## Change facts

Prefer normalized facts, e.g.:

```yaml
change:
  type: CAPABILITY_ADDED
  source: inventory
  entity: tool:invoice.delete
  before: null
  after: <digest>
```

## Impact mapping

Prefer explicit dependency data rather than LLM-only inference.

```yaml
dependencies:
  MCP.AUTHZ.PER_OPERATION:
    depends_on:
      - inventory.tools
      - authorization.policy
      - tool.identity
```

## Reuse validator

```text
can_reuse(result):
  original evidence exists
  AND property version unchanged
  AND relevant target facts unchanged
  AND profile semantics unchanged
  AND relevant policy unchanged
  AND environment assumptions unchanged
```

Otherwise false.

## Full fallback

Mandatory when dependency mapping, inventory completeness, schema migration or impact analysis is unknown/incomplete.

## Drift engine

Track transitions, not only current state.

## Graph diff

Use stable Cycle 008 node/edge/path IDs and compare evidence states, authority contexts and impact factors.

## Dynamic execution

Cycle 009 modes remain authoritative. `AUTHORIZED_DYNAMIC` remains separately authorization-gated.

## CI

Use small deterministic transition fixtures: baseline + patch → expected change set → expected plan → expected drift.

## Performance

Measure full assessment time, incremental time, reuse ratio, impact-resolution time and graph-diff time. Correctness comes first.

## Core freeze

After acceptance, do not add another major security capability before v1.0 productization.
