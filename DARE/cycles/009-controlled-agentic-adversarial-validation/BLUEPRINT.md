# Cycle 009 — Blueprint

**Status:** APPROVED FOR EXECUTION  
**Approval:** APPROVED (2026-08-20)

## Dependency statement

Cycle 009 reuses Cycles 001–008. Do not create parallel evidence, coverage, verdict, graph, path, or property models.

## Architecture

```text
Cycle 008 AttackPath
      +
Cycle 006 Security Property
      +
ROE / Authorization
      ↓
Candidate Selector
      ↓
Minimum Safe Proof Planner
      ↓
AdversarialValidationPlan
      ↓
Approval Gate
      ↓
Precondition Engine
      ↓
Runtime Policy
      ↓
Execution Budget
      ↓
Adversarial Test Vector
      ↓
Controlled Runner
      ↓
Cycle 001 Evidence
      ↓
ValidationResult
      ↓
Graph / Path Reclassification
```

## Component boundaries

### Candidate Selector
Filters paths eligible for validation.

### Minimum Safe Proof Planner
Selects the least harmful proof class defined by the property registry.

### Approval Gate
Validates authorization, target, environment, category, identities, data classes, egress and budget.

### Precondition Engine
Evaluates deterministic prerequisites and fails closed.

### Controlled Runner
Executes only approved steps.

### Budget Enforcer
Stops on operation/time/state/egress/read/write/retry/chain bounds.

### Kill Switch
Aborts on unexpected behavior.

### Reclassification Adapter
Produces a new graph/path revision from evidence.

## Validation plan schema

```yaml
validation_plan:
  id: avp-001
  attack_path_id: path-001
  property_id: MCP.IDENTITY.CONFUSED_DEPUTY
  target_id: target-001
  target_version: <sha>
  mode: LOCAL_SYNTHETIC
  proof:
    objective: ...
    minimum_safe_condition: ...
  roe:
    id: ROE-001
    digest: sha256:...
  vector:
    id: vector-001
    digest: sha256:...
  budget:
    id: budget-001
    digest: sha256:...
```

## Vector constraints

Vector is data, not code.

Allowed fields describe method, capability/tool, arguments, expected secure/vulnerable outcome, stop condition, and preconditions.

Disallow embedded shell/Python/eval/arbitrary callbacks in vector data.

## Minimum Safe Proof registry

Prefer property-driven metadata:

```yaml
MCP.IDENTITY.CONFUSED_DEPUTY:
  proof_class: READ_ONLY
  required_test_data:
    - synthetic_tenant_a
    - synthetic_tenant_b_canary
  max_operations: 2
```

## Runtime policy

Before every operation:

```text
plan digest valid?
vector step expected?
target matches?
method allowed?
tool allowed?
arguments match?
budget available?
egress allowed?
state impact allowed?
```

Any mismatch => `DENY`.

## Budget model

```yaml
budget:
  max_operations: 3
  max_duration_seconds: 30
  max_state_changes: 0
  max_external_egress_bytes: 0
  max_bytes_read: 8192
  max_bytes_written: 0
  max_retries: 0
  max_chain_depth: 2
```

## Kill switch

First-class state:

```text
ARMED
TRIGGERED
NOT_TRIGGERED
```

Evidence captures trigger reason, operation, timestamp, and budget snapshot.

## Execution record

Append-only:

```yaml
execution_record:
  plan_digest: ...
  vector_digest: ...
  path_digest: ...
  steps:
    - index: 1
      operation: ...
      decision: ALLOW
      observed: ...
      evidence_ids: [...]
  budget:
    before: ...
    after: ...
  kill_switch:
    state: NOT_TRIGGERED
```

## Validation result

Reuse existing verdicts:

```text
PASS
FAIL
INCONCLUSIVE
ERROR
```

Coverage remains Cycle 006 semantics.

## Graph reclassification

Validation creates a new graph revision; it never mutates historical evidence.

```text
parent_graph_digest
validation_result_digest
new_graph_digest
```

## Safe chaining

No recursive discovery. Every chain step must already be present in the approved plan.

## Synthetic-first progression

```text
SIMULATED
↓
LOCAL_SYNTHETIC
↓
AUTHORIZED_DYNAMIC
```

Lab success never implies dynamic authorization.

## CI

Use deterministic local fixtures only:

```text
invalid ROE -> deny
digest mismatch -> deny
unexpected tool -> deny
argument mutation -> deny
budget exhausted -> stop
egress attempt -> kill
unexpected state change -> kill
valid canary proof -> evidence
```

## Future compatibility

Cycle 010 can consume stable plans, vectors, budgets, results, graph revisions, coverage and benchmark records for continuous revalidation.
