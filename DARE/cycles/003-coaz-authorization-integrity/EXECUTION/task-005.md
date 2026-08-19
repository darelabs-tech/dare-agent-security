# task-005 — Implement Authorization Projectors and Synthetic Mappings

> Status: **DONE**
> Depends on: task-001, task-003

## Objective

Project MCP operations and trusted context into sanitized AuthZEN-shaped requests without implementing full COAZ/CEL conformance.

## Required interface

Project-owned `AuthorizationProjector` or equivalent with no public SDK runtime types.

## Reference projectors

### Default tools/call projector

Captures method/tool identity equivalent to the COAZ-MCP default `tools/call` authorization shape needed by the vectors.

### Declared rental.quote projector

Uses synthetic mapping-relevant values such as:

```text
customer_id
vehicle_id
daily_rate
agent_id / subject_id as trusted inputs
```

At least `daily_rate` must contribute to the authorization projection so vector 003 tests a genuinely mapped argument.

## Requirements

- mapping identity is explicit;
- missing required projected values returns a deterministic projection error;
- no arbitrary CEL interpreter;
- untrusted and trusted provenance is preserved;
- raw credentials never enter serialized projection artifacts.

## Tests

- default projection fixture;
- declared projection fixture;
- missing mapped value error;
- trust-context projection;
- deterministic repeated projection.

## DONE when

The integrity engine can test both default mapping-selection changes and declared argument-level authorization semantics.
