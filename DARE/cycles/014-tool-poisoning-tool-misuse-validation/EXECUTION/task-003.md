# task-003 — Freeze/add Tool Security AGENT.* properties and applicability predicates

**Status:** APPROVED FOR EXECUTION

## Objective
Preserve existing Tool Security properties and add the approved specialized properties/predicates additively.

## Required work
- Preserve unchanged: `AGENT.TOOL.AUTHORIZATION_BOUNDARY`, `AGENT.TOOL.OUTPUT_TRUST_BOUNDARY`.
- Add: `AGENT.TOOL.METADATA_TRUST_BOUNDARY`, `AGENT.TOOL.SELECTION_INTENT_BINDING`, `AGENT.TOOL.ARGUMENT_INTEGRITY`, `AGENT.TOOL.CHAIN_BOUNDARY`.
- Map new properties to `TOOL_MISUSE_EXPLOITATION` / `TOOL_SECURITY`.
- Add only closed typed predicates needed for applicability.

## Acceptance
- Existing Cycle 012 property semantics are regression-pinned.
- Unknown property/predicate values fail closed.
- Registry remains unique, valid and additive.
