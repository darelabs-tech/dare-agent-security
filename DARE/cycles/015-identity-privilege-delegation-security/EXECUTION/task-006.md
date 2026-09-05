# task-006 — Define delegation-chain schema and bounded delegation semantics

**Status:** APPROVED FOR EXECUTION
**Dependencies:** task-004, task-005

## Objective
Define versioned ON_BEHALF_OF, AGENT_HANDOFF and SERVICE_DELEGATION edges with subject, ceiling, purpose, audience and validity.

## Acceptance
Unknown principals, loops, duplicate edges, invalid windows, over-depth chains and authority expansion fail closed; no real token material is accepted.