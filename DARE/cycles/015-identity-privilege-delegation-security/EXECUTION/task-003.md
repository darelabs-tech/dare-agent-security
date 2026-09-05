# task-003 — Freeze/add Identity Security AGENT.* properties and applicability predicates

**Status:** APPROVED FOR EXECUTION
**Dependencies:** task-001, task-002

## Objective
Add the four approved Identity Security properties without changing existing IDs or semantics.

## Required work
Add `PRINCIPAL_BINDING`, `DELEGATION_SCOPE_BOUNDARY`, `TENANT_RESOURCE_BOUNDARY`, and `AUTHORIZATION_EXECUTION_BINDING`; preserve existing delegation/privilege properties; add only necessary closed predicates.

## Acceptance
Registry changes are additive, `IDENTITY_PRIVILEGE_ABUSE` mapping is correct, unknown predicates fail closed, prior profiles are unchanged.