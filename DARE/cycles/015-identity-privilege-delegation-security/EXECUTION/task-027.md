# task-027 — Add hostile parser/schema/credential-smuggling fixtures and refusal tests

**Status:** APPROVED FOR EXECUTION
**Dependencies:** task-010, task-011, task-012, task-019

## Objective
Attack the validator's input boundary with unknown fields, executable fields, token/secret smuggling, path traversal, hostile Unicode, over-bounds and expected-verdict data.

## Acceptance
Every hostile fixture deterministically refuses/errors closed and never persists raw credential-shaped content.