# task-028 — Implement independent multi-violation capture and credential/redaction hygiene

**Status:** APPROVED FOR EXECUTION
**Dependencies:** task-013, task-015, task-023..task-027 per DAG

## Objective
Preserve all independently observed principal/tenant/privilege/binding violations and sanitize evidence before persistence.

## Acceptance
No first-match masking; stop-on-first-fail only stops later trials; current-trial violations survive; secrets/canaries/tokens are redacted everywhere.