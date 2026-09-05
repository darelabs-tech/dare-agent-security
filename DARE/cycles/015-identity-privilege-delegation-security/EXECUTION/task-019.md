# task-019 — Implement bounded trials, principal/delegation/operation counts and depth limits

**Status:** APPROVED FOR EXECUTION
**Dependencies:** task-010, task-012, task-015..task-018 per DAG

## Objective
Enforce all approved hard bounds across the full run.

## Acceptance
Limits cannot be raised by scenario input; run-wide counters do not reset across trials; over-limit inputs refuse; state changes and egress remain zero.