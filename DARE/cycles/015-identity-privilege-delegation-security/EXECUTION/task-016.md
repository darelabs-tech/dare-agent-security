# task-016 — Implement authority subset/ceiling comparison

**Status:** APPROVED FOR EXECUTION
**Dependencies:** task-005, task-013, task-014, task-015

## Objective
Deterministically prove whether effective authority is a subset of the authorized/delegated ceiling.

## Acceptance
Action/resource/tenant/scope/purpose/audience constraints cannot silently widen; broader runtime/service credentials do not expand authority.