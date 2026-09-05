# task-017 — Implement delegation-chain validation, acyclicity and validity windows

**Status:** APPROVED FOR EXECUTION
**Dependencies:** task-006, task-013, task-014, task-015, task-016

## Objective
Validate delegation graph integrity and bounded authority propagation.

## Acceptance
Loops, duplicate/unknown edges, subject mismatch, scope expansion, expired/not-yet-valid edges and excessive depth fail deterministically.