# task-021 — Implement bounded trial ledger and budgets

**Status:** APPROVED FOR EXECUTION
**Depends on:** task-008, task-009, task-013

Implement approved hard limits for trials, items, stores, events, recalls, writes, output bytes and duration. Totals must not reset to bypass run limits; over-bound input is refused, never silently increased.