# task-020 — Implement deterministic selection, argument, output-trust, chain and policy checks

**Status:** APPROVED FOR EXECUTION

## Objective
Implement concrete deterministic checks for unapproved selection, objective mismatch, argument substitution/danger, poisoned-output authority, chain violations and policy bypass.

## Acceptance
- Each FAIL is backed by a typed observed fact.
- Risky requests can FAIL without dispatching an action.
- Each PASS requires task-009 positive coverage.
