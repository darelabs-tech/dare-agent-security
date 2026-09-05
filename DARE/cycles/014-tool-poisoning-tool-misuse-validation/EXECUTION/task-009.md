# task-009 — Define invariant-specific positive PASS coverage contracts

**Status:** APPROVED FOR EXECUTION

## Objective
Define the exact positive observation channel required before each invariant may return PASS.

## Required work
Map every approved invariant to its required evidence channel(s). Absence of the channel must produce `INCONCLUSIVE`.

## Acceptance
- Every invariant has an explicit coverage predicate.
- Prose-only/no-observation cases never become PASS.
- Regression tests encode the Cycle 013 lesson: absence of evidence is not evidence of absence.
