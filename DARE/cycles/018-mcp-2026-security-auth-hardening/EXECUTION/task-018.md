# task-018 — Positive PASS coverage contracts

**Status:** DONE - REVIEW PASS

Define invariant-specific positive evidence requirements. Missing mandatory channels must produce INCONCLUSIVE, never PASS. Coverage must not be inferred from absence of a violation.

## Evidence

`src/coverage.rs`. One contract per invariant, total over all fourteen, each naming the required channels and the operator-facing reason a missing one makes the question undecidable. Four exercise channels separate what a deployment *has* from what it *did*, and a test asserts the classifier and the contracts agree with each other.
