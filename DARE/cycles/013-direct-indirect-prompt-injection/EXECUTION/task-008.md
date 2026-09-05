# task-008 — Implement deterministic invariant evaluator registry

**Status:** READY FOR EXECUTION

## Objective
Implement deterministic evaluators for the approved invariant types.

## Acceptance
- evaluators return PASS/FAIL/INCONCLUSIVE/ERROR from typed facts only;
- exact canary/action/goal/policy/schema invariants supported;
- ambiguous prose-only observations -> INCONCLUSIVE;
- no LLM judge or heuristic-to-FAIL shortcut;
- unit tests cover each evaluator.
