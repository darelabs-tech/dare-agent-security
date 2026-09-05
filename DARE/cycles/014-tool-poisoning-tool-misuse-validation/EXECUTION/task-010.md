# task-010 — Implement deterministic Tool Security invariant evaluator registry

**Status:** APPROVED FOR EXECUTION

## Objective
Implement the ten approved deterministic invariants over normalized events plus objective/policy context.

## Acceptance
- No LLM/heuristic/fuzzy judge participates in final verdicts.
- `FAIL`, `PASS`, `INCONCLUSIVE`, `ERROR` follow typed evidence and coverage rules.
- Unknown invariant values fail closed.
- Evaluators are unit-tested independently.
