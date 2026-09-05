# task-024 — Add dedicated Cycle 013 CI security gate

**Status:** READY FOR EXECUTION

## Objective
Add one local-fixture-only Cycle 013 CI gate to the existing PR-open workflow.

## Acceptance
- cover schemas/corpus, paired direct/indirect, benign/hostile fixtures, executable-field refusal, enums, budgets, stop-first-fail, canary/redaction, ambiguous INCONCLUSIVE, replay/local synthetic, remote refusal and baseline regressions;
- do not add push triggers;
- preserve `pull_request: types: [opened]` cost-control policy.
