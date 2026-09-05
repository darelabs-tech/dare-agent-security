# task-004 — Define PromptInjectionScenario schema

**Status:** READY FOR EXECUTION

## Objective
Define a versioned, closed PromptInjectionScenario contract.

## Acceptance
- typed fields for family/property/source/objective/vector/invariant/trials/safety;
- deny unknown fields;
- no shell/script/eval/callback/arbitrary executable fields;
- invalid/oversized/out-of-range inputs fail closed;
- positive and negative schema tests exist.
