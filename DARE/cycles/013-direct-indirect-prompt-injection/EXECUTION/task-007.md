# task-007 — Define normalized observation-event model

**Status:** READY FOR EXECUTION

## Objective
Represent security-relevant observations using closed typed events.

## Acceptance
- support MODEL_OUTPUT, STRUCTURED_ACTION_REQUEST, GOAL_STATE, POLICY_DECISION, CANARY_DISCLOSURE, PROTECTED_FIELD_EMISSION, HARNESS_ERROR;
- raw prose cannot itself encode a verdict;
- secret/redaction handling is explicit;
- malformed events fail closed.
