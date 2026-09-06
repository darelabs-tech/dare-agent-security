# task-024 — Token validity and audience/resource evaluators

**Status:** DONE - REVIEW PASS

Evaluate synthetic token-validity evidence plus audience/resource binding. Token presence alone cannot PASS; a valid token for the wrong resource/audience must FAIL when evidence is complete.

## Evidence

`invariant::token_audience` and `token_validity`. A wrong audience fails. Missing validity evidence is INCONCLUSIVE rather than FAIL, unless the deployment accepted the token anyway, which is a decision made on no evidence and a finding in itself.
