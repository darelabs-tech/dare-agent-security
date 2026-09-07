# task-023 — Authorization-response issuer evaluator

**Status:** DONE - REVIEW PASS

Evaluate authorization-response issuer correlation against the approved authorization request/server evidence. A response from another issuer must not be accepted solely because the response is otherwise well formed.

## Evidence

`invariant::response_issuer`. The mix-up is recorded whether or not the client accepted it: observing an attempt and being fooled by one are different facts, and the detail field says which happened.
