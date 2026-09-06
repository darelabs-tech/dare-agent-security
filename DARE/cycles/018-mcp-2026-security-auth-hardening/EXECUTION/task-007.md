# task-007 — Authorization request/response correlation schemas

**Status:** DONE - REVIEW PASS

Model bounded authorization request/response correlation, including resource, issuer, state and final MCP operation references required by the approved invariants. Correlation evidence must be canonical and deterministic.

## Evidence

`src/authorization.rs`. Request and response correlation on three independent axes — issuer, state, redirect — each answering None when there is nothing to compare. A state that vanishes *or* appears breaks correlation. There is deliberately no authorization-code field: a code is a bearer secret, and every question is answerable from correlation values alone.
