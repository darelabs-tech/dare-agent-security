# task-026 — Redirect/state evaluator

**Status:** DONE - REVIEW PASS

Evaluate redirect URI integrity and state correlation against the approved flow evidence. Mismatched or substituted redirect/state values must not be normalized away.

## Evidence

`invariant::redirect_state`. Three independent checks, each contributing its own violation.
