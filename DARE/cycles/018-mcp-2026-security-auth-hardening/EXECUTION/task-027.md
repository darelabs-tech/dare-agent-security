# task-027 — Scope step-up and retry-bound evaluator

**Status:** DONE - REVIEW PASS

Evaluate insufficient-scope challenge behavior, effective scope union/preservation and bounded retries. Step-up must not silently remove previously required scopes or create an unbounded retry loop.

## Evidence

`invariant::scope_step_up`. Dropped scopes are named in the finding; the retry ceiling is enforced separately.
