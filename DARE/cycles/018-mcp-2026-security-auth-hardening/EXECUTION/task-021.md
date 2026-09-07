# task-021 — PRM/resource binding evaluator

**Status:** DONE - REVIEW PASS

Evaluate whether protected-resource metadata and requested resource identity remain bound to the MCP protected resource under test. Do not treat metadata presence alone as authorization.

## Evidence

`invariant::resource_metadata`. Metadata describing another resource is a violation; presence alone is never authorization.
