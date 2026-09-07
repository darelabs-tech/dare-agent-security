# task-020 — Protocol revision and header/body binding evaluators

**Status:** DONE - REVIEW PASS

Evaluate supported MCP revision and `Mcp-Method`/`Mcp-Name` ↔ JSON-RPC method/name semantic binding. Unsupported, contradictory or ambiguous current/legacy semantics fail closed or become typed refusal as designed.

## Evidence

`invariant::protocol_revision`, `method_binding`, `name_binding`. Unsupported revisions fail closed. PASS and FAIL directions both covered by tests in `simulated.rs` and `invariant.rs`.
