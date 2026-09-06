# task-004 — Protocol/request/header/body schemas

**Status:** DONE - REVIEW PASS

Define bounded typed schemas for protocol revision, request identity, JSON-RPC method/name and modern MCP header evidence. Unknown executable or verdict-bearing fields fail closed.

## Evidence

`crates/dare-mcp-auth-security/src/protocol.rs` plus `schemas/mcp-auth-security/v1/scenario.schema.json`.

`ProtocolContext`, `McpHeaderProjection`, `JsonRpcOperation`, `RequestEnvelope`. The revision is *classified* against the Cycle 002 constants rather than compared to a literal, so this crate cannot disagree with Cycle 002 about what current means. Routing and body are compared on normalized semantics — casing and padding ignored, separators never — and a header naming an operation the body did not is a mismatch rather than nothing to compare. `SyntheticUri` refuses anything scheme-shaped, on deserialize as well as on construction.
