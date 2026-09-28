# task-041 — Record the remote-validation standards provenance snapshot

**Status:** DONE  
**Complexity:** LOW

## Files changed

- `standards/remote-validation/2026/provenance.json` (new)

## Result

It pins A2A 1.0.0 and the Agent Card 1.0.0 (from Cycle 020), MCP 2026-07-28 and MCP
Authorization 2026-07-28 (from Cycle 018), RFC 9728, RFC 8414, RFC 6750 and the internal
`dare-conversation` v1 contract. For each one it names the client methods that use it.

## Recorded deviation

No upstream re-verification was possible here. The repository's only "realistic" Agent
Card example (`dare-a2a-security/src/schema.rs:431`) uses the 0.3-era shape (`url`,
`preferredTransport`, `additionalInterfaces`), while the pinned version is 1.0.0. The
A2A client (task-024) and the card projection (task-029) therefore accept both
documented interface shapes, and select JSON-RPC method names from the card's declared
`protocolVersion`. This refines BLUEPRINT §5.4/§6.1 and is recorded in REGRESSION.md.

## Verification

`python3 -m json.tool standards/remote-validation/2026/provenance.json` is valid.
