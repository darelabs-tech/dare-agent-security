# task-013 — Self-reported MCP identity metadata schema

**Status:** DONE - REVIEW PASS

Model `clientInfo`, `serverInfo` and related MCP self-description as metadata evidence, not authenticated principal identity. Reuse Cycle 015 identity semantics for actual authority.

## Evidence

`src/identity.rs`. `SelfReportedMetadata::trust()` is a method rather than a field, so a fixture cannot declare its own clientInfo authenticated. Two independent failure paths: the deployment stating it derived the principal from self-report, and an acting principal whose own trust class is self-reported. `PrincipalKind` is re-exported from Cycle 015, never redefined.
