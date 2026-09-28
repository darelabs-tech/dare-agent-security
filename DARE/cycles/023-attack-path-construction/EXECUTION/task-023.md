# task-023 — Implement the MCP Auth projector (§6.5)

**Status:** DONE  
**Complexity:** MED

## Change

`project/mcp_auth.rs`. From the bound scenario: the expected resource becomes `MCP_SERVER`, the acting principal takes its declared kind, the inbound credential gets principal `USES_CREDENTIAL` and inbound `CAN_REACH` server, the upstream credential (privileged, a target) gets server `USES_CREDENTIAL` and upstream `CAN_REACH` performed resource, and the selected authorization server gets `AUTHORIZED_BY` a `POLICY_DECISION_POINT`. The performed principal gets `CAN_REACH` performed resource, with `authority_mutation` = authorized ≠ performed over principal, tenant and resource. Edges observed by `CREDENTIAL_FLOW_CONTEXT` or `FINAL_OPERATION_BINDING` are also emitted with that trial's evidence. Every guard is RUN scope. A remote run without a bound scenario is counted `McpAuthScenario::not_supplied`.

## Tests (`crates/dare-attack-path/tests/projection_tables.rs`)

`mcp_auth_rows`. Every projected edge is also checked by `all_have_evidence`:
- it carries evidence ids;
- an OBSERVED edge cites evidence records;
- a STATICALLY_PROVEN edge cites `input:<engine>:` ids only;
- it has a locator and an original kind.

The inputs are real engine output (the fixture bundles of tasks 014–016).

## Ralph Loop

Green: fmt, clippy `-D warnings`, `cargo test -p dare-attack-path` (60 tests).
