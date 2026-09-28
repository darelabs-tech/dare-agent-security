# task-019 — Implement the tool projector (§6.1)

**Status:** DONE  
**Complexity:** MED

## Change

`project/tool.rs`. The tool surface becomes an `MCP_SERVER` node, with server `CAN_REACH` tool and SUT `CAN_INVOKE` tool from the pinned scenario (STATICALLY_PROVEN). `ToolRequested` becomes SUT `CALLS` tool (OBSERVED, REGRESSION R-4). `ToolOutputObserved` produces the `output.<tool>` DATA node, tool `TRANSFERS_TO` output, and output `TRANSFERS_TO` SUT. The output is an `EXTERNAL_CONTENT` entry unless the surface is TRUSTED. DELETE, PAYMENT, PRIVILEGE_CHANGE or `destructive_hint` mark a tool `destructive` and make it a `DESTRUCTIVE_CAPABILITY` target. SEND makes a tool an `EXTERNAL_PUBLICATION` target. HIGH sensitivity marks it `sensitive`. `ToolViolation.tool_id` narrows a FAIL. Every other event kind is counted.

## Tests (`crates/dare-attack-path/tests/projection_tables.rs`)

`tool_rows`, `tool_security_flags_follow_the_declared_operation_class`. Every projected edge is also checked by `all_have_evidence`:
- it carries evidence ids;
- an OBSERVED edge cites evidence records;
- a STATICALLY_PROVEN edge cites `input:<engine>:` ids only;
- it has a locator and an original kind.

The inputs are real engine output (the fixture bundles of tasks 014–016).

## Ralph Loop

Green: fmt, clippy `-D warnings`, `cargo test -p dare-attack-path` (60 tests).
