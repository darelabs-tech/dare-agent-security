# task-009 — Build synthetic MCP lab

## Goal
Provide a deterministic, non-customer MCP target for integration, safety and future standards testing.

## Required implementation
- Create `labs/synthetic-mcp` with official MCP SDK primitives.
- Expose synthetic read-only, state-changing, destructive and ambiguous tools.
- Expose resources, one resource template and prompts.
- Provide deterministic pagination for at least one collection.
- Support current-protocol test mode and the selected legacy compatibility mode where feasible.
- Record received MCP method names in a bounded test-only trace.
- No real credentials, customer names, internal endpoints or copied proprietary behavior.

## Required tests
Lab boots deterministically; inventories expected fixture counts; pagination stable; trace records requested methods; fixture data contains no secret canaries.

## Gates
Standard workspace gates.

## DONE
The lab can serve both CLI integration and passive-method proof without external services or sensitive data.