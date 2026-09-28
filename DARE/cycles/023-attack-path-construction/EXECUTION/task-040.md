# task-040 — Add scenarios APL-013..APL-026 and the class-contract test

**Status:** DONE  
**Complexity:** HIGH

## Scenarios APL-013..026

| Id | Class | Role | Runs | Expected |
|---|---|---|---|---|
| APL-013 | D | attack | static BOM (support-agent without a hash), IDENTITY-LAB-004 | left-pad → support-agent → (declared) assistant → index service → credential FAILED (BOM_COMPLETENESS) |
| APL-014 | D | control | static BOM with every component hashed, IDENTITY-LAB-004 | same path UNDECIDED (the declared edge is never assessed) |
| APL-015 | D | NOT_TESTED | static BOM only | path absent; exit 0 |
| APL-016 | E | attack | MCP-AUTH-LAB-027, IDENTITY-LAB-006 | alice → inbound token → MCP server → upstream credential (→ resource) FAILED (CREDENTIAL_SEPARATION); alice → credential FAILED (PRIVILEGE_AMPLIFICATION) |
| APL-017 | E | control | MCP-AUTH-LAB-026/031/029, IDENTITY-LAB-019 | alice → resource HELD; alice → credential HELD; passthrough path UNDECIDED |
| APL-018 | E | attack | MCP-AUTH-LAB-030, MCP-AUTH-LAB-033, IDENTITY-LAB-019 | FAILED (SELF_REPORTED_METADATA_BOUNDARY); FAILED (FINAL_OPERATION_BINDING) |
| APL-019 | F | attack | PI-LAB-002, multiturn-lab-025 | user channel → assistant → payments transfer FAILED (USER_INPUT_INSTRUCTION_BOUNDARY) |
| APL-020 | F | control | PI-LAB-001, multiturn-lab-025 | same path CONTROLS_HELD |
| APL-021 | F | attack | PI-LAB-001, multiturn-lab-026 | both channels FAILED (CROSS_TURN_CONTINUITY) |
| APL-022 | G | structural | IDENTITY-LAB-001, TOOL-LAB-011 + a declared access under `mallory` | alice → assistant → ticket document DISCONTINUOUS at edge 1; alice → ticket document HELD |
| APL-023 | G | structural | IDENTITY-LAB-004, A2A-LAB-016 + a declared access under the index service | peer and alice paths DISCONTINUOUS at edge 1; the feasible path through the delegation FAILED (DELEGATION_SCOPE_BOUNDARY) |
| APL-024 | H | structural | MEMORY-LAB-008, RAG-LAB-004, no model | two separate `user-7` nodes; no memory → RAG path |
| APL-025 | H | structural | the same runs, with aliases | tenant-B memory → alice → salary document FAILED (TENANT_DOCUMENT_ISOLATION) |
| APL-026 | I | structural | 022 replay capture, IDENTITY-LAB-001 | one `dynamic_authorized` artifact, `MULTI_TURN_RESULT_ONLY` = 1, summary names it |

## Class contract (`attack_path_lab`, after all scenarios)

The contract checks the following:
- the lab holds exactly APL-001..APL-026;
- every chain class (A–F) has an `attack` scenario and a `control` twin;
- every `CONTROL_FAILED` expectation names its failed properties;
- each control twin asserts `no_failed_property` for every property its class's attack
  scenarios fail on;
- every scenario's double run, with the artifacts in reverse order, is byte-identical.

Classes G–I are structural. Each is its own twin, or a single demonstration.

The differences from the Blueprint table are recorded in REGRESSION R-17 (D, E), R-18
(APL-026) and R-19 (APL-022..023).

## Ralph Loop

Green: fmt, clippy `-D warnings --tests`, `attack_path_lab`, which covers 26 scenarios in
about 13 s in debug, and the full CLI test suite. No dependency changed.
