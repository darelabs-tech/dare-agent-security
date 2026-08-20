# Scenario catalog — Cycle 005

| ID | Title | Secure | Vulnerable | Standards status |
|----|-------|--------|------------|------------------|
| MCP-LAB-001 | Passive discovery boundary | PASS | FAIL | NORMATIVE (MCP) |
| MCP-LAB-002 | Missing per-tool authorization | PASS | FAIL | INFORMATIVE |
| MCP-LAB-003 | Confused deputy | PASS | FAIL | INFORMATIVE (CWE-441) |
| MCP-LAB-004 | Tool name mutation after PERMIT | PASS | FAIL | DRAFT_OR_OPEN_PROPOSAL |
| MCP-LAB-005 | Argument mutation after PERMIT | PASS | FAIL | DRAFT_OR_OPEN_PROPOSAL |
| MCP-LAB-006 | Trusted-context mutation | PASS | FAIL | DRAFT_OR_OPEN_PROPOSAL |
| MCP-LAB-007 | Header/body semantic divergence | PASS | FAIL | INFORMATIVE |
| MCP-LAB-008 | Authorization issuer validation failure | PASS | FAIL | INFORMATIVE |
| MCP-LAB-009 | Credential issuer reuse | PASS | FAIL | INFORMATIVE |
| MCP-LAB-010 | MRTR authorization mutation | PASS | FAIL | DRAFT_OR_OPEN_PROPOSAL |

Manifests: `labs/scenarios/*/scenario.json`  
Schema: `schemas/lab/v1/scenario.schema.json`

## Contributing a scenario

1. Add `labs/scenarios/MCP-LAB-NNN/scenario.json` conforming to the schema.
2. Keep `safety.external_network`, `real_credentials`, and `destructive` false.
3. Provide secure => PASS and vulnerable => FAIL expectations.
4. Prefer reusing existing DARE engines (`discover`, `validate coaz-integrity`) when the property maps.
5. Add a matrix test under `crates/dare-mcp-lab/tests/`.
