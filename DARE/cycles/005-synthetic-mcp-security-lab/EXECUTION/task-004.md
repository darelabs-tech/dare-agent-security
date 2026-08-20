# task-004 — Implement passive discovery and authorization-presence scenarios

**Cycle:** 005 — Synthetic MCP Security Lab & Scenario Corpus  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective

Implement MCP-LAB-001 and MCP-LAB-002.

### MCP-LAB-001
Prove passive discovery does not dispatch active operations.

### MCP-LAB-002
Prove authentication alone is not treated as per-operation authorization.

### Variants
Each scenario needs secure and vulnerable targets.

### Acceptance
Secure => expected PASS.
Vulnerable => expected FAIL.

## DARE execution rule

Do not mark this task complete from code appearance alone.

Capture deterministic evidence for acceptance.

If implementation reveals an architectural conflict with `DESIGN.md` or `BLUEPRINT.md`, return to Review instead of silently redefining the cycle.
