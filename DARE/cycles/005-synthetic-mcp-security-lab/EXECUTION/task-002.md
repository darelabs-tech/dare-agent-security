# task-002 — Define scenario manifest and schema

**Cycle:** 005 — Synthetic MCP Security Lab & Scenario Corpus  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective

Create a versioned machine-readable scenario contract.

### Required fields
- schema version
- scenario id/revision
- title/family
- security property
- MCP revision/profile
- secure/vulnerable variants
- expected coverage status
- expected verdict
- safety metadata
- standards mappings

### Tests
- valid manifest
- missing required field
- unknown verdict
- invalid standards status
- unsafe/external-network declaration policy

### Acceptance
The schema is deterministic and suitable for future benchmark/corpus reuse.

## DARE execution rule

Do not mark this task complete from code appearance alone.

Capture deterministic evidence for acceptance.

If implementation reveals an architectural conflict with `DESIGN.md` or `BLUEPRINT.md`, return to Review instead of silently redefining the cycle.
