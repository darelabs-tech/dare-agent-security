# task-011 — Add hostile-fixture and isolation tests

**Cycle:** 005 — Synthetic MCP Security Lab & Scenario Corpus  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective

Threat-model the lab.

### Test
- malformed manifest
- path traversal
- malicious metadata
- state leakage
- teardown failure
- accidental external network
- secret-like fixture strings
- ordering dependency

### Acceptance
The lab itself does not become an unsafe execution surface.

## DARE execution rule

Do not mark this task complete from code appearance alone.

Capture deterministic evidence for acceptance.

If implementation reveals an architectural conflict with `DESIGN.md` or `BLUEPRINT.md`, return to Review instead of silently redefining the cycle.
