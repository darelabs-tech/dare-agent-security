# task-003 — Build shared synthetic lab framework

**Cycle:** 005 — Synthetic MCP Security Lab & Scenario Corpus  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective

Create reusable synthetic infrastructure.

### Include
- local identities
- local synthetic credentials
- policy fixtures
- temporary state
- deterministic startup/teardown
- no external network
- stable target addressing

### Acceptance
A fixture can run repeatedly without cross-test state leakage.

## DARE execution rule

Do not mark this task complete from code appearance alone.

Capture deterministic evidence for acceptance.

If implementation reveals an architectural conflict with `DESIGN.md` or `BLUEPRINT.md`, return to Review instead of silently redefining the cycle.
