# task-009 — Build scenario runner and evidence assertions

**Cycle:** 005 — Synthetic MCP Security Lab & Scenario Corpus  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective

Build a thin orchestrator.

### Flow
manifest -> start variant -> invoke real DARE engine -> read evidence -> assert expected -> teardown

### Important semantics
Security FAIL can produce Scenario PASS when FAIL is the expected outcome.

### Acceptance
Runner contains no duplicate MCP/authz security engine logic.

## DARE execution rule

Do not mark this task complete from code appearance alone.

Capture deterministic evidence for acceptance.

If implementation reveals an architectural conflict with `DESIGN.md` or `BLUEPRINT.md`, return to Review instead of silently redefining the cycle.
