# task-005 — Implement the thin GitHub Action adapter

**Cycle:** 004 — CI Security Gate  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective
Create the Action adapter.

### Requirements
- explicit bounded `mode`
- explicit `target` where required
- workspace-contained output
- safe argument quoting
- no `eval`
- no `sh -c` using action inputs
- no arbitrary CLI passthrough
- no GitHub write token requirement

### Acceptance
The adapter invokes existing CLI behavior and contains no MCP discovery/authorization/security business logic.

## DARE execution rule

Do not mark this task complete from code appearance alone. Capture deterministic evidence for the acceptance statements.

If implementation reveals a security-relevant architectural assumption that contradicts `DESIGN.md` or `BLUEPRINT.md`, stop and return to Review rather than silently changing the architecture.
