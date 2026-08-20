# task-008 — Add Action E2E workflow matrix

**Cycle:** 004 — CI Security Gate  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective
Test the Action as GitHub Actions will execute it.

### Required
- repository-local `uses: ./`
- PASS assertion
- expected FAIL assertion
- ERROR assertion
- INCONCLUSIVE policy assertion
- evidence-file assertion
- GitHub-output assertion

### Safety
No customer target. No internet dependency for MCP test behavior.

### Acceptance
The workflow distinguishes expected security failure from infrastructure/test failure.

## DARE execution rule

Do not mark this task complete from code appearance alone. Capture deterministic evidence for the acceptance statements.

If implementation reveals a security-relevant architectural assumption that contradicts `DESIGN.md` or `BLUEPRINT.md`, stop and return to Review rather than silently changing the architecture.
