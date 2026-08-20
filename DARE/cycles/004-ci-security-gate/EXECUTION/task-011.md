# task-011 — Final DARE proof and release-candidate handoff

**Cycle:** 004 — CI Security Gate  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective
Create the final completion proof.

### Map each acceptance criterion to
- implementation file
- test
- command/workflow
- observed result

### Re-run
- Rust tests
- schema/evidence contract tests
- Action E2E
- hostile-input tests
- secret/redaction checks
- documentation consistency checks

### Acceptance
No unresolved mandatory criterion remains. Implementation completion does not create/move a release tag and does not publish Marketplace metadata.

## DARE execution rule

Do not mark this task complete from code appearance alone. Capture deterministic evidence for the acceptance statements.

If implementation reveals a security-relevant architectural assumption that contradicts `DESIGN.md` or `BLUEPRINT.md`, stop and return to Review rather than silently changing the architecture.
