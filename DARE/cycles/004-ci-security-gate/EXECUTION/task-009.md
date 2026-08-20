# task-009 — Security hardening and hostile-input tests

**Cycle:** 004 — CI Security Gate  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective
Adversarially test the adapter surface itself.

### Inputs
- shell metacharacters
- whitespace/newlines
- traversal paths
- Markdown/control characters
- unknown mode
- unsupported revisions
- secret-like values
- redirect target attempts

### Required invariants
- inputs remain data
- output stays within workspace
- no tool invocation becomes active by accident
- no secret-like fixture reaches public summary/output
- no scope expansion

### Acceptance
Negative tests fail closed and do not execute injected content.

## DARE execution rule

Do not mark this task complete from code appearance alone. Capture deterministic evidence for the acceptance statements.

If implementation reveals a security-relevant architectural assumption that contradicts `DESIGN.md` or `BLUEPRINT.md`, stop and return to Review rather than silently changing the architecture.
