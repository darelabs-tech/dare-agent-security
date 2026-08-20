# task-005 — Implement confused-deputy scenario

**Cycle:** 005 — Synthetic MCP Security Lab & Scenario Corpus  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective

Implement MCP-LAB-003.

### Model
- human principal
- agent identity
- service/deputy identity
- privileged downstream operation

### Secure
Authority remains bound to requester/action.

### Vulnerable
Privileged deputy identity performs operation without correct binding.

### Acceptance
The DARE engine distinguishes both deterministically.

## DARE execution rule

Do not mark this task complete from code appearance alone.

Capture deterministic evidence for acceptance.

If implementation reveals an architectural conflict with `DESIGN.md` or `BLUEPRINT.md`, return to Review instead of silently redefining the cycle.
