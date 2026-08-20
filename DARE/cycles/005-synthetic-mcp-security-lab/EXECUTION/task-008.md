# task-008 — Implement MRTR authorization-mutation scenario

**Cycle:** 005 — Synthetic MCP Security Lab & Scenario Corpus  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective

Implement MCP-LAB-010.

### Secure
Additional input that changes authorization-relevant semantics triggers re-evaluation/refusal according to the scenario policy.

### Vulnerable
Stale permit is reused after relevant additional input.

### Acceptance
Additional input is deterministic and synthetic; no LLM-generated secret/customer data is required.

## DARE execution rule

Do not mark this task complete from code appearance alone.

Capture deterministic evidence for acceptance.

If implementation reveals an architectural conflict with `DESIGN.md` or `BLUEPRINT.md`, return to Review instead of silently redefining the cycle.
