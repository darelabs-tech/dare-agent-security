# task-010 — Integrate full corpus with Cycle 004 CI gate

**Cycle:** 005 — Synthetic MCP Security Lab & Scenario Corpus  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective

Run the scenario corpus through the existing CI security gate.

### Required
- secure matrix
- vulnerable matrix
- repeatability
- evidence persistence
- no customer/external target
- deterministic expected-failure handling

### Acceptance
CI proves the engine detects known-bad fixtures without treating intentional FAIL verdicts as infrastructure failures.

## DARE execution rule

Do not mark this task complete from code appearance alone.

Capture deterministic evidence for acceptance.

If implementation reveals an architectural conflict with `DESIGN.md` or `BLUEPRINT.md`, return to Review instead of silently redefining the cycle.
