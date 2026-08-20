# task-015 — Build controlled adversarial fixtures

**Cycle:** 009 — Controlled Agentic Adversarial Validation  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective

Implement confused-deputy, tool/argument mutation, tenant-boundary, credential reuse, budget, kill-switch and no-safe-proof scenarios.

## Safety boundary

Cycle 009 may execute only explicitly approved, bounded, minimum-safe-proof validation vectors.

It must never escalate beyond the approved plan because a weaker test failed.

No authorization or ROE:

```text
NO DYNAMIC EXECUTION
```

## DARE execution rule

Do not mark this task complete from code appearance alone.

Capture deterministic evidence for acceptance.

If repository reality contradicts `DESIGN.md`, `BLUEPRINT.md`, or actual post-Cycle-008 contracts, return to Review before changing validation semantics.
