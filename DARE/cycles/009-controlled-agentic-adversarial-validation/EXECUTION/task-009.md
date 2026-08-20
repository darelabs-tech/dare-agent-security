# task-009 — Implement runtime policy enforcement

**Cycle:** 009 — Controlled Agentic Adversarial Validation  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective

Check every vector step against the immutable approved plan, ROE, target, method, tool, arguments, scope and safety class.

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
