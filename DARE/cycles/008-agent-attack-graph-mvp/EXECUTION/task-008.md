# task-008 — Implement deterministic Graph Builder

**Cycle:** 008 — Agent Attack Graph MVP  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective

Build canonical nodes/edges from normalized facts. Identical inputs must produce identical graph output/digest.

## Safety boundary

Cycle 008 derives and analyzes paths.

It must not autonomously execute exploit chains or perform state-changing third-party tests.

Controlled adversarial execution belongs to Cycle 009 and remains explicitly authorization/ROE gated.

## DARE execution rule

Do not mark this task complete from code appearance alone.

Capture deterministic evidence for acceptance.

If repository reality contradicts `DESIGN.md`, `BLUEPRINT.md`, or actual post-Cycle-007 contracts, return to Review before changing graph semantics.
