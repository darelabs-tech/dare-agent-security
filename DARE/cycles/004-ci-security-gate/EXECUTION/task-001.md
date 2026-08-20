# task-001 — Reconcile post-Cycle-003 `main`

**Cycle:** 004 — CI Security Gate  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective
Inspect the real merged state before implementing any CI integration.

### Required inspection
- Cycle 003 merge/commit and acceptance proof
- Rust workspace members
- CLI package/binary
- available commands and flags
- evidence schema version and serializer
- current discovery and authorization-integrity fixtures
- existing workflows
- Rust toolchain/MSRV
- README/ROADMAP status

### Deliverables
- short reconciliation note in the Cycle 004 working log
- confirmed implementation paths used by later tasks
- list of stale project-status documentation

### Acceptance
- No later task relies on a guessed crate, command, flag, fixture, or path.
- If Cycle 003 is incomplete on `main`, stop and report instead of compensating inside Cycle 004.

## DARE execution rule

Do not mark this task complete from code appearance alone. Capture deterministic evidence for the acceptance statements.

If implementation reveals a security-relevant architectural assumption that contradicts `DESIGN.md` or `BLUEPRINT.md`, stop and return to Review rather than silently changing the architecture.
