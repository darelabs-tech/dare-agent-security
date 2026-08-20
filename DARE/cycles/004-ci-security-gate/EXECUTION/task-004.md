# task-004 — Make the CLI CI-safe and non-interactive

**Cycle:** 004 — CI Security Gate  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective
Adapt only the minimum CLI surface needed for automation.

### Required properties
- no prompts
- explicit output location
- machine-readable aggregate result
- deterministic exits
- stable stderr/stdout responsibilities
- no GitHub-specific domain logic

### Acceptance
CLI can run headlessly in a clean process and all outcome classes are testable.

## DARE execution rule

Do not mark this task complete from code appearance alone. Capture deterministic evidence for the acceptance statements.

If implementation reveals a security-relevant architectural assumption that contradicts `DESIGN.md` or `BLUEPRINT.md`, stop and return to Review rather than silently changing the architecture.
