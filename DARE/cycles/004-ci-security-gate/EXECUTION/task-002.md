# task-002 — Define deterministic CI result contract

**Cycle:** 004 — CI Security Gate  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective
Create the contract between existing evidence and GitHub Actions.

### Decide
- Action modes actually supported
- aggregate precedence
- `INCONCLUSIVE` default behavior
- no-evidence behavior
- exit semantics
- output directory
- GitHub outputs

### Constraints
- Reuse Cycle 001 verdict vocabulary.
- Do not parse prose.
- Do not silently map `INCONCLUSIVE` to `PASS`.
- Preserve backwards-compatible CLI behavior where possible.

### Acceptance
Contract tests cover PASS, FAIL, INCONCLUSIVE, ERROR, mixed evidence, no evidence, and malformed result.

## DARE execution rule

Do not mark this task complete from code appearance alone. Capture deterministic evidence for the acceptance statements.

If implementation reveals a security-relevant architectural assumption that contradicts `DESIGN.md` or `BLUEPRINT.md`, stop and return to Review rather than silently changing the architecture.
