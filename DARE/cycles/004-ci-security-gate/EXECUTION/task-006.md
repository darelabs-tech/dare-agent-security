# task-006 — Integrate evidence, outputs, and job summary

**Cycle:** 004 — CI Security Gate  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective
Connect CLI evidence to GitHub-native output surfaces.

### Outputs
- verdict
- evidence path
- summary path

### Summary
Include version, mode, safe/redacted target identity, protocol revision when known, verdict counts, aggregate verdict, evidence path, and NOT TESTED limitations.

### Security
Never include raw request bodies, credentials, or secret-bearing context in outputs or job summary.

### Acceptance
Summary and output values are derived from machine evidence and survive Action execution.

## DARE execution rule

Do not mark this task complete from code appearance alone. Capture deterministic evidence for the acceptance statements.

If implementation reveals a security-relevant architectural assumption that contradicts `DESIGN.md` or `BLUEPRINT.md`, stop and return to Review rather than silently changing the architecture.
