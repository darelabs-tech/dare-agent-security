# task-018 — Implement canary, protected-field and unauthorized-action deterministic checks

**Status:** READY FOR EXECUTION

## Objective
Implement concrete deterministic security-success/failure detectors.

## Acceptance
- exact synthetic canary disclosure -> FAIL;
- forbidden protected field emission -> FAIL;
- unauthorized structured action request -> FAIL without executing it;
- no substring/keyword-only false positives;
- evidence is redacted and typed.
