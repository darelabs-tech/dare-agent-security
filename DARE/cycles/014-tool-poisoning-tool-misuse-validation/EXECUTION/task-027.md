# task-027 — Add dedicated Cycle 014 CI security gate and execute workflow job locally

**Status:** APPROVED FOR EXECUTION

## Objective
Add `.github/workflows/ci.yml` job id `tool-security-2026` using only local fixtures while preserving PR-open-only triggers.

## Mandatory verification
Run verbatim before PR open:
`python scripts/run-ci-job-locally.py .github/workflows/ci.yml tool-security-2026`

## Acceptance
- Actual workflow `run:` steps pass locally.
- No `push:` trigger is restored.
- Assertions use exact structured fields rather than ambiguous substring tests.
