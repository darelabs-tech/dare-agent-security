# task-033 — Add confidential/offline/no-live-identity regressions and dedicated Cycle 015 CI gate

**Status:** APPROVED FOR EXECUTION
**Dependencies:** task-023..task-032 per DAG

## Objective
Prove offline/confidential behavior and add `identity-security-2026` to the PR-open-only workflow.

## Required gates
Run the actual job with `python scripts/run-ci-job-locally.py .github/workflows/ci.yml identity-security-2026` before PR open.

## Acceptance
Job uses local fixtures only; no push trigger is added; forbidden remote/credential flags and secret persistence are regression-tested.