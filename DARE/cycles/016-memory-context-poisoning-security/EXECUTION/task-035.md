# task-035 — Add CI and offline/confidential regressions

**Status:** APPROVED FOR EXECUTION
**Depends on:** task-025..034

Add `memory-security-2026` to `.github/workflows/ci.yml` while preserving `pull_request: branches: [main], types: [opened]` and no push trigger. Test no live store/provider mode, no network/egress, no secret leakage and regressions for Cycles 013–015. Execute the actual job locally with `scripts/run-ci-job-locally.py`.