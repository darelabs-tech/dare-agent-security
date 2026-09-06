# task-046 — Dedicated CI job and real local workflow execution

**Status:** APPROVED FOR EXECUTION

Add `mcp-auth-security-2026` to the existing PR-open-only CI workflow. Before opening the PR, execute the real YAML job locally with `scripts/run-ci-job-locally.py`; also run fmt, clippy, workspace tests, audit and required regressions.