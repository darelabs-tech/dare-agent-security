# task-027 — Run complete workspace and compatibility regression

**Status:** READY FOR EXECUTION

## Objective
Run all task-specific and release gates on the completed implementation before opening the PR.

## Required gates
- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo audit`
- dedicated Cycle 013 prompt-injection tests/gate commands locally
- legacy Agentic and MCP profile regressions
- offline/confidential regressions

## Acceptance
All mandatory gates pass locally. Fix failures before opening the PR. Record exact commands/results/head SHA. Because GitHub Actions runs only on PR open, do not open the PR until this task is DONE.
