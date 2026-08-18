# task-012 — Documentation, CI compatibility matrix and final proof

## Goal
Close Cycle 002 with reproducible documentation and acceptance evidence, not merely implemented code.

## Required implementation
- Update root README with `discover` quick start and safety boundary.
- Add discovery crate README.
- Document Inventory v1 versioning and schema path.
- Document passive allowlist/refusal policy.
- Document synthetic lab startup/use.
- Publish supported MCP compatibility matrix including current `2026-07-28` and the tested legacy revision.
- Extend CI for inventory fixtures, integration matrix, secret canaries and passive method trace.
- Produce a cycle verification report mapping every DESIGN acceptance criterion to concrete files/tests/results.

## Final gates
```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Also prove: offline schema validation; JSON stdout purity; no secret canary leakage; passive trace subset invariant; Cycle 001 tests remain green.

## DONE
Every Cycle 002 acceptance criterion is explicitly PASS with reproducible evidence, or the cycle remains incomplete.