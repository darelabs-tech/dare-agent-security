# task-003 — Create `dare-multi-turn-security` crate skeleton and no-network manifest test

**Status:** DONE  
**Complexity:** LOW

## Files changed

- `Cargo.toml`: workspace member added
- `crates/dare-multi-turn-security/Cargo.toml`: path deps on `dare-adversarial`, `dare-coverage` and `dare-security-evidence`, plus workspace serde, serde_json, sha2 and time, and thiserror 2.0
- `crates/dare-multi-turn-security/src/lib.rs`: crate rules (closed adaptivity), boundaries and manifest tests
- `crates/dare-multi-turn-security/src/error.rs`: `MultiTurnError` with every Blueprint variant, plus `BoundZero` (see below)

## Tests

- `tests::this_crate_declares_no_network_or_generation_dependency` checks 24 forbidden crates (HTTP, TLS, RNG, model clients, process spawners).
- `tests::the_check_catches_a_forbidden_dependency_when_one_is_added` proves the check **fails** when `rand`, `reqwest` or `async-openai` is appended to the manifest. This demonstrates the second half of the DONE criterion without committing a bad manifest.
- `tests::the_manifest_check_actually_sees_dependencies` guards against a vacuous pass.
- `error::tests::no_error_message_reads_as_a_verdict` and `document_problems_are_refusals_and_run_problems_are_not`.

## Deviation recorded

The Blueprint names only `BoundRaised`. A bound of `0` is not a raise, and reporting it as one would be a misleading message. `BoundZero` was added, so `is_refusal()` covers it. This does not change semantics: both are refusals with exit code 3.

## Ralph Loop

- Build: `cargo build --workspace` green
- Test: `cargo test --workspace`: 266 suites, 3 781 passed, 0 failed (baseline 3 767 + 14 new)
- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Audit: `cargo audit` clean. No external dependency was added; `Cargo.lock` gains only the new workspace member.
