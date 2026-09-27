# task-034 — Add determinism and compatibility tests (including embedded-asset locations)

**Status:** DONE  
**Complexity:** MED

## Files changed

- `crates/dare-multi-turn-security/tests/determinism.rs` (new)
- `crates/dare-multi-turn-security/tests/compatibility.rs` (new)

## Result

**Determinism:** every non-refusal corpus entry in every staged mode (at least 40
pairs) runs **10 times**, and every artifact is compared byte for byte. Refusal messages
are identical across 10 runs.

**Compatibility:**
- `every_pre_existing_registry_entry_is_byte_for_byte_unchanged`: the digest of the first 58 registry entries equals the digest computed from `git show 4ca06b2:…/registry.json`. Python's canonical JSON and serde_json's agree, which is itself checked by the test passing.
- `every_earlier_profile_is_unchanged`: 10 baseline profile digests.
- `this_crate_takes_no_single_turn_engine_as_a_dependency`: none of the 8 Cycle 013–020 engine crates is a dependency.
- `embedded_assets_live_in_docker_copied_dirs`: every `include_str!` in `src/` and `tests/` resolves under a directory the root `Dockerfile` copies (Blueprint AD-10).
- `the_ci_trigger_is_still_pull_request_opened_only`.

The Cycle 013/016/020 lab suites run unchanged as part of `cargo test --workspace`: 3955 passed, 0 failed.

## Environment note

The session's writable disk filled up while running the workspace tests, which made
command output fail with `ENOSPC`. Deleting `target/debug/incremental` and pruning
Docker's build cache freed 11 GB, and the suite was re-run clean.

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 3955 passed, 0 failed
- CI job: `python scripts/run-ci-job-locally.py .github/workflows/ci.yml multi-turn-security-2026`: **all 12 steps PASSED**
- Audit: no external dependency change (`dare-multi-turn-security` added as a path dependency of the CLI)
