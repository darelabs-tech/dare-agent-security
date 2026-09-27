# task-033 — Add `multi-turn-security-2026` CI job

**Status:** DONE  
**Complexity:** LOW

## Files changed

- `.github/workflows/ci.yml`: new job `multi-turn-security-2026` (12 steps), placed before `docs-build`; the trigger (`pull_request: types: [opened]`) is unchanged
- `scripts/k21/assert_no_real_credentials.py` (new): Cycle 021 file lists, with the rules of the Cycle 020 script, including its brace-tracking skip of `#[cfg(test)]` modules, plus model-provider endpoints
- `crates/dare-multi-turn-security/tests/hostile_refusal.rs`: credential-shaped test strings are now assembled at run time

## Result

The job runs:
- engine unit tests;
- the lab harness contract with replay equivalence;
- the hostile corpus;
- determinism and compatibility (added in task-034);
- the multi-turn properties and profile;
- the Cycle 015/016 family tests;
- the CLI flag surface;
- the credential sweep;
- three offline CLI runs: a PASS control, a local-synthetic FAIL with exit 2, and a refused cyclic graph with exit 3 that writes nothing. The JSON assertions use `scripts/assert-json.py`.

## Finding

The first run of the new credential sweep failed on
`tests/hostile_refusal.rs`: the refusal test wrote `sk-live-…`, `-----BEGIN PRIVATE KEY-----`
and `Bearer …` literally. Those strings are now built with `format!` at run time. The
test still refuses them, and the source carries no credential shape.

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 3955 passed, 0 failed
- CI job: `python scripts/run-ci-job-locally.py .github/workflows/ci.yml multi-turn-security-2026`: **all 12 steps PASSED**
- Audit: no external dependency change (`dare-multi-turn-security` added as a path dependency of the CLI)
