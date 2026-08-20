# Cycle 004 — Proof

**Cycle:** CI Security Gate  
**Branch:** `agent/cycle-004-ci-security-gate`  
**Status:** IMPLEMENTED (pre-release — no Marketplace / stable v1 claim)

Maps Design acceptance criteria to deterministic evidence.

| # | Criterion | Evidence |
|---|-----------|----------|
| 1 | Post-Cycle-003 CLI contract documented | `DARE/cycles/004-ci-security-gate/IMPLEMENTATION-NOTES.md`, `docs/ci-result-contract.md` |
| 2 | Action succeeds on secure synthetic fixture | `.github/workflows/action-e2e.yml` matrix `secure-pass`; `fixtures/ci/matrix.json` |
| 3 | Action fails on intentionally failing fixture | workflow matrix `fail-stale-permit`; `tests/cli_ci_automation.rs` |
| 4 | Same evidence schema inside and outside CI | `schemas/evidence/v1/evidence.schema.json`; evidence under `{output_dir}/evidence/` |
| 5 | PASS/FAIL/INCONCLUSIVE/ERROR aggregation tested | `tests/ci_result_contract.rs`; workflow matrix + `action-error` job |
| 6 | Evidence at stable workspace path | `--output-dir` default `.dare-agent-security`; `crates/dare-agent-security-cli/src/ci_output.rs` |
| 7 | Outputs expose verdict and evidence location | `github-output.env`; `action.yml` outputs; `tests/ci_github_outputs.rs` |
| 8 | Job summary without secrets | `summary.md` generation + canary guard; `tests/hostile_input.rs` |
| 9 | Shell metacharacters treated as data | `tests/hostile_input.rs`; `action/entrypoint.sh` (no eval) |
| 10 | Default mode not active/state-changing | `discover` list-only policy unchanged; validate uses offline vectors |
| 11 | Minimum permissions example | `docs/ci-gate.md`; workflows `permissions: contents: read` |
| 12 | E2E needs no customer target | `fixtures/ci/README.md`; synthetic-mcp + built-in vectors only |
| 13 | Public docs reconciled | `README.md`, `docs/ci-gate.md` |
| 14 | No stable release claim | docs explicitly pre-release; no Marketplace metadata |

## Ralph Loop (final)

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Invariants confirmed

- No approval bypass (`APPROVAL.md` required before execution)
- No out-of-scope active testing in default Action surface
- No secret leak to `GITHUB_OUTPUT` / summary (canary tests)
- No domain logic duplicated in Action layer (entrypoint invokes CLI only)
- No stable-release / Marketplace claim in implementation artifacts

## Release handoff

Tagging, Marketplace listing, and mutable major refs remain **separate human decisions** outside this proof.
