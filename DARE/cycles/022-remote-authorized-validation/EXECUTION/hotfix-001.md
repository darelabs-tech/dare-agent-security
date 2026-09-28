# hotfix-001 — Remote evidence in coverage (RF-16) and Ctrl-C operator stop

**Status:** DONE  
**Requested by:** the Product Owner after the Cycle 022 merge, as a hotfix instead of a new cycle.  
**Base:** `main @ c078951`

## 1. RF-16: remote evidence feeds Cycle 006 coverage as dynamic

| File | Change |
|---|---|
| `crates/dare-coverage/src/correlate.rs` | `ExecutionsDocument` (`schema_version`, `execution_mode`, `evidence_class`, `source`, `executions`; unknown fields refused), `check(&facts)`, `annotate(&mut report)`, `parse_executions` (bare array or document) |
| `crates/dare-remote-validation/src/coverage.rs` (new) | `executions_document(result, evidence)`: the property is read from each engine's own extension (`property_id` for prompt injection, `property` for the others). A record without one fails closed. The verdict is `result::aggregate` over that property's records. |
| `crates/dare-remote-validation/src/result.rs`, `tests/runner.rs`, `tests/replay_equivalence.rs`, CLI `tests/remote_cli.rs` | the artifact-set assertions now include it; `COVERAGE_FILE = "remote-coverage.json"`, rendered and admitted through the output ledger as the sixth artifact |
| `crates/dare-agent-security-cli/src/coverage.rs` | `--executions` accepts the document; checks it against the facts (a contradiction is a usage error, exit 3); annotates decided rows |
| `crates/dare-agent-security-cli/tests/fixtures/remote-replay/coverage-facts.json` (new) | facts for the CI step: stateful agent over HTTP, dynamic authorization allowed |

### Why the report is annotated rather than re-typed

`SupportedMode::Dynamic` is not in any registry entry, and the compatibility test pins
the registry and every profile byte for byte. The mode is therefore carried by the
executions document. In the report, each row the document decided gets its
rationale suffixed with `; dynamic evidence from remote run under authorization …`.
Counts, gate, verdicts and evidence ids are untouched
(`annotation_marks_only_rows_the_document_decided_and_moves_no_number`).

## 2. Ctrl-C operator stop

| File | Change |
|---|---|
| `crates/dare-remote-validation/src/gateway.rs` | `with_operator_stop(flag)`. The stop is re-checked **after** the rate-limit wait (see §3). |
| `crates/dare-remote-validation/src/runner.rs` | `run_remote_stoppable(…, stop)`. `run_remote_lowered` delegates to it with a fresh flag, so its signature is unchanged. |
| `crates/dare-agent-security-cli/src/remote_validation.rs` | `operator_stop_listener`, spawned before the run and aborted after it. First signal: set the flag and print a notice. Second signal: exit 130. |
| `crates/dare-agent-security-cli/Cargo.toml` | tokio `signal` feature. `Cargo.lock` is unchanged. |

## 3. Gap found while wiring

`admit` checked the operator stop before `limiter.wait`. A Ctrl-C during the wait (up
to 500 ms at the 2 rps maximum) would still have let that request leave. It is now
checked again after the wait. Covered by
`a_stop_during_the_rate_wait_keeps_the_request_from_leaving`.

## 4. CI

`remote-validation-2026`:
- the replay step also checks that `remote-coverage.json` exists and asserts `execution_mode=dynamic` and `evidence_class=DYNAMIC_AUTHORIZED`;
- a new step runs `validate coverage` on it with the multi-turn profile and asserts `eligible=7 tested=7 counts.FAIL=1`.

Both steps were run locally with the job's own commands.

## 5. Docs

- **EN/PT concept pages:** the new artifact, a "Coverage" section and a "Stopping a run" section.
- **`commands/validate.md`:** six artifacts, Ctrl-C, and `--executions`.
- **`exit-codes.md`:**
  - `validate coverage` exit 3 now covers a contradicting executions document;
  - `validate remote`: exit 130 on a second Ctrl-C.

## Ralph Loop

- **Build:** `cargo build --workspace`
- **Test:**
  - `cargo test --workspace --no-fail-fast`: 314 suites, **4 224 passed, 0 failed**, 4 ignored (4 209 before the hotfix);
  - new tests: 6 in `dare-coverage`, 3 in the CLI listener, 2 CLI process tests, 2 gateway tests, 2 replay/runner tests.
- **Lint:**
  - `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings`;
  - `cargo clippy -p dare-remote-validation --all-targets --features lab -- -D warnings`.
- **Audit:** `cargo audit` exit 0; no lockfile change.
- **Other checks:**
  - `scripts/k22/assert_no_real_credentials.py` and every `scripts/k*/verify_proof_citations.py` pass;
  - both mdBooks build.
