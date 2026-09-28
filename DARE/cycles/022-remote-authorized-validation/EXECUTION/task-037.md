# task-037 — Add the `validate remote` and `validate replay-capture` CLI subcommands

**Status:** DONE (two recorded deviations)  
**Complexity:** MED

## Files changed

- `crates/dare-agent-security-cli/src/remote_validation.rs` (new): `RemoteArgs`, `ReplayCaptureArgs`, `REMOTE_AFTER_HELP`, `run_remote_validation`, `run_replay_capture`
- `src/args.rs`, `src/main.rs`, `src/lib.rs`: wiring
- `Cargo.toml`: `dare-remote-validation` as a normal dependency, **without** `lab`
- `crates/dare-remote-validation`:
  - `VerifiedAuthorization::lower_limits`
  - `AuditRecord::admit`
  - `runner::run_remote_lowered`
  - `tests/cli_fixture.rs`, an ignored generator for the committed fixture
- `crates/dare-agent-security-cli/tests/fixtures/remote-replay/`: a real REMOTE-LAB `multiturn-lab-002` run, holding the authorization, plan, capture, audit and expected result. None of it contains a secret: the capture is scrubbed, and the authorization names only the credential's variable.

## Result

**Flags.** Exactly those of BLUEPRINT §5.1. `--max-*` flags only lower limits, and they
are applied to the verified authorization **after** `verify`: the plan is untouched, so
its digest and the capture's binding still hold. There is no URL, header, token, proxy,
TLS, redirect, model, seed or shell flag.

**Exit codes.**

| Code | Meaning |
|---|---|
| 0 | PASS |
| 1 | ERROR, or a non-refusal harness error |
| 2 | FAIL or INCONCLUSIVE |
| 3 | Any refusal (authorization, schema, bounds, tampered capture), before anything is written |

**Output.** Artifacts pass through the output ledger. The directory is created only after
the run succeeds. stdout carries one line (`remote-result verdict …`), or the result
JSON with `--json`.

## Deviations (recorded in REGRESSION.md)

1. **`--max-request-bytes` is not offered.** §5.1 lists four lower-only flags, and this
   matches them. The request-size limit stays authorization- and plan-only.
2. **Ctrl-C** terminates the process without writing artifacts. The gateway's
   operator-stop flag remains a library entry point (`EgressGateway::operator_stop_flag`,
   tested in `gateway.rs`). Wiring a signal handler would need tokio's `signal` feature
   in the CLI and a handle into `run_remote`; recorded as a follow-up.

## Tests (`tests/remote_cli.rs`)

- `the_help_offers_no_flag_that_could_widen_scope`: none of the 17 forbidden flags appears in either subcommand's help, each one fails to parse, and the help carries the bounded claim.
- `a_refusal_exits_3_and_writes_nothing`
- `a_raised_limit_is_refused`: `--max-rps 0` exits 3, and nothing is written.
- `replay_capture_reproduces_the_committed_result_byte_for_byte`: exits 2 (FAIL), writes exactly five files, and `remote-result.json` equals the committed expected result.
- `replay_capture_refuses_a_tampered_capture_and_writes_nothing`

## Ralph Loop

- `cargo clippy -p dare-agent-security --all-targets -- -D warnings` green
- `cargo test -p dare-agent-security`: **323 passed, 0 failed**
