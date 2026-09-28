# task-033 — Implement `ledger.rs`, `evidence.rs` and `result.rs` (including self-reported marking and `summary.md`)

**Status:** DONE  
**Complexity:** MED

## Result

- **`ledger.rs`.** `OutputLedger` scrubs with the run's `Scrubber` (credential forms and credential shapes) and then charges every artifact. It enforces a 32 MiB ceiling, and a write that would exceed it is refused and not charged. `charge` accounts for scratch bytes.
- **`evidence.rs`.** `retag` (AD-14) sets `observed.source = PROTOCOL_RESPONSE` and adds `extensions["dare.remote"]`: authorization id and digest, plan digest, origin, capture id and digest, observed window, `self_reported_fields` and `not_observable`. It then re-runs `validate` and `validate_secret_safety`, and a record that fails either is never returned.
- **`result.rs`.** `RemoteResult` carries no wall-clock value except the observed window copied from the capture.
  - Aggregation: FAIL stands over everything, then ERROR, then INCONCLUSIVE. PASS requires every run to pass, and no runs is INCONCLUSIVE.
  - `render_summary` writes "PASS relies on target-reported `<field>`" for every self-reported field of a PASS (BQ-2), a "not observable remotely" line per run, and the bounded claim.
  - `render_artifacts` admits the five artifacts through the ledger.
- **`StopReason::as_str`** was added. `Scrubber` derives `Clone`, and `EgressGateway::scrubber()` lets artifacts written after the run be scrubbed with the same credential forms.

## Tests

- `ledger::admitted_bytes_are_scrubbed_and_counted`
- `ledger::the_write_that_would_exceed_the_budget_is_refused_and_not_charged`
- `evidence::a_retagged_record_is_a_protocol_response_with_provenance_and_still_valid`: uses a real prompt-injection record
- `result::fail_stands_over_everything_and_pass_needs_every_run`
- End to end in task-034's `tests/runner.rs`: the summary wording, and no token in any of the five artifacts

## Ralph Loop

- `cargo clippy -p dare-remote-validation --all-targets --features lab -- -D warnings` green
- `cargo test -p dare-remote-validation`: 179 passed
