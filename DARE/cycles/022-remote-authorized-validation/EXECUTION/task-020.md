# task-020 — Implement `audit.rs`

**Status:** DONE  
**Complexity:** MED

## Result

The audit record follows BLUEPRINT §4.11. Events are chained from a seed that binds the
authorization digest, plan digest, origin and confirmed origin. `detail` is a closed
vocabulary word: the schema pattern `^[A-Z][A-Z_]{0,63}$` makes a target value
impossible there. `verify` checks the chain, and that the record describes the capture
(same digests and origin, and `totals.requests == entries.len()`).

`operator_host` from the Blueprint was dropped: it is `None` in v1 and would only ever be
a local hostname.

## Tests

- `a_consistent_record_verifies_against_its_capture`
- `a_changed_or_removed_event_breaks_the_chain`
- `totals_must_describe_the_capture`

The refusal-writes-nothing half is asserted at the runner and CLI (tasks 034 and 037).

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets --features lab -- -D warnings` green
- `cargo test -p dare-remote-validation`: 103 passed
- No external dependency added
