# task-021 — Implement `outcome.rs` transport overlay

**Status:** DONE  
**Complexity:** LOW

## Result

`overlay(engine, transport)` implements BLUEPRINT §4.10:
- connection, timeout, TLS and protocol violation give ERROR;
- oversize, 429, 5xx, unexpected auth and 404 give INCONCLUSIVE;
- FAIL is never lowered;
- PASS is impossible when any transport outcome is present.

`classify_status` maps statuses to outcomes. A 401/403 is an observation, not a failure,
when the step expects an authentication challenge (MCP auth discovery).

## Tests

- `no_transport_outcome_can_produce_pass` (10 outcomes × 4 verdicts)
- `a_fail_is_never_lowered`
- `without_a_transport_outcome_the_engine_verdict_stands`
- `the_blueprint_table`
- `statuses_map_to_outcomes`

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets --features lab -- -D warnings` green
- `cargo test -p dare-remote-validation`: 103 passed
- No external dependency added
