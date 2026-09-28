# task-028 — Implement the remote (022) projector (§6.9)

**Status:** DONE  
**Complexity:** MED

## Change

`project/remote.rs` dispatches each run's `engine_result` to the owning projector in result-only mode. Guards come from `remote-evidence.json` (R-7). Every fact carries `dynamic_authorized: true` through the bundle. A multi-turn run has no transcript and is counted `MULTI_TURN_RESULT_ONLY`. A run with a null `engine_result` is counted `RemoteRun::no_engine_result`.

## Tests (`crates/dare-attack-path/tests/projection_tables.rs`)

`remote_multi_turn_runs_are_counted_not_guessed` (the 022 CLI fixture is a multi-turn run over `dare-conversation`). Every projected edge is also checked by `all_have_evidence`:
- it carries evidence ids;
- an OBSERVED edge cites evidence records;
- a STATICALLY_PROVEN edge cites `input:<engine>:` ids only;
- it has a locator and an original kind.

The inputs are real engine output (the fixture bundles of tasks 014–016).

## Ralph Loop

Green: fmt, clippy `-D warnings`, `cargo test -p dare-attack-path` (60 tests).
