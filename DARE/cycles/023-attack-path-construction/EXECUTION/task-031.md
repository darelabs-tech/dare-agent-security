# task-031 — Implement graph construction in `run.rs` and the determinism test

**Status:** DONE  
**Complexity:** MED

## Change

- `project_all` loads every bundle and refuses `NoArtifacts`, `TooManyArtifacts` and `DuplicateRun`, naming both positions. It then re-indexes the bundles by result digest (R-15) and projects them.
- `build_graph`: merge, designate, then build and seal the `AttackGraphV2`, together with the projection report. Both are validated.
- `construct` adds enumeration and `validate_paths_v2`.
- No wall-clock value is written.
- Two defects surfaced on the first end-to-end run and are fixed: R-13 (the label fallback) and R-14 (the guard pattern).

## Tests

`the_same_artifacts_in_any_order_build_byte_identical_output`: 10 permutations of all 10 fixture bundles give byte-identical graph and report, and neither contains `generated_at`. Also `the_same_result_given_twice_is_refused_with_both_positions`.

## Ralph Loop

Green: fmt, clippy `-D warnings` (`dare-attack-path` and `dare-attack-graph`, all targets), and `cargo test -p dare-attack-path -p dare-attack-graph` (17 suites, 115 passed, 0 failed).
