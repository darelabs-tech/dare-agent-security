# task-034 — Implement `chokepoint.rs`

**Status:** DONE  
**Complexity:** MED

## Change

- For each target, the chokepoints are the edges shared by every feasible CONTROL_FAILED path, excluding BQ-1-exempt edges, each with its non-PASS guard properties and the failed-path count.
- A chokepoint is `partial` when any bound other than the per-pair cap fired, when a truncated pair names the target, or when the truncated-pair list was itself capped.

## Tests

`chokepoints_are_the_edges_every_failed_path_shares` (a shared entry edge, and `partial` under a cap of 1), `a_single_failed_path_…_and_disjoint_paths_none`, `discontinuous_paths_are_listed_apart` (no chokepoint).

## Ralph Loop

Green: fmt, clippy `-D warnings` (`dare-attack-path` and `dare-attack-graph`, all targets), and `cargo test -p dare-attack-path -p dare-attack-graph` (17 suites, 115 passed, 0 failed).
