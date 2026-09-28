# task-035 — Implement path classification, v2 impact factors and `AttackPathsDoc`

**Status:** DONE  
**Complexity:** MED

## Change

- `paths.rs` forms pairs (R-11) and enumerates them.
- Each path is classified: v1 path id, weakest-edge evidence status, feasibility, the control state with its failed guards and undecided edges, entry and target classes, and `impact_factors`. Every one of these is computed by the shared `dare_attack_graph::v2` functions that the validator also uses.
- Discontinuous paths go to their own list, and chokepoints are computed over the feasible paths.

## Tests

`an_unguarded_edge_leaves_the_path_undecided_and_a_held_path_is_held` (BQ-1), `discontinuous_paths_are_listed_apart`, and `v2_impact_factors_equal_v1_on_the_v1_fixtures`: every path of the 5 v1 fixtures has the same six factors in v1 and v2. Every document passes `validate_paths_v2`.

## Ralph Loop

Green: fmt, clippy `-D warnings` (`dare-attack-path` and `dare-attack-graph`, all targets), and `cargo test -p dare-attack-path -p dare-attack-graph` (17 suites, 115 passed, 0 failed).
