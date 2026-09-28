# task-033 — Implement `enumerate.rs` pairwise shortest-first enumeration

**Status:** DONE  
**Complexity:** HIGH

## Change

- An index maps node ids to indices. Adjacency is sorted by (target id, edge id), so each step is an O(log n) lookup with no linear scan.
- The search runs level by level over exact lengths and collects up to budget + 1 paths to detect a cut.
- The per-pair cap, the global cap (`MAX_PATHS`) and the step bound (`MAX_STEPS`) are each reported in `stopped_by`, together with the counts of truncated and exhausted pairs. `max_path_edges` is not reported as truncation (R-10).

## Tests

`tests/paths.rs`: `paths_are_shortest_first_simple_and_validated`, `the_per_pair_cap_is_reported_and_keeps_the_shortest`, `the_global_cap_and_the_step_bound_are_reported` (K₁₁ plus an unreachable target stops at exactly `max_steps + 1`, both with 1 000 and with the real 5 000 000), `cycles_and_self_loops_do_not_repeat_nodes`, `ids_and_order_do_not_depend_on_input_order` (10 rotations).

## Ralph Loop

Green: fmt, clippy `-D warnings` (`dare-attack-path` and `dare-attack-graph`, all targets), and `cargo test -p dare-attack-path -p dare-attack-graph` (17 suites, 115 passed, 0 failed).
