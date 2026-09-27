# task-009 — Implement acyclicity, depth and DP path count (rules 8–10)

**Status:** DONE  
**Complexity:** MED

## Files changed

- `crates/dare-multi-turn-security/src/graph.rs`

## Result

- **Rule 8:** Kahn's algorithm. On a cycle, the error names the smallest remaining node id.
- **Rules 9 and 10:** children-before-parents passes over the topological order. The path count uses `saturating_add`.

## Tests

- `rule_8_a_cycle_names_its_smallest_node` (the cycle `m ↔ k` reports `k`)
- `rule_9_depth_bound_is_the_turn_bound` (32 accepted, 33 refused, a lowered bound respected)
- `rule_10_path_counts_match_hand_computed_values`: **5 graphs**:
  - single node = 1;
  - 10-chain = 1;
  - 3-way fan = 3;
  - 5-rung diamond ladder = 32;
  - 6-rung ladder = 64.

  A 7-rung ladder (128 paths) is refused.
- `rule_10_path_count_saturates_instead_of_overflowing`: 2^63 is exact and 2^64 saturates at `u64::MAX` instead of wrapping.

## Recorded correction

The first version of the saturation test assumed the node cap would trip at 64 rungs.
A 64-rung ladder has 193 nodes, which is below the 256-node cap. The test was wrong,
not the code, and it now asserts the actual saturation value.

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 266 suites, 3 816 passed, 0 failed (+20 over task-007)
- Audit: no dependency change
