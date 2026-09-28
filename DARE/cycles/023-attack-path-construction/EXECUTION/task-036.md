# task-036 — Add the scale test (O-09)

**Status:** DONE  
**Complexity:** LOW

## Change

- `tests/scale.rs` builds a fixed-seed LCG graph: 2 000 nodes, exactly 10 000 distinct edges with a mix of FAIL, PASS and unguarded edges, and 50 entries × 50 targets.
- The test validates it, enumerates it and validates the paths.

## Tests

`cargo test -p dare-attack-path --release --test scale`: 1 601 paths, stopped by `MAX_STEPS` (reported as truncated), 0.64 s, under the 10 s bound.

## Ralph Loop

Green: fmt, clippy `-D warnings` (`dare-attack-path` and `dare-attack-graph`, all targets), and `cargo test -p dare-attack-path -p dare-attack-graph` (17 suites, 115 passed, 0 failed).
