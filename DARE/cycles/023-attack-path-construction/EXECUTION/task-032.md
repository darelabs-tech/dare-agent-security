# task-032 — Implement `continuity.rs` rules C1–C6

**Status:** DONE  
**Complexity:** HIGH

## Change

- `discontinuity(entry, edges, node_type)` tracks the acting principal and the set of actors through rules C1–C6 of BLUEPRINT §7.3, and returns the index of the first edge no rule explains.
- C4 requires `authority_mutation` **and** a FAIL guard from `MUTATION_PROPERTIES`.
- `ext:` principals never break a path (R-12).

## Tests

Unit tests `c1_…` to `c6_…`, each covering the positive and the negative case (in `continuity.rs`).

## Ralph Loop

Green: fmt, clippy `-D warnings` (`dare-attack-path` and `dare-attack-graph`, all targets), and `cargo test -p dare-attack-path -p dare-attack-graph` (17 suites, 115 passed, 0 failed).
