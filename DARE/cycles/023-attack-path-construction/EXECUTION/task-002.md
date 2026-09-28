# task-002 — Remove the `unwrap()` from v1 `make_path` and pin v1 output with golden digests

**Status:** DONE  
**Complexity:** LOW

## Change

- `crates/dare-attack-graph/src/path.rs`: `make_path` now looks up each edge with
  `ok_or_else(|| GraphError::Invalid("path references missing edge"))` and collects into
  `Result<Vec<_>>`, where it used to call `.unwrap()`. The lookup and the path construction
  are otherwise unchanged. The linear lookup stays as it was (Q5: items 2–4 are fixed in v2
  only).
- New unit test `a_path_naming_a_missing_edge_is_an_error_not_a_panic`.
- New `crates/dare-attack-graph/tests/v1_unchanged.rs`. For each of the five fixtures it
  repeats exactly what `validate attack-graph` does (build, `derive_paths` with the defaults,
  `graph_digest`, `validate_graph`, `to_vec_pretty`), then asserts the SHA-256 of both
  outputs against the digests recorded in `BASELINE.md`.

## Commands and results

- `cargo test -p dare-attack-graph`: all suites green, including `v1_unchanged` and the new
  unit test.
- `cargo test -p dare-adversarial -p dare-continuous`: 27 passed, 0 failed, unchanged.
- `grep -n "unwrap()\|expect(" crates/dare-attack-graph/src/path.rs`: matches only inside
  `#[cfg(test)]`.

## Ralph Loop

- fmt: clean.
- clippy `-D warnings` (`-p dare-attack-graph --all-targets`): clean.
- Test: green (above).
- Audit: no dependency change.
