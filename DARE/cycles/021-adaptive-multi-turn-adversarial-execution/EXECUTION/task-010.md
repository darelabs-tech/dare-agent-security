# task-010 — Implement canonical JSON and graph digest

**Status:** DONE  
**Complexity:** LOW

## Files changed

- `crates/dare-multi-turn-security/src/canonical.rs` (new): `canonical_bytes`, `digest`, `digest_bytes`, `is_digest`
- `crates/dare-multi-turn-security/src/graph.rs`: `StrategyGraph::digest`

## Result

Canonical bytes go through `serde_json::Value` (a sorted `BTreeMap`).
`cargo tree -e features -i serde_json` shows only `default` and `std`, with no
`preserve_order`, which confirms Blueprint AD-09.

`StrategyGraph::digest` goes beyond AD-09 by also sorting nodes by id and edges
lexicographically. The same strategy written in a different order therefore has the
same digest, while any content change produces a different one.

## Tests

- `canonical::tests::key_order_does_not_change_the_digest` (two differently ordered JSON sources)
- `canonical::tests::digests_are_well_formed_and_the_shape_check_is_strict`
- `graph::tests::the_digest_is_stable_across_runs_and_declaration_order` (10 runs, reversed nodes and edges, reparsed JSON, a content change alters the digest)

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 266 suites, 3 816 passed, 0 failed (+20 over task-007)
- Audit: no dependency change
