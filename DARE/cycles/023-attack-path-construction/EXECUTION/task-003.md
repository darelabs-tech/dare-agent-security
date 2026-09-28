# task-003 — Add the three `schemas/attack-graph/v2` JSON schemas

**Status:** DONE  
**Complexity:** MED

## Change

- `schemas/attack-graph/v2/attack-graph.schema.json`, `attack-paths.schema.json` and
  `projection-report.schema.json`, all draft 2020-12.
- `additionalProperties: false` is set on every object.
- The `nodeType`, `edgeType`, `authority` and `evidence` definitions are copied
  **verbatim** from the v1 schema, so v1 and v2 cannot disagree on them.
- Entry and target classes are separate enums (`entryClass`, `targetClass`), so an entry
  class used as a target is a schema error (BLUEPRINT §4.8).
- Bounds: `path.nodes` ≤ 13 and `path.edges` ≤ 12 (`MAX_PATH_EDGES`), artifacts ≤ 64,
  `pairs_truncated` ≤ 1 000, plus the v1 node and edge limits.
- A `DISCONTINUOUS` path requires `discontinuity_at`, and a `FEASIBLE` path must not
  carry it (`allOf` / `if` / `then` / `else`).

## Tests

- `the_embedded_schemas_compile` (`crates/dare-attack-graph/tests/v2_contract.rs`): all three
  schemas compile, and each one's top level sets `additionalProperties: false`.
- `the_golden_example_validates_and_round_trips`: the serialized Rust types validate
  against these schemas, which proves that the field names and enums agree.

## Ralph Loop

Green: fmt, clippy `-D warnings`, `cargo test -p dare-attack-graph`. There is no dependency
change.
