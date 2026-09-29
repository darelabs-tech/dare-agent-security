# task-010 — Implement `scenario.rs`: seed resolution, the kind table and entry-point seeding

**Status:** DONE  
**Complexity:** MED

`crates/dare-blast-radius/src/scenario.rs` provides:
- `load_scenario`, which admits the file (1 MiB, depth 64, no symlink), validates it
  against the embedded schema and deserializes it;
- `scenario_from_value`, which follows BLUEPRINT §6.1:
  - `graph_id` must equal the graph's id;
  - each seed resolves by `node_id`, or by `entity_id` to the unique
    `node:<own slug>:<entity>`;
  - the kind must fit the node's type, and a `(node, kind)` pair may appear once;
  - seeds are sorted by `(node, kind)`;
  - the scenario digest is the canonical `sha256:`;
- `kind_fits` and `kind_for_entry`;
- `entry_point_seeds`, which maps entry classes onto kinds, skips misfits
  (`seeds_skipped`), deduplicates, caps at 64 (`seeds_omitted`), and refuses a graph
  with no entries (`NoSeeds`).

## Tests (`tests/scenario.rs`)

- `seeds_resolve_by_node_or_entity_and_sort`: the tenant is carried, the digest is
  present, and a run-scoped id is never matched by an entity id.
- `every_seed_rule_refuses_with_its_variant`: `GraphMismatch`, `UnknownSeed` (by entity
  and by node), `SeedKindMismatch`, `DuplicateSeed { first: 0, second: 2 }`,
  `InvalidDocument`, and `AmbiguousSeed` on a graph where one entity id names two
  types.
- `the_kind_table_is_complete`: all 4 kinds × 14 node types.
- `entry_points_become_seeds_and_misfits_are_skipped`: a `PEER_AGENT` entry on a DATA
  node is skipped, and `NoSeeds` is refused.

`tests/support/mod.rs` builds small valid v2 graphs, and each is checked with
`validate_graph_v2`.

Ralph Loop green: fmt, clippy `-D warnings --all-targets`, and the 7 scenario tests.
