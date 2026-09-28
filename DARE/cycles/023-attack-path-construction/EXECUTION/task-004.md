# task-004 — Implement the `dare_attack_graph::v2` model types

**Status:** DONE  
**Complexity:** MED

## Change

- `crates/dare-attack-graph/src/v2/model.rs` adds every type in BLUEPRINT §4.7, each with
  `deny_unknown_fields`.
- The string-valued fields of the Blueprint sketch are closed enums serialized in
  SCREAMING_SNAKE_CASE, so the JSON matches the sketch:
  - `GuardVerdict`, `GuardScope`, `EntryClass`, `TargetClass`, `DesignationOrigin`,
    `Feasibility`, `ControlState`, `StopBound`;
  - `DesignationV2` is split into `EntryDesignation` and `TargetDesignation`, so the class
    enum matches the side.
- `AttackPathsDoc` and `ProjectionReport` also carry their own `schema_id`.
- `ImpactFactorsV2` flattens the v1 `ImpactFactors`.
- v1 types, v1 serialization and the v1 module layout are unchanged. The one visible
  change is that `render::safe_label` becomes `pub(crate)` so the v2 views reuse it.
- `lib.rs` gains `pub mod v2;`.

## Tests

- `the_golden_example_validates_and_round_trips`: a serde round-trip of the golden graph and
  its paths document is lossless.
- `v1_unchanged` still passes.

## Ralph Loop

Green: fmt, clippy `-D warnings`, `cargo test -p dare-attack-graph`.
