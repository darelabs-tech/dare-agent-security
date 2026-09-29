# task-009 — Add `blast-radius.schema.json` and the `model.rs` types

**Status:** DONE  
**Complexity:** MED

- **Schema.** `schemas/blast-radius/v1/blast-radius.schema.json` is closed throughout.
  Its `$defs` are `route`, `search`, `impact`, `target`, `seed`, `guardRef` and the
  enums. It reuses the v2 target-class and control-state values and the graph, node and
  edge id patterns.
- **Types.** `crates/dare-blast-radius/src/model.rs` has every type of §4.4 with
  `deny_unknown_fields`. It also has the enums `SeedKind`, `Exposure` and `StopBound`,
  and the embedded schemas.
- **`the_result_document_round_trips_and_carries_no_score`** checks three things:
  - a hand-built document with one `CONTAINED` target validates against the schema;
  - it deserializes into `BlastRadiusDoc` and serializes back to an equal value;
  - none of the schema's more than 40 property names contains `score`, `probab`,
    `likelihood`, `weight`, `risk` or `rank` (RS-07).

  The first draft scanned the whole schema text and matched the word "score" in the
  description that says there is none. It now checks the declared property names.

Ralph Loop green.
