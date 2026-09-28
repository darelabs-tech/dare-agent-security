# task-011 — Add `schemas/attack-path/v1/system-model.schema.json`

**Status:** DONE  
**Complexity:** MED

## Change

The schema is draft 2020-12 and sets `additionalProperties: false` on every object. It
covers each field of BLUEPRINT §4.5:
- **Id patterns:** `entity_id`, `model_id` and `boundary_id` use the entity-id pattern.
  An alias `run` must match `^[0-9a-f]{12}$`.
- **Designations:** each names exactly one of `entity_id` or `node_id`, through `oneOf`.
  `entry_points` and `targets` use separate class enums, which are copied from the v2
  graph schema.
- **Declared edges:** `rationale` is required when `status` is INFERRED and `reason` when
  it is NOT_TESTED.
- **Array limits:** 2 000 entities, 10 000 aliases, 5 000 declared edges, 64 trust
  boundaries and 500 members per boundary.
- **Shared enums:** `nodeType` and `edgeType` are copied from the attack-graph schemas.

One refinement to the Blueprint sketch: on a declared edge, `authority.principal` and
`authority.credential` name **model entities** (entity-id pattern). `merge` turns them into
node ids, and the credential must be a `CREDENTIAL` entity. This keeps the v1 rule that
`authority.credential` is a `node:credential:` id, without making the model author write
node ids.

## Tests

`the_schema_compiles_and_the_base_model_is_admitted` (`crates/dare-attack-path/tests/model.rs`).

## Ralph Loop

Green: fmt, clippy `-D warnings`, tests.
