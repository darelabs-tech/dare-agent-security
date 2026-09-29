# task-008 — Add `schemas/blast-radius/v1/compromise.schema.json`

**Status:** DONE  
**Complexity:** LOW

The schema follows draft 2020-12 with `additionalProperties: false`. It matches BLUEPRINT
§4.3:
- `schema_version` const `"1"`;
- `scenario_id` and `entity_id` use the entity pattern;
- `graph_id` is `^graph:[0-9a-f]{64}$`;
- `node_id` uses the v1 node pattern, with `maxLength` 400;
- `seeds` holds 1–64 items, each with `oneOf` node_id/entity_id;
- `kind` is the closed enum, and `note` is 1–160 characters;
- `max_depth` is 1–12 and `max_states` is 1–1 000 000.

## Tests (`crates/dare-blast-radius/tests/scenario.rs`)

- `both_schemas_compile_and_are_closed` checks that every object schema at any depth has
  `additionalProperties: false`. The first draft of this test mistook a data field named
  `properties` for the keyword; it now checks only `type: object` nodes.
- `the_compromise_schema_enforces_its_shape` refuses each of the following:
  - 0 seeds and 65 seeds;
  - a seed with no reference, and a seed with both references;
  - an unknown kind;
  - an entity id containing `:`;
  - a bad `graph_id`;
  - an extra field;
  - `max_depth` 13.

  It admits `max_depth` 12.

Ralph Loop green.
