# task-010 — Implement `ids.rs` run-scoped and entity node ids

**Status:** DONE  
**Complexity:** LOW

## Change

- `EngineSlug` holds the ten kebab-case slugs.
- `RunTag::from_result_bytes` takes the first 12 hex digits of SHA-256.
- `local_token` keeps an id that matches `^[A-Za-z0-9._-]{1,96}$`. Anything else becomes
  `x-` plus 32 hex digits.
- `scoped_node_id` builds `node:<type>:<engine>:<run>:<token>`.
- `entity_node_id` builds `node:<type>:<entity_id>`. It returns `None` for an id that does
  not match `^[a-z0-9][a-z0-9._-]{0,95}$`.
- `display_name` keeps the raw label only if `validate_safe_label` passes and it has no
  control character. Otherwise the name becomes `<type-slug> <token>`.

## Tests

- `safe_tokens_pass_through_and_everything_else_is_hashed`: `:`, a space, a bidi override,
  `Bearer …`, an empty id and 97 characters are all hashed. The hash is deterministic and
  distinct per input.
- `produced_ids_match_the_v1_node_id_pattern_and_never_collide`: a scoped id has 4 `:` and
  an entity id has 2, and an entity id cannot contain `:`.
- `entity_ids_follow_their_grammar`.
- `unsafe_labels_are_replaced_by_the_hashed_token`: a bearer label never survives.
- `engine_slugs_are_kebab_case_and_serialize_as_such`.

## Ralph Loop

Green: fmt, clippy `-D warnings`, tests.
