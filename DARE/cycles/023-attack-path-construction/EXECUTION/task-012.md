# task-012 — Implement `model.rs` system-model admission and resolution rules 1–7

**Status:** DONE  
**Complexity:** MED

## Change

`crates/dare-attack-path/src/model.rs`:
- **`load_model`:**
  - refuses a symbolic link;
  - reads through `take(4 MiB + 1)` (`TooLarge`);
  - hands the bytes to `admit_model_bytes`.
- **`admit_model_bytes`** checks, in this order:
  1. JSON;
  2. depth ≤ 64;
  3. count limits (`OverLimit` names the list);
  4. declared-edge justification (rule 6);
  5. entity-id grammar;
  6. exactly one designation reference;
  7. the embedded schema;
  8. typed decode (`deny_unknown_fields`);
  9. `digest` = `sha256:` + the canonical key-sorted digest.
- **`resolve`:**
  - checks safe labels, with the Cycle 008 `validate_safe_label` and the tenant included;
  - rule 1: unique entities;
  - rule 2: an alias names a known entity;
  - rule 3: one local id maps to one entity. A run-less alias and a run-specific alias
    for the same `(engine, local_id)` may coexist only if they name the same entity, and
    then the run-specific one is found first by `alias_for`;
  - rule 6: declared-edge endpoints and authority entities are known, and the credential
    names a `CREDENTIAL` entity;
  - trust boundaries name known entities and have unique ids.
- **Rules applied later.** Rules 4 (type clash), 5 (a designation resolves to a graph
  node) and 7 (unused aliases reported) need the projected graph. `merge` (task-029)
  applies them through the lookups `alias_for`, `entity` and `entity_index`.

## Tests (`tests/model.rs`, 10 tests)

- `rule_1_…`: a duplicate entity, an entity id containing `:`, and a bearer label.
- `rule_2_…`: an unknown entity.
- `rule_3_…`: the same key twice, a run-less alias against a run-specific alias naming
  different entities (refused), and the same pair naming the same entity (accepted, with
  run-specific precedence asserted through `alias_for`).
- `rule_5_…`: both references, neither reference, and an entry class used as a target.
- `rule_6_…`: a missing rationale, a blank rationale, a missing reason, an unknown
  endpoint, and a credential authority that is not a credential.
- The remaining tests cover:
  - trust boundaries;
  - limits and unknown fields (10 001 aliases, an extra key, depth 70);
  - the file loader (a symlink, 4 MiB + 1 byte);
  - digest stability (the same under pretty-printing, different on a content change).

## Ralph Loop

Green: fmt, clippy `-D warnings`, `cargo test -p dare-attack-path` (27 tests).
