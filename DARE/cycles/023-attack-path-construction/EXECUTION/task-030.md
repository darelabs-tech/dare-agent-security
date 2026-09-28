# task-030 — Implement `designate.rs` default designations and model overrides

**Status:** DONE  
**Complexity:** MED

## Change

- `apply_defaults` adds targets from merged flags: sensitive, privileged credential and destructive.
- `apply_model` resolves `entity_id` or `node_id`, refuses an unknown node (`UnknownDesignationTarget`), and applies `exclude` after the defaults, whatever the origin.
- `cross_tenant_targets` is per entry (R-9).

## Tests

`designations_follow_flags_then_the_model` (`tests/graph.rs`), and `a_cross_tenant_resource_is_a_target_for_an_entry_of_another_tenant` (`tests/paths.rs`).

## Ralph Loop

Green: fmt, clippy `-D warnings` (`dare-attack-path` and `dare-attack-graph`, all targets), and `cargo test -p dare-attack-path -p dare-attack-graph` (17 suites, 115 passed, 0 failed).
