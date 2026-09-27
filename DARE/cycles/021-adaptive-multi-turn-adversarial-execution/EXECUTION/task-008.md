# task-008 — Implement `StrategyGraph` types and validation rules 1–7 and 11

**Status:** DONE  
**Complexity:** MED

## Files changed

- `crates/dare-multi-turn-security/src/graph.rs` (new)
- `crates/dare-multi-turn-security/src/model.rs` (new): the closed enums of Blueprint §4.3, needed by the graph types
- `crates/dare-multi-turn-security/src/lib.rs`: module declarations

## Result

`TurnTemplate`, `ApprovalDisclosure`, `StrategyNode`, `StrategyEdge` and `StrategyGraph`
match Blueprint §4.4, with `deny_unknown_fields`. `validate` returns the first failing
rule in the frozen order.

Rule 1 also re-checks turn content (size and hostile text). The corpus builds graphs in
code, so file admission cannot be assumed to have run.

`model.rs` was pulled forward from task-011 because the graph types need `TurnRole`,
`ObservationClass` and `AuthorityLevel`. `MultiTurnInvariant::property_id` fixes the
seven property IDs, and its serde names are tested against the scenario schema enum.

## Tests (`graph::tests`, `model::tests`)

- `rule_1_version_and_hostile_content`
- `rule_2_node_and_edge_counts`
- `rule_3_duplicate_node_and_missing_root`
- `rule_4_unknown_endpoint_and_duplicate_transition`
- `rule_5_unclassifiable_never_selects_a_node`
- `rule_6_terminal_with_edges_and_dead_end`
- `rule_7_unreachable_node`
- `rule_11_approval_must_match_the_role` (role without disclosure, disclosure without role, malformed digest, valid)
- `transitions_follow_declared_edges_only`
- `authority_is_ordered_from_none_to_admin`
- `serialized_names_match_the_schemas`
- `every_invariant_maps_to_a_distinct_property_in_an_existing_family` (asserts no `MULTI_TURN` namespace, DESIGN §13 Q1)
- `only_replay_is_not_synthetic`

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 266 suites, 3 816 passed, 0 failed (+20 over task-007)
- Audit: no dependency change
