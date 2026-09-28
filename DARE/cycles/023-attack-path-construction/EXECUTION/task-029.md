# task-029 — Implement `merge.rs`

**Status:** DONE  
**Complexity:** HIGH

## Change

`merge.rs` implements BLUEPRINT §7.1 and §4.9:
- Model entities become nodes in their own right.
- A projected node resolves through `alias_for`, or else gets its run-scoped id. A type clash is refused, security flags are OR-ed, and a tenant disagreement is refused (`TenantClash`).
- Authority principals and credentials are rewritten to node ids. A principal that is not a node becomes `ext:<token>`, and a credential that is not a credential node is dropped.
- Identical edges merge: the stronger evidence wins, ids and guards are unioned, and provenance is kept.
- Declared edges are INFERRED, with `source_facts` citing `system-model:<digest>#/declared_edges/<i>`, or NOT_TESTED.
- `crosses_trust_boundary` lists the boundaries that contain exactly one endpoint.
- Alias hits are counted for the report.

## Tests

`tests/graph.rs`: `the_same_local_id_in_two_runs_stays_two_nodes_without_an_alias`, `an_alias_to_an_entity_of_another_type_is_refused`, `merged_nodes_that_disagree_on_their_tenant_are_refused`, `identical_edges_merge_by_the_stronger_evidence_and_unioned_guards`, `authority_names_nodes_or_an_opaque_external_subject`, `declared_edges_and_trust_boundaries_come_from_the_model`.

## Ralph Loop

Green: fmt, clippy `-D warnings` (`dare-attack-path` and `dare-attack-graph`, all targets), and `cargo test -p dare-attack-path -p dare-attack-graph` (17 suites, 115 passed, 0 failed).
