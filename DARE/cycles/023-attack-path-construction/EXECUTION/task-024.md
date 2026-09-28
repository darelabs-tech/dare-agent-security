# task-024 — Implement the supply-chain projector (§6.6)

**Status:** DONE  
**Complexity:** MED

## Change

`project/supply_chain.rs`. `node_type` and `edge_for` are exhaustive matches, with no wildcard. `PROVIDED_BY`, `ATTESTED_BY` and `SIGNED_BY` are counted, not projected. Dependency and lineage edges point from dependency to dependent. A lineage whose source is a DATASET uses the dataset role. Edges cite `evidence_digest`, plus the BOM documents when a BOM stated the edge (R-6). `SupplyChainViolation.component_id` narrows a FAIL on either endpoint.

## Tests (`crates/dare-attack-path/tests/projection_tables.rs`)

`supply_chain_tables_are_exhaustive`, `supply_chain_rows_and_entity_narrowing`: on the static fixture, a BOM_COMPLETENESS FAIL is ENTITY-scoped on the only edge. Every projected edge is also checked by `all_have_evidence`:
- it carries evidence ids;
- an OBSERVED edge cites evidence records;
- a STATICALLY_PROVEN edge cites `input:<engine>:` ids only;
- it has a locator and an original kind.

The inputs are real engine output (the fixture bundles of tasks 014–016).

## Ralph Loop

Green: fmt, clippy `-D warnings`, `cargo test -p dare-attack-path` (60 tests).
