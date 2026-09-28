# task-020 — Implement the identity projector (§6.2)

**Status:** DONE  
**Complexity:** HIGH

## Change

`project/identity.rs`. Principals map HUMAN→HUMAN, AGENT→AGENT, and WORKLOAD or SERVICE→IDENTITY. Delegation edges are STATICALLY_PROVEN, or OBSERVED when a `DelegationEdge` event with the same `edge_id` occurs. Their authority is `{principal: subject or delegator, delegated, scopes: purpose and audience}`. Credential contexts give `CREDENTIAL` nodes, privileged when the owner is WORKLOAD or SERVICE, plus owner `AUTHENTICATES_AS` credential. A `CredentialContext` event gives effective principal `USES_CREDENTIAL` credential (R-5). The resource gives `RESOURCE` (sensitive when `SYNTHETIC_RESTRICTED`) and `BELONGS_TO_TENANT`. A credential `CAN_REACH` the resource when its tenant labels include the resource's tenant. `FinalOperation` gives subject `CALLS` tool and subject `CAN_REACH` resource (R-4), with `authority_mutation` set exactly when `AUTHORIZATION_EXECUTION_BINDING` or `PRINCIPAL_BINDING` is FAIL. The SUT is the agent principal (AD-08).

## Tests (`crates/dare-attack-path/tests/projection_tables.rs`)

`identity_rows`, `identity_principal_kinds_map_to_node_types`. Every projected edge is also checked by `all_have_evidence`:
- it carries evidence ids;
- an OBSERVED edge cites evidence records;
- a STATICALLY_PROVEN edge cites `input:<engine>:` ids only;
- it has a locator and an original kind.

The inputs are real engine output (the fixture bundles of tasks 014–016).

## Ralph Loop

Green: fmt, clippy `-D warnings`, `cargo test -p dare-attack-path` (60 tests).
