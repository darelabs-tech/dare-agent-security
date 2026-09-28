# task-025 — Implement the A2A projector (§6.7)

**Status:** DONE  
**Complexity:** MED

## Change

`project/a2a.rs`. Peers become AGENT nodes keyed by logical agent id, and each is a `PEER_AGENT` entry. Each exchange becomes peer `CALLS` SUT, with authority `{principal: authorization_subject(), delegated, tenant: tenant_claim, scopes: requested skill}`. Delegation hops become grantor `DELEGATES_TO` grantee (STATICALLY_PROVEN over the DELEGATION documents). `AUTHORITY_PROPAGATION` guards only `DELEGATES_TO`, and the other 11 properties guard `CALLS`. `card_for` is not called (O-2). Result-only mode (022) projects `PeerRecord` and `ExchangeRecord` and no delegation.

## Tests (`crates/dare-attack-path/tests/projection_tables.rs`)

`a2a_rows` (simulated and static). Every projected edge is also checked by `all_have_evidence`:
- it carries evidence ids;
- an OBSERVED edge cites evidence records;
- a STATICALLY_PROVEN edge cites `input:<engine>:` ids only;
- it has a locator and an original kind.

The inputs are real engine output (the fixture bundles of tasks 014–016).

## Ralph Loop

Green: fmt, clippy `-D warnings`, `cargo test -p dare-attack-path` (60 tests).
