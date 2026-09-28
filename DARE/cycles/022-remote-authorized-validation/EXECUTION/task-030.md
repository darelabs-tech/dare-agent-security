# task-030 — Add `ObservedResourceContext` and `scenario_with_observed_resource` to the 018 engine (BQ-1)

**Status:** DONE (with a Product Owner decision on trust class)  
**Complexity:** MED

## Files changed

- `crates/dare-mcp-auth-security/src/observed.rs` (new): `ObservedAuthServer`, `ObservedResourceContext`, `opaque_uri`, `scenario_with_observed_resource`
- `crates/dare-mcp-auth-security/src/lib.rs`: `pub mod observed;`

This is an additive API. No existing type, invariant, schema or test in 018 changed, and
the engine still has no network capability.

## Result

**Opaque identifiers.** Every observed URL becomes `u-` plus 16 hex characters of
SHA-256. This passes `SyntheticUri`'s non-fetchable check, and equal URLs give equal ids,
so every comparison the engine makes keeps its structure.

**Derived scenario.** It keeps only the observed metadata: tokens, flows, scope,
registration, credentials, identity and final operation are cleared, and so is the lab
behaviour, with one trial. The base scenario's synthetic contexts can therefore never be
decided as if a live target produced them.

## Product Owner decision: trust class

BQ-1 said observed metadata is `SELF_REPORTED`. The 018 engine treats anything other
than `AUTHENTICATED` as a violation of the resource-binding and issuer-boundary
invariants (`TrustClass::may_establish_identity`). With `SELF_REPORTED`, every coherent
server would therefore FAIL.

The Product Owner chose **`AUTHENTICATED` via TLS**: each document arrives over verified
TLS from the exact origin the target's owner authorized.

The content is still the server's own claim. The remote validator reports it in
`self_reported_fields` (`protected_resource_metadata`), and the module doc states that
the trust class means origin authentication only. Recorded in REGRESSION.md.

## Tests

- `opaque_identifiers_preserve_equality_and_are_not_fetchable`
- `the_derived_scenario_keeps_only_observed_metadata`
- `a_resource_that_differs_from_the_expected_one_stays_different`
- `no_observation_means_no_metadata`

## Ralph Loop

- `cargo clippy -p dare-mcp-auth-security --all-targets -- -D warnings` green
- `cargo test -p dare-mcp-auth-security`: 352 passed, 0 failed (the existing suite plus 4 new)
- No dependency change: `sha2` was already a dependency
