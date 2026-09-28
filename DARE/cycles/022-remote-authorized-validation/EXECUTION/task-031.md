# task-031 — Implement the MCP Auth conversion using the new 018 API

**Status:** DONE  
**Complexity:** MED

## Result (`engines/mcp_auth.rs`)

**Loading.** `load` reads a built-in fixture the way `validate mcp-auth-security` does,
and its digest is the engine's own `bind(..).scenario_digest`.

**Live pass.** `live` GETs the protected-resource metadata. It then GETs the
authorization-server metadata **only** when an advertised server is the planned origin:
a plan has one origin, so any other server is recorded, never fetched.

**Verdict pass.**
- `observed` rebuilds the context from the capture alone.
- `verdict` derives the scenario through `scenario_with_observed_resource` and decides with an adapter that observes no request. The validator's own requests are not a property of the target, and `observations_are_synthetic() == false`.
- `not_observable` lists the eight contexts a metadata-only run cannot see.

## Tests (`tests/mcp_auth_live.rs`)

- `coherent_metadata_never_fails_any_mcp_auth_lab_scenario`: all 35 scenarios over one live capture.
  - 34 decide: 4 PASS (the metadata invariants the observation actually decides), 30 INCONCLUSIVE, no FAIL, no ERROR, all evidence valid.
  - `MCP-AUTH-LAB-022`, a deliberate over-budget fixture, is refused at load. No authorization could grant it, because no digest exists.
- `metadata_for_another_resource_fails_resource_binding`: PRM names another resource. **FAIL**, and the reason names the two differing opaque ids.
- `an_issuer_that_is_not_the_advertised_server_fails_issuer_binding`: AS metadata names a different issuer. **FAIL**, "not advertised by the protected resource".
- `missing_metadata_is_never_a_pass`: a 404 gives no PASS, and the AS is not fetched.

## Ralph Loop

- `cargo clippy -p dare-remote-validation --all-targets --features lab -- -D warnings` green
- `cargo test -p dare-remote-validation --test mcp_auth_live`: 4 passed
