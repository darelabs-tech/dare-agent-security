# task-003 — Define MCP auth properties and applicability

**Status:** DONE — REVIEW PASS

Add only the MCP authentication/authorization properties and closed applicability predicates required by the approved Design. Preserve existing registry schema compatibility and Cycle 006 denominator semantics. No speculative or untested property may render as SECURE.

## Evidence

Ten additive properties in `schemas/coverage/v1/registry.json` (10 → 20), eleven predicates
in `schemas/coverage/v1/property.schema.json` (9 → 20) and `crates/dare-coverage/src/property.rs`.

`cargo test -p dare-coverage --test mcp_auth_properties` → **12 passed**;
`cargo test -p dare-coverage` → **252 passed, 0 failed** (baseline 233).

Placement: the properties go into the **v1 MCP registry**, not v2. That is why the Agentic
risk-family count stays at ten without any exclusion rule — nothing was added to the
registry that carries families, so nothing could have created an eleventh. Asserted from
the v2 side as well (40 properties, 10 families, no `MCP.AUTH.*` present).

Applicability (AC-08) is the substantive part. Predicates are classified in two groups and
a false predicate means different things in each:

- **target shape** (`mcp_current_protocol_present`, `mcp_http_transport_present`,
  `mcp_auth_flow_present`, `mcp_identity_metadata_present`) → `NOT_APPLICABLE`. A
  stdio-only server has no HTTP authorization surface.
- **control/evidence** (`protected_resource_metadata_present`,
  `authorization_server_metadata_present`, `token_claims_present`, `pkce_context_present`,
  `scope_challenge_present`, `client_registration_present`, `credential_forwarding_present`)
  → `NOT_TESTED`, via the new `Predicate::is_auth_control_evidence()`. These targets *have*
  the auth surface; the control or its evidence is missing, which is a gap. Relabeling it
  `NOT_APPLICABLE` would let a server with no Protected Resource Metadata score identically
  to one that was never in scope.

Both directions are asserted, plus a third test proving a complete target makes all ten
applicable — without it the other two could pass vacuously.

### Existing tests rescoped, and why none was weakened

Six assertions pinned the v1 registry at exactly 10 properties. Each was rescoped from a
count to the invariant it was actually protecting:

| Test | Was | Now |
|---|---|---|
| `property::tests::builtin_registry_loads_and_ids_are_unique` | `len() == 10` | all ten pre-Cycle-018 ids present + uniqueness |
| `agentic::tests::crosswalk_does_not_mutate_legacy_registry` | `len() == 10` | all ten ids present after crosswalk |
| `lib::tests::registry_selection_is_profile_aware` | `len() == 10` | resolves v1 and finds a known property |
| `identity_security_properties::the_v1_registry_did_not_move` | `len() == 10` | no `AGENT.IDENTITY.*` in v1 **and** v1 holds `MCP.*` only |
| `prompt_injection_profile::the_mcp_baseline_is_unchanged` | registry `len() == 10` | **profile** selection `== 10` + report denominator unchanged |
| `prompt_injection_properties::legacy_profiles_keep_their_exact_property_sets` | registry `len() == 10` | profile selection `== 10` + no `MCP.AUTH.*` injected |
| `tool_security_properties::every_existing_profile_keeps_its_exact_property_set` | registry `len() == 10` | profile selection `== 10` |

The registry count never was the invariant. Two of these tests are named for profile
*sets*, and the profile denominator — the number a coverage percentage divides by — is
untouched at 10 and is now asserted directly on the profile and the report rather than
inferred from the registry. The identity-based replacements detect a rename or a removal,
which a count could not.

The v1 property schema gained two status values, `OPEN_PROPOSAL` and `FUTURE`. Additive:
no existing document becomes invalid, and folding an open upstream discussion into `DRAFT`
would erase the distinction this cycle is required to keep.
