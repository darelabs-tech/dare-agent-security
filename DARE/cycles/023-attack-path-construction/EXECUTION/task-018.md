# task-018 — Implement `facts.rs` and the `guard_table.rs` verdict rule

**Status:** DONE  
**Complexity:** HIGH

## Change

- **`facts.rs`:**
  - `NodeRef` (type plus local id), `FactNode`, `FactAuthority` (principal and credential
    as `NodeRef`s), `FactGuard`, `FactEdge`, `Designation` (Entry or Target), `RunFacts`;
  - `FactSink` keys nodes by `NodeRef`. On a second sighting it ORs the security flags
    and keeps the first label and locator;
  - `observed(ids)` and `statically_proven(engine, digests)` build the AD-09 evidence
    (`input:<engine>:<hex>`).
- **`guard_table.rs`:**
  - `Role` has 28 variants, and `properties(role)` is the closed table of BLUEPRINT
    §6.1–§6.9;
  - `MULTI_TURN_DELEGATED` lists the two owning properties a 021 finding may name;
  - `RunVerdicts` implements §6.11:
    - the RUN verdict is the worst verdict over the run's records for that property
      (REGRESSION R-7);
    - a FAIL whose violations name entities stays FAIL on edges touching them and becomes
      INCONCLUSIVE (ENTITY scope) on other guarded edges;
    - a FAIL naming no entity stays RUN scope;
    - a property with no records attaches no guard, so the edge stays `UNASSESSED`.

## Tests (`guard_table.rs` unit tests)

- `every_guard_property_exists_in_the_registries`: every property of all 28 roles, plus
  the delegated list, is in `REGISTRY_JSON` or `AGENTIC_REGISTRY_JSON`.
- `run_scope_applies_the_decided_verdict_and_skips_undecided_properties`.
- `a_failure_naming_an_entity_fails_only_that_entitys_edges`.
- `a_failure_naming_no_entity_stays_run_scoped`.
- `narrowing_never_improves_a_verdict_beyond_inconclusive`: narrowing never produces PASS.
- `delegated_failures_attach_only_to_their_entity_and_role`.

## Ralph Loop

Green: fmt, clippy `-D warnings`, `cargo test -p dare-attack-path` (60 tests).
