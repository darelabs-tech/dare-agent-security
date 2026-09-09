# task-049 — Implement `agentic-a2a-security-2026` profile

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Add the assessment profile for this cycle's twelve properties, and prove no earlier denominator moved.

## Files changed

- `profiles/agentic-a2a-security-2026.json` (new — 12 properties)
- `crates/dare-coverage/src/profile.rs` (`AGENTIC_A2A_PROFILE_JSON`, `agentic_a2a_profile`, the `resolve_profile` arm)
- `crates/dare-coverage/src/lib.rs` (re-export)
- `crates/dare-coverage/tests/a2a_profile.rs` (new, 11 tests)

## The requirement split, and why it is not editorial

Five REQUIRED, seven CONDITIONAL, and the level follows the predicate that gates each property in the v2 registry.

**Gated on an evidence or control predicate → REQUIRED.** `PEER_IDENTITY_BINDING`, `SKILL_AUTHORIZATION`, `TENANT_BOUNDARY`, `PROTOCOL_NEGOTIATION_INTEGRITY`, and `MESSAGE_AUTHENTICITY` (which is gated on nothing beyond the two universal predicates). A deployment that speaks A2A and records no authentication evidence has a **gap**, and the property must stay in the denominator and report `NOT_TESTED`.

**Gated on a target shape → CONDITIONAL.** `DISCOVERY_TRUST_BOUNDARY`, `AUTHORITY_PROPAGATION`, `MESSAGE_CONTEXT_BINDING`, `DATA_SCOPE_BOUNDARY`, `REPLAY_BOUNDARY`, `EXTENSION_TRUST_BOUNDARY`, `PUSH_NOTIFICATION_BOUNDARY`. A deployment that configures no callback genuinely has no callback boundary, and marking push notifications REQUIRED would report a finding against every such deployment — which is how an operator learns to ignore the profile.

`the_requirement_split_follows_the_predicate_that_gates_each_property` derives the expected level from the registry rather than restating the list, so a property whose gating predicate changes fails here instead of silently acquiring the wrong level.

## A defect found while writing the denominator test

`no_earlier_profile_denominator_moved` first asserted that no earlier profile contains any `AGENT.A2A.*` property, and failed: the Cycle 012 `agentic-security-baseline-2026` has selected `AGENT.A2A.MESSAGE_AUTHENTICITY` since that cycle.

That is not a regression — it is the inheritance this cycle is built on. The assertion was wrong, not the profile. It is now split in two:

- `no_earlier_profile_denominator_moved` pins each earlier profile's property count as a **literal**. The first version computed the expected count from the same accessor it then checked, which compares a profile against itself and passes no matter what moves.
- `this_cycles_ten_new_properties_reached_no_earlier_profile` names the ten properties this cycle created and asserts none appears in any of the nine earlier profiles, and separately that the Cycle 012 baseline still selects exactly `AGENT.A2A.MESSAGE_AUTHENTICITY` and nothing more.

That is the actual risk: one of the new properties leaking into an older profile would change that profile's denominator without changing its file, and every assessment already filed against it would silently mean something different.

## Also pinned

- `the_v1_registry_gained_nothing_from_this_cycle` — A2A properties belong to v2; one reaching v1 would change what an MCP-only assessment is measured against.
- `the_cycle_019_profile_is_untouched_and_still_selects_ten_properties` — named separately because it is the profile most likely to be edited by mistake: it is the previous cycle's, it lives in the same directory, and its properties read similarly.
- `the_profile_selects_no_property_outside_the_a2a_namespace` — there is deliberately no top-level `A2A.*` namespace, and this profile does not reach into another cycle's properties to inflate its own coverage.

## Commands executed

```
cargo test -p dare-coverage --test a2a_profile
cargo test -p dare-coverage
cargo clippy -p dare-coverage --all-targets -- -D warnings
cargo fmt --all
```

## Result

11 profile tests passing; the whole `dare-coverage` crate green at 374 tests across 20 binaries; clippy clean.

## Evidence

```
cargo test -p dare-coverage --test a2a_profile
test result: ok. 11 passed; 0 failed; 0 ignored
```

## Review result

**REVIEW PASS**
