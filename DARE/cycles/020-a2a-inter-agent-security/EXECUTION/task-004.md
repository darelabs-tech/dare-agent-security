# task-004 — Add A2A applicability predicates and preserve existing coverage denominators

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Add the eleven predicates the ten new properties gate on, split correctly between *target shape* and *evidence channel*, and prove no earlier denominator moved.

## Files changed

- `crates/dare-coverage/src/property.rs` (11 variants, names, `is_target_shape`, new `is_a2a_evidence`)
- `crates/dare-coverage/src/facts.rs` (11 fields, all `#[serde(default)]`)
- `crates/dare-coverage/src/applicability.rs` (evaluation + the A2A gap branch)
- `crates/dare-coverage/tests/a2a_properties.rs`

## The split, and why it is the whole point

**Four target-shape predicates** (`a2a_exchange_present`, `agent_card_present`, `a2a_extension_present`, `push_notification_config_present`). False means the target has no such surface, and `NOT_APPLICABLE` is honest: a system that configures no push notification genuinely has no callback boundary to answer for.

**Seven evidence-or-control predicates** (`peer_authentication_evidence_present`, `skill_authorization_policy_present`, `task_context_binding_present`, `a2a_tenant_policy_present`, `data_scope_policy_present`, `replay_policy_present`, `protocol_policy_present`). False means the target *has* the A2A surface and the evidence is missing, which is a **gap**. These resolve to `NOT_TESTED`.

Getting this backwards is the failure Cycle 018 acceptance criterion 8 exists to prevent, and it is worth being blunt about why: a deployment that speaks A2A and records no authentication evidence would otherwise score identically to one that speaks no A2A at all. The first has a hole and the second has no surface. Collapsing them lets a target improve its coverage **by collecting less evidence**, and each of these seven is precisely the difference between an authenticated peer and an authorized one.

`a_missing_a2a_control_is_a_gap_and_never_not_applicable` asserts all seven resolve to `NOT_TESTED`. `a_target_with_no_a2a_surface_is_not_applicable` asserts the four shapes resolve to `NOT_APPLICABLE`. `the_evidence_and_shape_classifications_do_not_overlap` asserts no predicate is both — one that was would decide its own meaning from whichever branch ran first, and branch order is an implementation detail.

`a_complete_target_makes_every_a2a_property_applicable` is the control: without it, every assertion above could pass because the predicates were unsatisfiable.

## Commands executed

```
cargo test -p dare-coverage --test a2a_properties
cargo test -p dare-coverage
cargo clippy -p dare-coverage --all-targets -- -D warnings
```

## Result

14 A2A property tests passing; the whole `dare-coverage` crate green (273 tests across 12 binaries); clippy clean after fixing one elidable-lifetime lint.

Every new fact field carries `#[serde(default)]`, so existing serialized facts documents keep decoding unchanged — an existing assessment fixture that predates this cycle is not invalidated by it.

## Evidence

```
cargo test -p dare-coverage --test a2a_properties
test result: ok. 14 passed; 0 failed
```

## Review result

**REVIEW PASS** — predicates added, split asserted in both directions.
