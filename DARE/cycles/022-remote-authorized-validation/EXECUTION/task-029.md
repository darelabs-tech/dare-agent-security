# task-029 — Implement the A2A card and exchange projection into STATIC documents

**Status:** DONE (with two recorded deviations)  
**Complexity:** HIGH

## Result (`engines/a2a.rs`)

**Live pass.** `live` fetches the Agent Card, sends one probe and, when a task comes back,
requests its status.

- The probe text is the A2A-LAB scenario's own `description`. That is the only
  pre-approved text an A2A-LAB entry carries, and it is part of the digest-pinned
  scenario.
- JSON-RPC ids are fixed (`PROBE_ID`, `TASK_ID_REQUEST`), so the verdict pass matches
  replies from the capture alone.

**Verdict pass.** `verdict`:
1. projects the capture into `remote-card.json`, `remote-trace.json` and `remote-peers.json`;
2. copies the operator's local policy to `remote-policy.json`;
3. derives a STATIC scenario (same id, class and invariant) naming exactly the files that exist;
4. runs the engine's `StaticAdapter`;
5. removes the work directory.

- **Projections.** `project_card` covers every row of BLUEPRINT §6.1, for both the 0.3-era
  (`url`/`preferredTransport`/`additionalInterfaces`) and 1.0 (`supportedInterfaces`)
  shapes. `project_exchange` covers §6.2 and leaves the seven non-observable fields
  empty (`NOT_OBSERVABLE`).
- **Unusable cards.** A card that cannot be projected (unknown transport or scheme, no
  `name`) is a `ProtocolViolation` transport outcome, and no card document is written.

## Deviations (recorded in REGRESSION.md)

1. **`card_id` is the peer id, not `card-<hex>`.** The engine binds a card to its peer by
   `card_id == peer_id` (`dare-a2a-security/src/normalize.rs:77`). With a different id,
   the card was never bound and discovery binding could not be decided.
2. **`endpoint_identity` is `host[:port]`, not the origin URL.** The engine refuses a
   URL-shaped identity ("a location belongs in a reference field"). The first lab run
   produced ERROR for all 64 scenarios because of this. The test that should have caught
   it only checked `synthetic == false`, so it now also asserts that no projection is
   ERROR.

## Tests

- **Unit:**
  - `a_0_3_card_projects_every_blueprint_row`: all 7 scheme kinds, 2 interfaces, skills requirements, extensions, signature `INDETERMINATE`, push flag, and `validate()` accepted by the engine
  - `a_1_0_card_with_supported_interfaces_projects`
  - `unknown_transports_and_schemes_are_protocol_violations`
  - `exchanges_leave_non_observable_fields_empty`: the engine's `validate()` accepts the exchange
- **Lab** (`tests/a2a_live.rs`):
  - `every_a2a_lab_scenario_decides_from_a_live_capture_without_synthetic_evidence`: all 64 A2A-LAB scenarios over one live capture. Every result has `synthetic: false`, no result is ERROR, all evidence validates, invariants needing non-observable facts are never PASS, and the work directory is removed. All 64 are INCONCLUSIVE for a compliant agent with an otherwise empty policy.
  - `a_card_from_an_unexpected_provider_fails_discovery_binding_and_its_twin_does_not`: a card whose provider differs from the policy's `expected_provider` gives **FAIL** (2 violations). The twin with the expected provider gives INCONCLUSIVE, never PASS.

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets --features lab -- -D warnings` green
- `cargo test -p dare-remote-validation`: green
