# Cycle 022 — Regression record

Every change to an existing behaviour, every departure from the Design or the
Blueprint, and every defect found and fixed during execution. Each entry names the
task, the files and the test that now holds the line.

## 1. Evidence bridges: INCONCLUSIVE/ERROR records carried an observed decision (tasks 002–004)

**Defect (Design §4.8, confirmed at baseline).** In the A2A, MCP Auth and
supply-chain bridges, INCONCLUSIVE and ERROR records carried
`observed.decision = NotApplicable` against `expected.decision = Deny`. The
Cycle 001 validator rejects that, and none of the three bridges called it.

**Fix.**
- **PASS** ⇒ `Some(Deny)` with the `INVARIANT_HOLDS` result.
- **FAIL** ⇒ `Some(Allow)` with `"invariant-violated"`.
- **INCONCLUSIVE and ERROR** ⇒ `None` / `None`.

This matches the other six bridges.

**Second latent defect.** Validating the corrected records exposed another problem:
`hashes[].value` carried the engine's `sha256:` prefix, which Cycle 001 rejects. The
fix already used by the identity, memory, rag, tool and multi-turn bridges was applied
as `bare_hex`, at:
- `dare-a2a-security/src/evidence_bridge.rs:60`
- `dare-mcp-auth-security/src/evidence_bridge.rs:60`
- `dare-supply-chain-security/src/evidence_bridge.rs:62`

PASS and FAIL records therefore changed in `hashes[].value` only. No verdict, result
artifact, property or coverage number changed.

**Assertions changed:**
- `dare-a2a-security/src/evidence_bridge.rs:448`: renamed from `an_undecided_record_is_not_applicable_and_never_a_pass` to `an_undecided_record_carries_no_decision_and_never_a_pass`
- `dare-mcp-auth-security/src/evidence_bridge.rs:457`: `an_undecided_trial_carries_no_decision_in_either_direction` (body)
- `dare-supply-chain-security/src/evidence_bridge.rs:434`: `an_undecidable_invariant_is_recorded_as_insufficient_evidence_not_as_a_pass` (body)

The Cycle 020 `PROOF.md` cited the renamed A2A test by its old name, which failed `scripts/k20/verify_proof_citations.py` in CI. The citation now names the new test. The row's claim (an undecided record never reaches Cycle 001 as `invariant-holds`) is unchanged.

## 2. O-09 measured as 29 of 36 cells, not "32/32" (task-006)

The Design assumed 8 bridges × 4 verdicts. There are 9 bridges.
`every_record_of_every_bridge_is_valid_cycle_001_evidence` validates **all 1 882
records** from every built-in scenario of all nine engines. That covers 29 of the 36
bridge × verdict cells:

| Engines | Verdicts covered |
|---|---|
| A2A, supply-chain | all four |
| The other seven | PASS, FAIL and INCONCLUSIVE |

The other seven engines produce no ERROR evidence from their built-in scenarios,
because harness errors stop before any artifact is written. In every bridge, ERROR
records are built by the same branch as INCONCLUSIVE records, and that branch is
exercised.

## 3. Product Owner decision: observed MCP metadata is `AUTHENTICATED` (task-030)

BQ-1 approved `SELF_REPORTED` for live metadata. The 018 engine
(`TrustClass::may_establish_identity`) treats anything but `AUTHENTICATED` as a
violation of resource binding and issuer boundary, so every coherent server would
FAIL.

**Decision (2026-09-28): `AUTHENTICATED` via TLS.** Each document arrives over
verified TLS from the exact origin the owner authorized. The content is still the
server's own claim, so every PASS lists `protected_resource_metadata` in
`self_reported_fields`. The `observed.rs` module doc and the concept page state that
the trust class means authentication of origin only.
- **Tests:** `remote_lab_009_metadata_for_another_resource_fails` and `remote_lab_011_an_unadvertised_issuer_fails`, with their twins `remote_lab_010_metadata_for_this_resource_never_fails` and `remote_lab_012_an_advertised_issuer_never_fails`.

## 4. Defects found by this cycle's own tests (all fixed)

| # | Defect | Found by | Fix | Test now holding it |
|---|---|---|---|---|
| 4.1 | **False PASS for multi-turn over A2A.** `multiturn-lab-008` FAILs offline but gave PASS over A2A. A2A carries no refusal, decision, fulfillment, authority or actions, and the engine decided over their defaults. | REMOTE-LAB design probe (task-035) | A multi-turn PASS over A2A is reported INCONCLUSIVE, and its evidence is lowered by `downgrade_pass`. Only a FAIL decided from the text stands. | `remote_lab_008_an_eroding_refusal_over_a2a_is_never_a_pass`, `remote_lab_004_the_isolated_twin_never_fails_and_never_passes_over_a2a` |
| 4.2 | A kill armed by the **last** exchange read as `COMPLETED`: no later send consumed it. | task-035 | `finish` records `KILL_SWITCH` whenever the switch is armed | `remote_lab_017_a_redirect_off_origin_kills_and_reaches_nothing`, `remote_lab_023_a_server_error_is_never_a_pass`, `remote_lab_028_an_echoed_credential_kills_and_leaves_no_trace` |
| 4.3 | TLS and connection failures gave INCONCLUSIVE, not ERROR: the unfinished-run rule ran before the transport overlay. | task-035 | `final_verdict` applies the overlay first (it still never yields PASS) | `remote_lab_020_a_certificate_for_another_name_is_an_error`, `remote_lab_025_a_closed_port_is_an_error`, `a_fail_stands_and_nothing_else_passes_when_unfinished` |
| 4.4 | No `KILL` audit event for status-armed triggers (redirect, instability) | task-035 | `record_kill` on the arming transition | `remote_lab_017_a_redirect_off_origin_kills_and_reaches_nothing` |
| 4.5 | A credential echoed in `WWW-Authenticate` was scrubbed but did not kill | Design §4.5 review (task-040) | header echoes count toward `scrubbed_credential` and trigger `SECRET_DETECTED` | `a_credential_echoed_in_the_challenge_header_is_scrubbed_and_kills` |
| 4.6 | `Mcp-Session-Id` was read but never sent back | `every_mcp_method_round_trips_in_json_and_event_stream_form` (task-025) | the header is inserted on every later MCP request | the same test |
| 4.7 | The Agent Card fetch before an A2A conversation made the multi-turn transcript refuse as tampered | task-035 probe | the transcript takes only turn methods | `remote_lab_003_a_leak_across_conversations_fails_over_a2a` |
| 4.8 | All 64 A2A-LAB projections were ERROR: the engine refuses a URL-shaped `endpoint_identity` | `every_a2a_lab_scenario_decides_from_a_live_capture_without_synthetic_evidence` (task-029) | the identity is `host[:port]`, and the test now asserts that no projection is ERROR | the same test |
| 4.9 | Discovery binding could never be decided: the card's `card_id` did not equal its peer id, so the engine never bound it | task-029 | `card_id` is the peer id (the engine binds by `card_id == peer_id`) | `a_card_from_an_unexpected_provider_fails_discovery_binding_and_its_twin_does_not` |
| 4.10 | 3 of 4 prompt-injection parity runs disagreed: 013 decides from `goal_id`, `emitted_fields` and per-operation decisions, which `dare-conversation` did not carry | `engines_live.rs` (task-027) | three **optional** response fields (see §5) | `pi_001`, `pi_002`, `pi_008`, `pi_010` in `tests/engines_live.rs` |

## 5. Design and Blueprint deviations recorded during execution

| Where | Planned | Delivered | Why |
|---|---|---|---|
| BLUEPRINT §4.9 (task-019) | chain seed `sha256("dare-remote/v1\|" ‖ capture_id)` | the seed also binds the authorization digest, plan digest and origin | a capture cannot be re-attributed to another authorization. `the_seed_binds_the_authorization_plan_and_origin` |
| task-019 | bodies scrubbed | scrubbed **and** control/bidi/zero-width characters replaced | the live pass and the replay read the same text. `control_and_bidi_characters_in_a_response_are_neutralized` |
| BLUEPRINT §4.11 (task-020) | `operator_host` | dropped | it was `None` in v1 and would only ever be a local hostname |
| BLUEPRINT §5.4 (tasks 024, 041) | `message/send`, `tasks/get` | names chosen from the card's `protocolVersion` (`0.*` ⇒ `message/send`/`tasks/get`, otherwise `SendMessage`/`GetTask`) | the pinned A2A version is 1.0.0, but field agents speak both. `method_names_follow_the_declared_version` |
| Closed method set (task-025) | 12 methods | 13: `MCP_INITIALIZED` added | streamable HTTP requires `notifications/initialized`, which carries no data |
| Gateway (task-025) | no response value ever sent back | `Mcp-Session-Id` echoed (1–128 visible ASCII) | servers that assign a session reject later requests without it |
| `dare-conversation` v1 (task-027) | 9 response fields | plus optional `goal_id`, `emitted_fields`, `policy_decisions` | see §4.10. All are target-reported and listed in `self_reported_fields` |
| BLUEPRINT §6.1 (task-029) | `card_id = "card-" + hex` | `card_id = peer_id` | see §4.9 |
| BLUEPRINT §6.2 (task-029) | `endpoint_identity` = origin | `host[:port]` | see §4.8 |
| BLUEPRINT §6 A2A row (task-029) | one message per scenario text probe (≤ 16) | one probe whose text is the scenario's `description` | A2A-LAB entries declare no probe texts; the description is their only pre-approved, digest-pinned text |
| BLUEPRINT §5.2 (task-034) | `run_remote(…, handle)` | plus `sources` and `work_root`; `run_remote_lowered` adds CLI lowering | the engines' scenario files and A2A's scratch directory needed a location |
| BLUEPRINT §5.1 (task-037) | `--max-*` lower the plan | lowered on the **verified authorization** after `verify` | lowering the plan would change its digest and break replay |
| CLI (task-037) | Ctrl-C ⇒ `OperatorStop` | Ctrl-C terminates without writing | the stop flag remains a library entry point (`the_operator_stop_flag_blocks_the_next_send`). Wiring it needs tokio's `signal` feature; recorded as a follow-up |
| BLUEPRINT §7.1 | `Behaviour` enum; `with_lookup` under `cfg(test)` | handler closures; `with_lookup` under `cfg(test)` **or** feature `lab` | integration tests are separate crates and cannot see `cfg(test)`. `the_cli_never_enables_the_lab_feature` keeps the seam out of the binary |
| Design RF-16 (SHOULD) | remote evidence feeds coverage as `Dynamic` | **not implemented** | no coverage file changes in this cycle (`the_registry_and_every_profile_are_byte_for_byte_unchanged`). Recorded as a follow-up |
| Design §4.5, 009–016 | includes "authenticated inventory" | the MCP client supports `initialize`, lists and reads (`every_mcp_method_round_trips_in_json_and_event_stream_form`), but no REMOTE-LAB entry decides an inventory verdict | no engine consumes a live inventory in v1 |
| Design §4.5, 023–027 | timeout and slow drip | the timeout is `a_reply_slower_than_the_read_timeout_is_a_timeout_never_a_pass` (gateway suite); a slow drip is bounded by the same 15 s total timeout, so no separate entry was staged | a slow drip ends as the same `READ_TIMEOUT` |

## 6. Coverage limits (not defects)

- **The peer-address re-check cannot be staged on loopback,** because every peer there
  is `127.0.0.1`. The check runs on every successful exchange, and each one passes
  only because the peer matches the pin (`a_pinned_hostname_is_used_for_every_request`).
- **The full two-stage image cannot be built in this session** (see §7). The runtime
  stage copies the binary that was built and exercised in the builder stage.

## 7. Environment findings (not repository defects)

- **Session disk full (task-038).** The linker died with `Bus error`, and the harness's
  temp filesystem filled. Old test binaries were deleted from `target/debug/deps`.
- **Runtime stage.** Its `apt-get` needs `deb.debian.org`, which the session network
  policy denies. `action-e2e.yml` on the pull request is the authoritative full-image
  check.
- **`mdbook` was not installed.** v0.4.40, the CI's pinned release, was downloaded to
  `~/.local/bin` to build both books.
