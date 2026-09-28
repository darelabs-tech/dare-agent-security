# Cycle 022 — Proof

**Cycle status:** COMPLETE — pending human final review  
**Baseline:** `main @ b6f14b9` (3 955 tests) → Cycle 022 head (see §8 for measured totals)

Every acceptance item below maps to a test or a command that was **executed**.
`python scripts/k22/verify_proof_citations.py` checks that every test name cited
here exists.

## 1. Objectives (DESIGN §2)

| # | Objective | Evidence |
|---|---|---|
| O-01 | No egress outside the authorization | `remote_lab_017_a_redirect_off_origin_kills_and_reaches_nothing` (0 hits on the redirect target), `remote_lab_018_a_metadata_address_is_refused_before_connecting`, `remote_lab_019_a_mixed_answer_is_refused_before_connecting`, `remote_lab_021_a_changing_answer_is_never_followed`, `remote_lab_022_an_ipv4_mapped_private_address_is_refused`, `remote_lab_014_an_off_origin_authorization_server_is_never_fetched`, `the_card_url_never_redirects_the_client`, `proxy_variables_pointing_at_a_dead_port_do_not_affect_the_gateway` |
| O-02 | Fail-closed authorization, 0 bytes | `remote_lab_031_an_unsupported_version_is_refused` … `remote_lab_036_a_policy_outside_the_policy_dir_is_refused` (each asserts 0 lab hits and nothing written); `rule_01_to_16_each_refuse`, `rule_06_a_forbidden_literal_is_refused`, `rule_12_a_plan_bound_to_another_authorization_is_refused`, `rule_14_an_ungranted_scenario_is_refused`, `rule_15_a_confirmation_for_another_origin_is_refused`, `window_edges_not_before_is_allowed_and_not_after_is_refused`; `a_refused_authorization_sends_nothing`; CLI `a_refusal_exits_3_and_writes_nothing`; the in-image binary exits 3 with networking disabled (task-040) |
| O-03 | Replay equivalence | every one of the 30 non-refusal REMOTE-LAB entries asserts byte-identical replay (`Lab::decided` in `tests/remote_lab.rs`); `a_live_run_and_its_replay_are_byte_identical_and_the_artifacts_are_clean`; `ten_replays_of_one_capture_are_byte_identical`; CLI `replay_capture_reproduces_the_committed_result_byte_for_byte` |
| O-04 | No false PASS from transport | `no_transport_outcome_can_produce_pass` (10 outcomes × 4 verdicts); `remote_lab_023_a_server_error_is_never_a_pass`, `remote_lab_024_rate_limiting_is_never_a_pass`, `remote_lab_025_a_closed_port_is_an_error`, `remote_lab_026_an_oversize_reply_is_never_a_pass`, `remote_lab_027_a_reply_outside_the_contract_is_never_a_pass`, `remote_lab_020_a_certificate_for_another_name_is_an_error`, `a_reply_slower_than_the_read_timeout_is_a_timeout_never_a_pass`, `a_budget_stop_leaves_the_running_scenario_inconclusive_never_pass` |
| O-05 | Secret hygiene (0 canary occurrences) | `remote_lab_028_an_echoed_credential_kills_and_leaves_no_trace` (all five artifacts and the error display), `remote_lab_029_a_base64_echo_is_scrubbed_and_kills`, `remote_lab_030_credential_shapes_are_scrubbed_without_a_kill`, `a_credential_echoed_in_the_challenge_header_is_scrubbed_and_kills`, `an_echoed_credential_is_scrubbed_and_kills_the_run`; every `Lab::decided` entry checks every artifact for the token; `scripts/k22/assert_no_real_credentials.py` |
| O-06 | Budget and rate | `at_two_per_second_consecutive_requests_are_at_least_500_ms_apart`, `requests_are_spaced_by_the_rate_limit` (measured by the lab server), `request_501_is_never_admitted`, `the_request_after_the_budget_is_never_sent`, `the_duration_limit_stops_the_run_before_the_next_slot` |
| O-07 | Detection parity (live verdict = offline verdict) | 15 parity tests in `tests/engines_live.rs`: 11 multi-turn scenarios and 4 prompt-injection scenarios, where the lab answers exactly as the engine's simulated agent did offline; `a_live_run_and_its_replay_are_byte_identical_and_the_artifacts_are_clean`; A2A `remote_lab_001_card_from_an_unexpected_provider_fails` / `remote_lab_002_card_from_the_expected_provider_never_fails`, `remote_lab_003_a_leak_across_conversations_fails_over_a2a`; MCP `remote_lab_009_metadata_for_another_resource_fails` / `remote_lab_010_metadata_for_this_resource_never_fails`, `remote_lab_011_an_unadvertised_issuer_fails` / `remote_lab_012_an_advertised_issuer_never_fails` |
| O-08 | Compatibility | `every_engine_no_network_test_is_unchanged` (7 engines, pinned to `b6f14b9`), `the_registry_and_every_profile_are_byte_for_byte_unchanged`, `dare_adversarial_still_refuses_non_local_execution`, `no_engine_crate_depends_on_this_crate`; `cargo test --workspace` green (§8) |
| O-09 | Evidence-bridge correctness | `every_record_of_every_bridge_is_valid_cycle_001_evidence` (1 882 records, 29 of 36 bridge × verdict cells; see REGRESSION §2), `every_engine_bridge_validates_before_returning` |

**Where a secure twin can only reach INCONCLUSIVE.** For some properties, secure twins
over A2A or MCP give INCONCLUSIVE rather than PASS, because the facts those properties
need are not observable remotely:
- `remote_lab_004_the_isolated_twin_never_fails_and_never_passes_over_a2a`;
- `every_a2a_lab_scenario_decides_from_a_live_capture_without_synthetic_evidence`;
- `coherent_metadata_never_fails_any_mcp_auth_lab_scenario` (34 decided: 4 PASS, 30 INCONCLUSIVE, no FAIL).

The concept page and every summary state this.

## 2. Functional requirements (DESIGN §4)

| ID | Requirement | Evidence |
|---|---|---|
| RF-01 | Authorization document | `every_embedded_schema_compiles_and_self_describes`, `the_embedded_copies_equal_the_files_on_disk`, `well_formed_documents_are_admitted`, `oversize_and_deep_documents_are_refused_before_parsing`, `every_forbidden_field_name_is_refused_in_any_case`, `a_consistent_lab_authorization_verifies` |
| RF-02 | Fail-closed check before any DNS or socket | `rules_run_in_order`, `rule_01_version` … `rule_16_credential` (unit tests, one per rule); `rule_01_to_16_each_refuse`; `a_resolution_to_a_forbidden_address_sends_nothing` |
| RF-03 | Operator confirmation | `rule_15_confirmation`, `rule_15_a_confirmation_for_another_origin_is_refused`, `remote_lab_034_a_confirmation_for_another_origin_is_refused`; no `--yes` (`the_help_offers_no_flag_that_could_widen_scope`) |
| RF-04 | Egress gateway | `a_request_reaches_the_authorized_path_with_only_the_fixed_headers`, `a_redirect_is_not_followed_and_kills_the_run`, `a_certificate_for_another_name_is_a_tls_error`, `a_pinned_hostname_is_used_for_every_request`, `a_permitted_answer_is_pinned_and_a_changed_answer_is_never_seen`, `the_172_16_slash_12_boundaries`, `every_row_of_the_table`, `an_oversize_request_is_refused_before_anything_is_sent`, `an_oversize_response_is_dropped_and_never_captured` |
| RF-05 | Budget, rate limit and kill switch (Cycle 009) | `the_budget_is_derived_from_the_limits`, `kill_triggers_latch_and_block_the_next_send`, `instability_triggers_after_three_or_on_first_fail`, `the_operator_stop_flag_blocks_the_next_send`, `no_request_leaves_after_the_window_closes` |
| RF-06 | Closed wire protocols | `a2a_card_message_and_task_round_trip_with_version_selected_names`, `every_mcp_method_round_trips_in_json_and_event_stream_form`, `a_conversation_turn_round_trips`, `a_method_outside_the_plan_is_refused_before_anything_is_sent`, `a_method_outside_the_plan_is_refused_by_the_gateway_not_the_client` |
| RF-07 | Pre-approved payloads only | `rule_14_scenarios` (digests by the engines' own `EngineDigests`); `a_resource_or_prompt_the_server_never_listed_is_not_requested`; prompt-injection parity asserts that the sent `content` is the vector payload byte for byte |
| RF-08 | Chained capture | `push_chains_and_verify_accepts`, `a_one_byte_change_is_detected_at_its_entry`, `gaps_duplicates_and_reorders_are_detected`, `the_seed_binds_the_authorization_plan_and_origin`, `every_field_of_every_entry_is_bound_by_the_chain` |
| RF-09 | Offline verdict by the owning engine | `transcript`/`verdict` conversions exercised by all 15 `engines_live.rs` parity tests, `every_a2a_lab_scenario_decides_from_a_live_capture_without_synthetic_evidence`, `coherent_metadata_never_fails_any_mcp_auth_lab_scenario`; the only local rule is `final_verdict` (transport overlay) |
| RF-10 | Credential by reference | `rule_16_credential`, `remote_lab_035_a_missing_credential_is_refused`; the scrubber unit tests; O-05 above |
| RF-11 | Transport outcomes never PASS | `the_blueprint_table`, `no_transport_outcome_can_produce_pass`, `a_fail_is_never_lowered`, `statuses_map_to_outcomes` |
| RF-12 | CLI | `the_help_offers_no_flag_that_could_widen_scope` (17 forbidden flags, each also fails to parse), `a_raised_limit_is_refused`, `replay_capture_refuses_a_tampered_capture_and_writes_nothing` |
| RF-13 | Artifacts through the output ledger | `admitted_bytes_are_scrubbed_and_counted`, `the_write_that_would_exceed_the_budget_is_refused_and_not_charged`, `a_retagged_record_is_a_protocol_response_with_provenance_and_still_valid`; five files in `replay_capture_reproduces_the_committed_result_byte_for_byte` |
| RF-14 | Audit record | `a_consistent_record_verifies_against_its_capture`, `a_changed_or_removed_event_breaks_the_chain`, `totals_must_describe_the_capture`, `a_changed_audit_or_a_changed_header_is_refused`; stop and kill events asserted by REMOTE-LAB 017, 018 and 028 |
| RF-15 | REMOTE-LAB (≥ 30, every class with a control) | `the_corpus_meets_its_class_contract` (36 entries) |
| RF-16 | Coverage (SHOULD) | **Not implemented**; see REGRESSION §5 |
| RF-17 | Conversational HTTP adapter | `the_request_validates_and_reveals_nothing_about_the_test`, `echo_mismatch_unknown_fields_and_garbage_are_protocol_violations` |
| RF-18 | Cycle 009 compatibility | `dare_adversarial_still_refuses_non_local_execution` |
| RF-19 | Continuous boundary | `nothing_continuous_or_adversarial_depends_on_this_crate` |
| RF-20 | Evidence-bridge correction | O-09; the three updated assertions in REGRESSION §1 |

## 3. Design §4.5 and §4.6 corpora

Each row maps to REMOTE-LAB entries, named `remote_lab_NNN_*`:

| Design row | REMOTE-LAB entries |
|---|---|
| A2A | 001–008 |
| MCP | 009–016 |
| Egress hostility | 017–022 |
| Transport | 023–027, plus the read-timeout gateway test |
| Credential | 028–030, plus the header-echo gateway test |
| Refusals | 031–036 |

§4.6 hostile documents:
- `every_refused_shape_is_refused_without_echo`, `control_and_bidi_characters_are_named_by_codepoint`, `control_and_bidi_characters_are_refused_by_codepoint` and `credential_shaped_values_are_refused_but_the_reference_is_not` (origin and field sweeps);
- `rule_07_window_edges`;
- `rule_16_credential`;
- `rule_14_scenarios`;
- `a_raised_limit_is_refused`;
- the admission tests of `source.rs`.

## 4. Non-functional requirements (DESIGN §5)

| ID | Evidence |
|---|---|
| RNF-01 | `ten_replays_of_one_capture_are_byte_identical` |
| RNF-02 | `request_501_is_never_admitted`, `the_duration_limit_stops_the_run_before_the_next_slot`, `every_limit_can_be_lowered_to_one` |
| RNF-03 | `cargo test -p dare-remote-validation --test remote_lab`: 36 entries in about 4 s on loopback |
| RNF-04 | `every_engine_no_network_test_is_unchanged`, `no_engine_crate_depends_on_this_crate` |
| RNF-05 | stop reasons asserted: `COMPLETED`, `FIRST_FAIL` (`after_a_first_failure_later_scenarios_are_never_sent`), `BUDGET_EXHAUSTED`, `TRANSPORT_ERROR`, `KILL_SWITCH`, `WINDOW_EXPIRED` (`no_request_leaves_after_the_window_closes`) |
| RNF-06 | `instability_stops_the_run_on_first_fail`; there is no retry path (the budget declares 0 retries: `a_step_never_declares_a_state_change`) |
| RNF-07 | §8 |

## 5. Security requirements (DESIGN §6)

| ID | Evidence |
|---|---|
| RS-01 | `a_capture_round_trips_through_admission`; depth and schema checks on every reply parser (`echo_mismatch_unknown_fields_and_garbage_are_protocol_violations`, `a_card_needs_a_name_and_must_be_an_object`, `metadata_must_be_an_object`) |
| RS-02 | O-05; `Credential` holds `Zeroizing<String>` and its `Debug` redacts |
| RS-03 | per-send checks in `EgressGateway::send`: `a_method_outside_the_plan_is_refused_before_anything_is_sent`, `the_request_after_the_budget_is_never_sent`, `no_request_leaves_after_the_window_closes` |
| RS-04 | `cargo audit` exit 0; `rcgen` dev-only (task-040) |
| RS-05 | `scripts/k22/assert_no_real_credentials.py`; `no_private_key_is_checked_in_anywhere_in_this_crate` |
| RS-06 | O-01 |
| RS-07 | RF-07 |
| RS-08 | the closed method set has no `tools/call` and no write (`every_mcp_method_round_trips_in_json_and_event_stream_form` covers every MCP method that exists) |
| RS-09 | O-04 |
| RS-10 | O-06, RF-05 |
| RS-11 | RF-08, RF-14 |
| RS-12 | the only socket is `EgressGateway`; `no_engine_crate_depends_on_this_crate` |

## 6. Review decisions (APPROVAL)

| Question | Decision | Evidence |
|---|---|---|
| BQ-1 | live 018 through an additive API | `the_derived_scenario_keeps_only_observed_metadata`; trust class changed by the Product Owner (REGRESSION §3) |
| BQ-2 | PASS relying on self-reports is marked | `a_pass_says_which_target_reported_fields_it_relies_on` |
| BQ-3 | `rcgen` dev-only | `the_cli_never_enables_the_lab_feature`; task-040 |
| BQ-4 | trait doc comments name the exception | task-032 (comment-only diff) |

## 7. Container

The builder-stage `docker build` compiled the whole workspace with Rust 1.88 inside the
image. The in-image `validate remote` refused an expired authorization with networking
disabled: exit 3, nothing written (task-040).

## 8. Measured totals

The completion gate was run on the final cycle tree:

| Check | Command | Result |
|---|---|---|
| Format | `cargo fmt --all --check` | exit 0 |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| Tests | `cargo test --workspace` | **314 suites, 4 209 passed, 0 failed, 4 ignored** (baseline 3 955 / 0 / 3; +254 tests; the added ignored test is the CLI fixture generator) |
| Advisories | `cargo audit` | exit 0 |
| Secrets | `python scripts/k22/assert_no_real_credentials.py` | exit 0 |
| Citations | `python scripts/k22/verify_proof_citations.py` | 128 names, all verified |
| Books | `mdbook build book/en`, `mdbook build book/pt` | both built |
| Canvas | `python scripts/regen-canvas.py --check` | current |
| Offline CLI | the two `remote-validation-2026` CLI steps | replay exit 2, byte-identical; refusal exit 3, nothing written |
| Container | builder-stage image, in-image refusal | see §7 |
