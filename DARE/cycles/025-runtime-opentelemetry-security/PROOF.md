# Cycle 025 — Proof

**Cycle status:** COMPLETE. Review of 2026-09-29: R-9 applied as option (b), R-10 accepted, and R-11
fixed (a jitter-aware Cycle 022 test, with its tree re-pinned). The merge to `main` awaits human approval.  
**Baseline:** `main @ 00e7aff` (347 suites, 4 433 passed, 9 ignored). The Cycle 025
head totals are in §7.

Every acceptance item below maps to a test or a command that was **executed**.
`python scripts/k25/verify_proof_citations.py` checks that every test name cited here
exists.

## 1. Objectives (DESIGN §2)

| # | Objective | Evidence |
|---|---|---|
| O-01 | Detect runtime violations | `every_entry_meets_its_class_contract`: all 20 OTEL-LAB ATTACK entries (B-1…B-6, T-1, T-2) FAIL on their own property, and a FAIL finding cites the evidence span id the fixture names. The per-rule unit tests are listed in §2 (RF-06) |
| O-02 | No PASS from absence | the same test: all 11 GAP entries (sampled-out, dropped attributes, orphan subtree, missing principal, missing tenant, dropped events, hostless client, unnamed tool, unobserved operation, id collision, parent cycle) are INCONCLUSIVE. Also `an_incomplete_trace_makes_passing_ones_inconclusive_never_pass`, `a_span_bound_stop_makes_every_judged_property_inconclusive`, `an_empty_export_judges_nothing_and_is_not_a_pass`, `a_sampled_out_trace_cannot_pass`, `missing_agent_or_tool_name_or_a_gap_is_inconclusive_never_pass`, and the hostile `a_span_flood_stops_at_the_bound_without_overshoot_or_pass` and `a_value_too_long_to_scan_is_never_a_confidentiality_pass` |
| O-03 | Controls stay green | `every_entry_meets_its_class_contract`: all 23 CONTROL entries PASS; `every_attack_theme_has_a_control`, `every_rule_has_an_attack_and_a_control` |
| O-04 | No secret leaves | `no_input_value_reaches_any_artifact_of_any_lab_entry`: every attribute value longer than 3 characters (span, event, resource and scope attributes, nested arrays and kvlists) of 54 lab entries is absent from all 216 rendered artifacts. The check itself is tested by `the_scan_would_see_a_leak`. Also `no_attribute_value_reaches_any_file_or_stdout` (CLI), `records_carry_no_attribute_value_and_neutralize_hostile_keys`, `no_value_and_no_time_stamp_appear`, `secrets_in_values_fail_confidentiality_and_never_reach_an_artifact`, `an_artifact_that_fails_the_output_sweep_is_never_written` |
| O-05 | Telemetry hygiene detected | T-1 ATTACK entries OTL-034/036/038/040/042 (bearer token, credential marker, content under a no-capture policy, e-mail, `authorization` header) FAIL; `every_leak_class_fails_without_echoing_the_value`, `secrets_in_values_fail_confidentiality_and_never_reach_an_artifact` |
| O-06 | Determinism | `ten_file_order_shuffles_give_byte_identical_artifacts` (the whole lab folded into 64 files, all four artifacts); `ten_span_order_shuffles_give_the_same_findings_and_verdicts` (R-8); `two_runs_give_byte_identical_files_whatever_the_file_order` (CLI); `the_summary_does_not_depend_on_file_order`; `file_and_span_order_do_not_change_the_forest` |
| O-07 | Compatibility | `every_attack_path_lab_output_keeps_its_baseline_digest` (the 156 Cycle 023 goldens); `every_blast_radius_lab_scenario_matches_its_expectation`; the BQ-1 pins `the_registry_and_every_profile_are_byte_for_byte_unchanged` and `the_registries_and_every_profile_are_unchanged`; `the_engine_crates_are_unchanged`; `every_pre_025_entry_is_byte_identical`; `no_earlier_profile_denominator_moved`; the full workspace gate (§7) |
| O-08 | Boundedness | `a_hundred_thousand_spans_in_64_files_are_analysed_in_under_ten_seconds`: 100 000 spans, every trace split across 64 files, analysed and rendered in release in **2.57 s** in the gate run (3.84 s earlier; bound 10 s). `the_span_bound_cuts_exactly_at_its_value`: no overshoot |

## 2. Functional requirements (DESIGN §4)

| ID | Requirement | Evidence |
|---|---|---|
| RF-01 | Trace input | `a_span_reads_with_both_time_encodings_and_lowercased_ids`, `any_value_is_a_one_of_with_nested_arrays_and_kvlists`, `events_links_status_and_dropped_counts_are_read`, `unknown_fields_below_the_top_level_are_counted_and_the_top_level_is_closed`, `every_malformed_field_is_refused_with_its_rule`, `the_trace_schema_and_the_reader_agree`, `admission_refuses_links_size_depth_and_garbage`, `the_total_budget_refuses_one_byte_over` (R-2) |
| RF-02 | Semantic conventions | `the_embedded_mapping_loads_with_its_pins`, `every_kind_is_recognized_from_the_mapping_alone`, `anything_else_is_unrecognized_never_guessed`, `a_malformed_mapping_is_an_internal_error` (R-1) |
| RF-03 | Runtime policy | `a_valid_policy_loads_with_a_canonical_digest`, `every_policy_rule_refuses_with_its_reason`, `egress_patterns_match_exact_hosts_and_strict_subdomains`, `the_file_loader_admits_before_parsing`, `every_policy_refusal_exits_3` |
| RF-04 | Trace reconstruction | `a_tree_links_children_and_orders_by_start_then_id`, `orphans_are_found_and_the_trace_is_not_sound`, `identical_duplicates_across_files_are_removed_and_conflicts_are_marked`, `cycles_depth_and_time_inversions_are_detected`, `id_collisions_are_deduplicated_or_marked_never_merged`, `parent_cycles_and_overdeep_trees_terminate_as_gaps` |
| RF-05 | Completeness signals | `a_complete_trace_has_no_gap`, `every_gap_reason_is_found`, `a_one_of_key_need_is_met_by_any_member`, `defects_on_spans_the_property_does_not_read_do_not_count` (R-3) |
| RF-06 | Behaviour properties | B-1 `an_allowed_tool_passes_and_a_disallowed_one_fails`, `an_unknown_agent_fails_and_an_mcp_tools_call_counts`; B-2 `an_approval_before_the_destructive_call_passes`, `no_approval_a_late_approval_or_another_tools_approval_fails`, `dropped_events_or_no_approval_config_make_it_inconclusive`; B-3 `a_constant_declared_principal_passes`, `a_tool_under_another_principal_fails`, `without_a_declared_principal_the_outermost_agent_sets_it` (R-4); B-4 `retrieval_in_the_agents_tenant_passes_and_another_tenant_fails`, `memory_operations_judge_the_memory_property_only`, `a_missing_tenant_is_inconclusive`; B-5 `url_hosts_are_parsed_without_userinfo_port_or_path`, `allowed_hosts_pass_and_others_fail`, `a_hostless_client_is_inconclusive_and_one_outside_any_agent_is_not_egress`; B-6 `one_retry_after_an_error_is_within_a_bound_of_one`, `two_retries_after_errors_exceed_a_bound_of_one`, `repeated_successful_calls_and_different_targets_are_not_retries`, `a_resend_count_above_the_bound_fails` (R-5) |
| RF-07 | Telemetry confidentiality | `the_local_markers_equal_the_products`, `a_clean_trace_passes`, `every_leak_class_fails_without_echoing_the_value`, `content_is_allowed_when_the_policy_says_so`, `a_repeated_resource_leak_is_reported_once_and_oversize_values_are_undecided`, `the_email_shape_is_conservative` |
| RF-08 | Telemetry completeness | `required_operations_with_their_keys_pass`, `a_required_span_missing_its_key_fails`, `a_structural_gap_is_inconclusive_and_no_policy_judges_structure_only`, `a_required_operation_seen_in_no_trace_leaves_completeness_undecided` |
| RF-09 | Property registry | `exactly_two_properties_were_appended_after_the_pre_025_entries`, `every_pre_025_entry_is_byte_identical`, `the_v1_registry_is_unchanged`, `the_predicate_is_declared_in_the_schema_and_is_target_shape`, `the_predicate_gates_both_properties`, `no_pre_025_property_uses_the_new_predicate`, `the_new_properties_are_passive_trace_evidence` (R-7) |
| RF-10 | Modes | `every_recorded_copy_replays_to_the_simulated_result`: the SIMULATED reference writer's exports, recorded and replayed through `read_trace_paths`, give the same result apart from `mode` and `synthetic`. `the_recorded_copies_match_the_writer_byte_for_byte`. The CLI has no mode flag (`help_names_every_flag_and_offers_no_network_or_exec_flag`) |
| RF-11 | OTEL-LAB | `the_lab_has_at_least_forty_uniquely_numbered_entries` (56 entries: 20 ATTACK, 23 CONTROL, 11 GAP, 2 REFUSAL), `every_entry_meets_its_class_contract`, `every_attack_theme_has_a_control`, `the_design_themes_are_all_present`, `no_fixture_states_its_own_outcome` |
| RF-12 | Hostile corpus | `an_oversize_file_and_deep_nesting_are_refused_before_parsing`, `a_span_flood_stops_at_the_bound_without_overshoot_or_pass`, `id_collisions_are_deduplicated_or_marked_never_merged`, `parent_cycles_and_overdeep_trees_terminate_as_gaps`, `hostile_names_never_reach_the_summary_raw`, `secrets_in_values_fail_confidentiality_and_never_reach_an_artifact`, `a_value_too_long_to_scan_is_never_a_confidentiality_pass`, `a_url_in_a_trace_is_never_dereferenced_or_echoed` |
| RF-13 | CLI | `help_names_every_flag_and_offers_no_network_or_exec_flag`, `exit_0_writes_the_four_files_when_every_judged_property_passes`, `exit_2_on_a_violation_or_when_nothing_can_be_judged`, `exit_3_on_a_refusal_writes_nothing`, `exit_1_on_an_internal_write_failure`; the refusal corpus `every_trace_admission_refusal_exits_3_and_writes_nothing`, `the_total_size_limit_is_enforced_across_files`, `every_trace_content_refusal_exits_3`, `bound_and_output_directory_refusals_exit_3` |
| RF-14 | Artifacts | `every_verdict_gives_a_valid_runtime_event_record`, `ids_are_unique_bound_into_the_result_and_stable_across_runs`, `timestamps_are_the_deciding_traces_span_times` (R-6), `the_executions_document_is_passive_trace_evidence`, `counts_verdicts_reasons_and_incomplete_traces_are_reported`, `it_ends_with_the_not_claimed_statements`, `a_conformant_run_passes_and_validates` (result schema), `an_artifact_that_fails_the_output_sweep_is_never_written` |
| RF-15 | Attack-graph projection (SHOULD) | `runtime_telemetry_rows`, `a_runtime_telemetry_bundle_binds_its_policy_by_digest`; the Cycle 023 outputs are unchanged (O-07). **Refined as R-10, accepted at Review:** the relationships come from the pinned policy (`STATICALLY_PROVEN`) and are guarded by the trace verdicts, because RS-02 keeps observed names inside the engine |
| RF-16 | Coverage and profile (SHOULD) | `the_profile_matches_the_approval_exactly`, `every_selected_property_is_registered`, `required_means_every_traced_agent_has_the_surface`, `a_traced_agent_makes_every_required_property_applicable`, `no_earlier_profile_denominator_moved`, `no_earlier_profile_selects_a_cycle_025_property`, `coverage_rows_restate_the_engine_states_without_promotion`, `the_baseline_report_covers_the_nine_properties_of_the_profile` |
| RF-17 | Product integration (COULD) | out of scope for v1 (Q7 (b)) |

## 3. Non-functional requirements (DESIGN §5)

| ID | Evidence |
|---|---|
| RNF-01 Determinism | O-06 |
| RNF-02 Boundedness | `the_maxima_are_the_design_values`, `every_bound_refuses_zero_and_values_above_its_maximum`, `lowering_takes_the_smaller_value`, `the_span_bound_cuts_exactly_at_its_value`, `a_span_flood_stops_at_the_bound_without_overshoot_or_pass` |
| RNF-03 Performance | O-08. The full OTEL-LAB (`otel_lab`, 8 tests including the replay of all 56 recorded copies) runs in about 1.4 s in debug (bound 60 s) |
| RNF-04 Containment | `the_dependencies_are_exactly_the_blueprint_list`, `the_source_reaches_no_socket_process_thread_or_environment`, `only_the_cli_depends_on_this_crate`, `this_crate_declares_no_telemetry_network_or_generation_dependency`, `the_check_catches_a_forbidden_dependency_when_one_is_added` |
| RNF-05 Explainability | FAIL and INCONCLUSIVE: `every_entry_meets_its_class_contract` (the deciding span cited) and the findings file (trace id, span ids, rule, reason codes). PASS: `every_pass_cites_the_spans_that_prove_it`, where the evidence lists the observed span ids per deciding trace (added in task-031) |
| RNF-06 Quality gate | §7. fmt, clippy `-D warnings` and `cargo audit` are clean. `cargo test --workspace` gave 4 585 passed and 1 failed; the failure was a load-sensitive Cycle 022 timing test, fixed as R-11 (test only, tree re-pinned; 0/30 failures under load) |

## 4. Security requirements (DESIGN §6)

| ID | Evidence |
|---|---|
| RS-01 Untrusted input | RF-01, RF-03, RF-12; `every_trace_content_refusal_exits_3`, `every_policy_refusal_exits_3` |
| RS-02 No value leaves | O-04; `fingerprints_separate_kinds_and_values_and_carry_no_value`, `the_raw_value_has_no_serializer_and_no_public_accessor`, `plain_keys_pass_and_others_become_digests`, `no_error_message_echoes_input`; `python scripts/k25/assert_no_real_credentials.py` |
| RS-03 No file outside the paths, no symlink, no URL dereferenced | `admission_refuses_links_size_depth_and_garbage`, `every_trace_admission_refusal_exits_3_and_writes_nothing` (symlink), `every_policy_refusal_exits_3` (policy symlink), `a_url_in_a_trace_is_never_dereferenced_or_echoed` |
| RS-04 No new third-party dependency | task-029: `Cargo.lock` adds only `dare-runtime-telemetry`, and `cargo audit` is clean; RNF-04 |
| RS-05 No secret needed, no environment | `the_source_reaches_no_socket_process_thread_or_environment` (no `std::env`) |
| RS-06 No PASS from absence | O-02 |
| RS-07 Self-reported evidence labelled | every result, evidence record and summary carries the bounded claim ("self-reported … unsigned"): `it_ends_with_the_not_claimed_statements`, `every_verdict_gives_a_valid_runtime_event_record`; `help_names_every_flag_and_offers_no_network_or_exec_flag` checks the help text |
| RS-08 No telemetry, analysis only | `help_names_every_flag_and_offers_no_network_or_exec_flag` (no endpoint, listen, port, collector, OTLP endpoint, header, token or exec flag), `the_job_references_no_secret_no_network_target_and_no_collector`, RNF-04; the in-image run used `--network none` (task-029) |
| RS-09 Hostile names | `names_lose_bidi_control_and_markup`, `hostile_names_never_reach_the_summary_raw`, `a_hostile_missing_key_is_written_as_a_digest` |

## 5. Approval decisions

| Decision | Evidence |
|---|---|
| BQ-1 (a): the pins become the prefix rule (a test-only exception) | task-002; `the_registry_and_every_profile_are_byte_for_byte_unchanged`, `the_registries_and_every_profile_are_unchanged`, `every_pre_025_entry_is_byte_identical` |
| BQ-2 (a): the semantic conventions are pinned | R-1; `the_embedded_mapping_loads_with_its_pins` |
| BQ-3 (a): a local copy of the markers | `the_local_markers_equal_the_products` |
| BQ-4 (a): retry groups by sibling | `repeated_successful_calls_and_different_targets_are_not_retries` |
| BQ-5 (a): exit codes 0/1/2/3 | RF-13 |
| Cycle 024 R-6 decision (c) | `a_lab_shaped_graph_is_analysed_in_under_ten_seconds` now uses a 10 s target and a 20 s ceiling. In the gate run it measured 11.8 s: reported over the target, and passing |
| Cycle 024 CI-trigger decision | R-9 (b): `workflow_dispatch` added to `ci.yml` and `action-e2e.yml`; `types: [opened]` is kept, so the frozen 021/022 trigger tests pass unchanged; `the_workflow_keeps_its_pull_request_opened_trigger_and_earlier_gates` |

## 6. Boundaries

- No engine crate `src/` changed (013–022). The only engine-tree change is the BQ-1
  pin test (`dare-remote-validation/tests/compatibility.rs`); see
  `the_engine_crates_are_unchanged`.
- The 65 pre-existing registry entries and the 11 earlier profiles are byte-identical.
- The Cycle 008, 023 and 024 outputs for existing inputs are unchanged (O-07).
- No third-party dependency was added. No telemetry is emitted, no port is opened and
  no collector is contacted.

## 7. Gate (measured on the Cycle 025 head, rustc 1.98.1)

| Step | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean |
| `cargo test --workspace --no-fail-fast` | **363 suites, 4 585 passed, 1 failed, 12 ignored**. The failure is R-11, since fixed: the test is jitter-aware and fails 0/30 under load. The baseline was 347 / 4 433 / 0 / 9 |
| Release scale tests | runtime telemetry 2.57 s (bound 10 s); blast radius 11.8 s (target 10 s, ceiling 20 s); attack paths 0.85 s |
| `cargo audit` | clean |
| `python scripts/k25/assert_no_real_credentials.py` | clean |
| `python scripts/k25/verify_proof_citations.py` | every cited name verified |
| `mdbook build book/en`, `book/pt` | clean |
| `python scripts/regen-canvas.py --check` | current |
| Builder-stage Docker image and in-image refusal | exit 0, then exit 3 with nothing written (task-029) |
