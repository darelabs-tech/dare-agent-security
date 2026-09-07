# Cycle 018 — Proof of acceptance

Each of the 76 acceptance criteria in `DESIGN.md` §30 is mapped to **executed
evidence**: a test that ran, a workflow step that ran, or an artifact a run
wrote. Nothing here is satisfied by the existence of code, by design prose, or
by a claim that something looks correct.

Every named test passed in the run recorded in `REGRESSION.md`.

**At merge:** `cargo test --workspace` — 2799 passing, 0 failing; the real
`mcp-auth-security-2026` job — all 27 steps PASSED.

**After the post-merge security review:** 2849 passing, 0 failing; all 31 steps
PASSED. Rows corrected by that review are marked below, and the review itself is
`POST-MERGE-REVIEW.md`. Nothing in the original mapping is deleted — a proof
document edited to hide what it once claimed is not a proof.

Every test name below was checked to exist by matching it against the compiled
test list, not by recollection. Cycle 016 shipped three citations naming tests
that did not exist; that is why the check is mechanical.

Abbreviations: **auth** = `dare-mcp-auth-security`, **cov** = `dare-coverage`,
**cli** = `dare-agent-security`, **job** = a step of the real
`mcp-auth-security-2026` workflow job. A bare `module::name` is an auth unit
test; `file.rs::name` is an auth integration test.

---

## Baseline, revision and standards (1–4)

| # | Criterion | Executed evidence |
|---|---|---|
| 01 | baseline pinned to `f5906e8b…` | `BASELINE.md` records 2442 tests, v1=10/v2=40 properties, 10 families, 7 profiles and 15 CI jobs at that head; `git merge-base --is-ancestor f5906e8b… HEAD` → true. `REGRESSION.md` §1 records that the *local* `main` ref was stale at `09e1279c` and that every count is measured against `f5906e8b…` instead |
| 02 | current MCP revision remains `2026-07-28` | `lib::revision_tests::the_revision_constants_come_from_cycle_002`; `source::revision_classification_follows_cycle_002_rather_than_a_literal`; `compat::the_revision_constants_are_cycle_002s`. The crate holds no literal of its own to compare against — it re-exports Cycle 002's |
| 03 | legacy `2024-11-05` isolated, unsupported revisions fail closed | `source::only_the_current_revision_carries_the_modern_auth_surface`; `protocol::an_unsupported_revision_classifies_closed`; `lab_scenarios.rs::an_unsupported_revision_fails_closed_rather_than_being_evaluated` (lab 002 → FAIL, reason contains "unsupported") |
| 04 | statuses distinguish NORMATIVE/DRAFT/OPEN_PROPOSAL/FUTURE | cov `mcp_auth_security_standards::*` (19 tests) over `PINNED_SOURCE_STATUS`, `assert_no_status_promotion` and `assert_no_conformance_claim`; cov `mcp_auth_properties::the_open_proposal_property_records_its_status_honestly`; `standards/mcp-auth-security/2026/provenance.json` carries 11 sources and a `reverification_note` stating plainly that no upstream re-verification was performed |

## Properties, taxonomy and coverage semantics (5–8)

| # | Criterion | Executed evidence |
|---|---|---|
| 05 | ten exact Cycle 018 properties are additive | cov `mcp_auth_properties::the_ten_approved_properties_exist_and_no_others_were_added`; the v1 registry moves 10 → 20 while v2 stays at 40 |
| 06 | prior MCP property IDs unchanged | cov `mcp_auth_properties::every_property_that_predates_this_cycle_is_unchanged`, `the_new_properties_did_not_enter_the_mcp_baseline_profile`; cov `mcp_auth_profile::the_earlier_v1_profile_keeps_every_requirement_level_it_had` — pinned level by level, because a count alone would not catch OPTIONAL becoming REQUIRED |
| 07 | no Agentic RiskFamily added | cov `mcp_auth_properties::the_agentic_registry_and_its_family_count_are_untouched`, `no_new_property_carries_an_agentic_risk_family`; cov `mcp_auth_profile::the_agentic_risk_families_still_number_exactly_ten`, `the_profile_selects_from_v1_and_not_from_the_agentic_registry`; job *Agentic baseline regression (Cycle 012)* asserts `--count "=10"` on `risk-family-coverage.json` |
| 08 | applicability never turns a missing auth control into NOT_APPLICABLE | cov `mcp_auth_properties::a_missing_auth_control_is_a_gap_and_never_not_applicable`, `a_target_without_the_surface_is_not_applicable`, `every_new_property_declares_at_least_one_target_shape_predicate`; cov `mcp_auth_profile::a_missing_auth_control_is_not_tested_rather_than_not_applicable`, `every_auth_control_predicate_reports_a_gap_when_its_evidence_is_absent` (all seven), `a_target_on_a_legacy_revision_reports_every_auth_property_not_applicable`; job *A missing auth control is a gap, never relabelled NOT_APPLICABLE* asserts `counts.NOT_APPLICABLE=0 counts.NOT_TESTED=10` and job *A target the modern authorization surface does not cover is not a gap* asserts the mirror |

## Schemas and typed evidence (9–21)

| # | Criterion | Executed evidence |
|---|---|---|
| 09 | typed scenario schema exists | `schemas/mcp-auth-security/v1/scenario.schema.json`; `schema::every_compiled_schema_compiles`, `an_unsupported_or_missing_version_is_refused`; `harness::the_fixture_scenario_validates` |
| 10 | typed replay trace schema exists | `trace.schema.json`; `replay::a_well_formed_trace_parses_and_replays`, `a_trace_can_never_declare_a_non_replay_mode`, `a_trace_claiming_production_evidence_is_refused` |
| 11 | typed PRM evidence exists | `metadata::the_fixture_context_validates`, `metadata_binds_the_resource_it_describes`, `a_metadata_document_records_how_much_it_may_be_believed` |
| 12 | typed AS metadata evidence exists | `metadata::the_selected_server_resolves_to_its_own_metadata`, `selecting_a_server_nobody_recorded_resolves_to_nothing`, `too_many_authorization_servers_are_refused_rather_than_truncated` |
| 13 | typed authorization request/response evidence exists | `authorization::a_well_correlated_exchange_holds_on_every_axis`, `a_response_answering_an_undeclared_request_is_refused`, `whether_the_client_accepted_the_response_is_recorded_separately` |
| 14 | typed token claims projection without raw tokens | `token::the_model_has_nowhere_to_put_a_raw_token`, `a_token_for_the_right_resource_binds`, `too_many_audiences_are_refused_rather_than_truncated` |
| 15 | typed PKCE evidence exists | `pkce::a_bound_s256_flow_holds`, `the_model_has_nowhere_to_put_a_raw_verifier`, `a_digest_field_must_actually_be_a_digest` |
| 16 | typed redirect/state evidence exists | `redirect::a_registered_and_undiverted_redirect_holds`, `a_redirect_can_never_be_a_reachable_target`, `too_many_registered_redirects_are_refused` |
| 17 | typed scope step-up evidence exists | `scope::a_step_up_that_widens_holds`, `a_dropped_scope_is_named_rather_than_merely_counted` |
| 18 | typed registration metadata evidence exists | `registration::pre_registered_metadata_may_be_relied_upon`, `a_client_metadata_document_may_be_relied_upon`, `the_legacy_dynamic_path_is_surfaced_but_not_a_violation` |
| 19 | typed credential-flow evidence exists | `credential::distinct_credentials_stay_separate`, `an_authorized_exchange_is_not_forwarding`, `the_model_has_nowhere_to_put_a_secret` |
| 20 | typed self-reported MCP identity metadata exists | `identity::an_authenticated_principal_alongside_self_description_holds`, `self_reported_metadata_cannot_declare_itself_authenticated`, `no_self_description_answers_nothing` |
| 21 | normalized observation model is closed | `observation::the_channel_set_is_closed_at_sixteen`, `every_other_observation_supplies_exactly_one_channel`, `every_observation_digests_deterministically`; `source::every_taxonomy_is_closed_and_uniquely_named`, `an_unknown_token_fails_closed_rather_than_defaulting` |

## The engine cannot judge for itself (22–23)

| # | Criterion | Executed evidence |
|---|---|---|
| 22 | adapters cannot assert a final verdict | `harness::the_adapter_trait_offers_no_way_to_state_a_verdict` — the trait has no such method; `observation::the_event_model_carries_no_verdict_variant`; `simulated::the_adapter_reports_its_mode_and_never_a_verdict`; `invariant::no_evaluator_reads_a_score_or_a_fixture_verdict`; `model::a_scenario_type_has_no_field_for_an_expected_verdict`; `lab_scenarios.rs::no_fixture_can_state_its_own_verdict` |
| 23 | exactly 14 invariants implemented | **Superseded by the post-merge review: there are now 15.** `model::the_fifteen_invariants_are_closed_and_uniquely_named`, `the_approved_invariant_names_are_exactly_these`, `an_unknown_invariant_fails_closed`; `invariant::the_registry_is_closed_at_fifteen`. DESIGN §18 fixed the count at fourteen "unless Review finds a concrete missing security dimension"; the review found one after merge instead — the self-reported metadata boundary was filing findings under `INBOUND_CREDENTIAL_NOT_REUSED_AS_UPSTREAM_AUTHORITY`, an invariant about a different problem. `POST-MERGE-REVIEW.md` §F06 records the change and what it touched |

## Invariant behaviour, PASS and FAIL (24–43)

| # | Criterion | Executed evidence |
|---|---|---|
| 24 | method header/body binding has PASS and FAIL | `protocol::a_routed_method_that_differs_from_the_body_does_not_bind`, `the_fixture_envelope_validates_and_binds`; labs 001 (PASS) / 003 (FAIL) via `lab_scenarios.rs::every_lab_reaches_the_outcome_the_register_approves`; job *Routing that names one operation while the body requests another* asserts exit 2 and `invariant=MCP_METHOD_HEADER_BODY_BINDING_PRESERVED` **Post-merge:** case is no longer folded — `post_merge_regressions::f01_a_case_changed_method_does_not_escape_the_binding_either`, `protocol::no_case_variant_of_a_routing_value_compares_equal`. |
| 25 | name header/body binding has PASS and FAIL | `protocol::a_routed_name_that_differs_from_the_body_does_not_bind`, `a_header_naming_an_operation_the_body_does_not_is_a_mismatch`; labs 001 / 004; same job step asserts `invariant=MCP_NAME_HEADER_BODY_BINDING_PRESERVED` **Post-merge:** `post_merge_regressions::f01_a_case_changed_mcp_name_does_not_escape_the_binding` — `Mcp-Name: DeleteInvoice` against a body executing `deleteinvoice` used to compare equal. |
| 26 | protocol downgrade / unsupported revision fails closed | `lab_scenarios.rs::an_unsupported_revision_fails_closed_rather_than_being_evaluated`; `protocol::an_unsupported_revision_classifies_closed`; `source::only_the_current_revision_carries_the_modern_auth_surface` |
| 27 | PRM resource binding has PASS and FAIL | `metadata::metadata_binds_the_resource_it_describes`; labs 005 / 006 **Post-merge:** provenance now participates — a `SELF_REPORTED` document cannot establish which servers may issue, however consistent its identifiers. `post_merge_regressions::f05_self_reported_resource_metadata_cannot_fabricate_an_authorization_server`. |
| 28 | AS issuer binding has PASS and FAIL | `metadata::selecting_a_server_nobody_recorded_resolves_to_nothing`; labs 007 / 008 **Post-merge:** adds the token-issuer boundary and the trust-class check — `post_merge_regressions::f04_a_token_from_an_unadvertised_issuer_fails_despite_a_correct_audience`, `f05_self_reported_authorization_server_metadata_cannot_establish_itself`, `f05_declared_metadata_is_not_silently_promoted_to_authenticated`. |
| 29 | authorization-response issuer binding has PASS and FAIL | `authorization::a_response_from_another_issuer_breaks_correlation`, `an_absent_issuer_is_nothing_to_compare_rather_than_agreement`; labs 009 / 010; `violations_and_hygiene.rs::a_violation_carries_the_subject_it_is_about` checks the finding names `as-attacker` rather than reporting that an issuer was wrong |
| 30 | token audience/resource binding has PASS and FAIL | `token::a_token_minted_for_another_resource_does_not_bind`, `the_resource_claim_binds_as_well_as_the_audience_claim`; labs 011 / 012; job *A valid token is not a correctly audienced one* asserts exit 2, `class=TOKEN_BINDING`, `mode=LOCAL_SYNTHETIC` **Post-merge:** audience and issuer stay independent findings — `post_merge_regressions::f04_the_issuer_finding_is_independent_of_the_audience_finding`. |
| 31 | missing token-validity evidence is INCONCLUSIVE, not PASS | `token::a_token_with_no_verification_evidence_is_not_evidence_either_way`, `validity_and_binding_stay_independent_questions`; `source::an_unverified_token_is_not_evidence_in_either_direction`; lab 014; job *Silence is inconclusive and never a pass* asserts `verdict=INCONCLUSIVE` **Post-merge:** an examined token is not a favourable one. `REJECTED` and `EXPIRED` tokens that were accepted are now findings, and `UNKNOWN` validity no longer satisfies the coverage contract. `post_merge_regressions::f03_*` (6). |
| 32 | PKCE binding has PASS and FAIL | `pkce::a_bound_s256_flow_holds`, `a_downgrade_to_plain_fails_the_requirement`, `a_verifier_that_does_not_match_its_challenge_breaks_the_binding`; `source::plain_pkce_does_not_satisfy_a_requirement_for_s256`; labs 016 / 017 |
| 33 | redirect/state integrity has PASS and FAIL | `redirect::a_registered_and_undiverted_redirect_holds`, `a_response_diverted_in_flight_is_caught`, `a_client_requesting_an_unregistered_destination_is_caught`; `authorization::a_substituted_state_breaks_correlation`; labs 018 / 019 |
| 34 | scope step-up union semantics has PASS and FAIL | `scope::a_step_up_that_widens_holds`, `a_retry_that_drops_a_previously_required_scope_fails`, `a_widened_retry_may_hold_more_than_required`; labs 020 / 021 |
| 35 | step-up retries are hard bounded | `scope::exceeding_the_retry_ceiling_is_refused_rather_than_clamped`, `the_ceiling_itself_is_still_allowed`; `lib::limits::tests::the_step_up_ceiling_is_small_enough_to_stop_a_loop`; `lab_scenarios.rs::a_retry_past_the_ceiling_is_refused_by_the_schema_before_evaluation` (lab 022, refused before evaluation and therefore never a corpus vector) |
| 36 | registration trust has PASS and FAIL | `registration::pre_registered_metadata_may_be_relied_upon`, `a_client_metadata_document_may_be_relied_upon`, `untrusted_metadata_cannot_manufacture_a_client`; labs 023, 024 / 025 |
| 37 | raw registration metadata cannot manufacture trust | `registration::untrusted_metadata_cannot_manufacture_a_client`, `recording_untrusted_metadata_without_relying_on_it_is_not_a_finding`, `an_unknown_trust_class_fails_closed`, `the_model_has_nowhere_to_put_a_client_secret`; `source::untrusted_registration_is_the_only_class_that_cannot_establish_a_client` |
| 38 | inbound credential separation has PASS and FAIL | `credential::distinct_credentials_stay_separate`, `forwarding_the_inbound_credential_upstream_fails_separation`, `a_rename_does_not_hide_forwarding`, `an_authorized_exchange_is_not_forwarding`; labs 026, 028 / 027; job *An inbound credential is not upstream authority…* asserts exit 2 |
| 39 | raw inbound bearer never appears in persisted evidence | `credential::the_model_has_nowhere_to_put_a_secret` — there is no field; `observation::a_bearer_token_is_masked_while_the_word_stays_writable`, `a_jwt_shaped_value_is_masked`, `an_armoured_key_block_is_masked_whole`; `violations_and_hygiene.rs::no_retained_text_from_any_lab_carries_a_canary_or_a_credential` (all 34 evaluable labs, every retained surface), `the_result_artifact_of_a_failing_run_is_still_secret_safe`; `result::the_artifact_never_carries_a_canary_a_credential_or_a_reachable_target` |
| 40 | self-reported metadata cannot establish authoritative identity | `identity::self_reported_metadata_cannot_declare_itself_authenticated` (no field to set), `deriving_the_principal_from_self_report_fails_the_boundary`, `a_principal_whose_own_trust_is_self_reported_fails_too`, `a_declared_principal_is_not_enough_either`; `lab_scenarios::a_promoted_self_report_fails_the_run_and_not_only_a_field_assertion`, `the_identity_boundary_is_checked_even_when_a_scenario_selects_another_invariant`, `a_scenario_with_no_self_description_is_not_judged_on_a_boundary_it_never_crossed`. **Post-merge:** the finding is now filed under `SELF_REPORTED_METADATA_NOT_AUTHORITY` and the `MCP.IDENTITY.SELF_REPORTED_METADATA_BOUNDARY` property rather than under the credential invariant, and carries the digest of the identity observation that decided it — it shipped with none. `post_merge_regressions::f06_*`, `f07_*`; job *A promoted self-report is reported under its own invariant*. See `POST-MERGE-REVIEW.md` §F06 and §F07 |
| 41 | Cycle 015 principal semantics reused | `identity::principal_kinds_come_from_cycle_015` — re-exported, and this crate adds no variant; `compat::principal_kinds_are_cycle_015s_and_this_cycle_adds_none` |
| 42 | Cycle 003 final-operation binding reused | **This row was false at merge and is corrected here.** `src/compat.rs` did not call `compute_authorization_binding`, and `changed_operation_fields` is a fixture helper mapping Cycle 003's own mutation kinds to field names — not a general comparison, so it could not have done the job it was credited with. The module compared `method`, `name` and `resource` with its own string comparison. It now assembles a `BindingMaterialV1` per end via `binding::binding_material_v1` and `canonical::CanonicalValue::normalize`, and the decision is `binding::bindings_equal` over `binding::compute_authorization_binding`. Evidence: `compat::the_decision_comes_from_cycle_003_rather_than_a_local_comparison`, `post_merge_regressions::f02_the_decision_is_taken_by_cycle_003`; job *Cycle 001 evidence, Cycle 002 revision and Cycle 003 integrity regressions*. See `POST-MERGE-REVIEW.md` §F02 for the exact API table |
| 43 | auth-relevant post-permit mutation re-evaluates or refuses | **Widened by the post-merge review.** At merge only `method`, `name` and `resource` were compared, so a permit for `payments.send(amount=100)` covered `amount=10000`. The binding now spans mapped `arguments`, `principal`, `tenant` and `scopes` as well. Evidence: `compat::a_mutated_argument_is_authorization_relevant`, `a_mutated_principal_is_authorization_relevant`, `a_mutated_tenant_is_authorization_relevant`, `a_mutated_scope_set_is_authorization_relevant`, `a_case_changed_operation_name_is_authorization_relevant`, `key_order_in_arguments_is_not_a_change`, `several_changes_are_all_reported`; `post_merge_regressions::f02_*` (8, including the re-evaluated and refused controls); labs 031, 032 / 033; job *A permit does not survive the operation changing under it* |

## Coverage, silence and multiple violations (44–47)

| # | Criterion | Executed evidence |
|---|---|---|
| 44 | PASS requires positive invariant-specific evidence | `coverage::the_contract_is_total_over_the_fifteen_invariants`, `an_empty_run_satisfies_no_contract`, `a_run_of_only_harness_errors_satisfies_no_contract`, `an_unrelated_observation_does_not_satisfy_a_contract`, `the_did_something_invariants_require_an_exercise_channel`, `naming_an_invariant_as_exercise_requiring_matches_its_actual_contract`; `lab_scenarios.rs::a_pass_never_rests_on_an_empty_observation_set` **Post-merge:** a trial stopped by a hard bound before its evidence was complete reports INCONCLUSIVE — `post_merge_regressions::f08_a_budget_that_stopped_the_evidence_never_yields_pass`. |
| 45 | missing required channels produce INCONCLUSIVE | `coverage::one_side_of_a_two_sided_question_is_not_enough`, `seeing_metadata_is_not_the_same_as_running_a_flow`, `a_decision_reports_what_was_missing_and_why`; `invariant::an_empty_observation_set_is_inconclusive_for_every_invariant`; labs 014 and 035; `result::an_inconclusive_claim_says_it_is_not_a_pass`; job *Silence is inconclusive and never a pass* |
| 46 | independent simultaneous violations are retained | `violations_and_hygiene.rs::three_simultaneous_violations_are_all_reported_from_one_trial` (lab 034 breaches issuer, audience and credential separation at once), `evaluating_one_invariant_never_consumes_or_hides_another` (order independence), `an_invariant_the_flow_did_not_breach_stays_independently_judged`, `every_violation_names_the_evidence_that_decided_it`; `lab_scenarios.rs::the_multi_violation_lab_crosses_three_boundaries_at_once`; `invariant::a_violation_is_reported_even_when_another_channel_is_missing` |
| 47 | stop_on_first_fail cannot discard same-trial violations | `violations_and_hygiene.rs::stopping_on_first_fail_never_discards_the_evidence_that_caused_it`; `result::stopping_on_first_fail_keeps_the_failing_trials_evidence`. The stop is a decision about *later* trials; the failing trial's record is pushed before the stop is taken |

## Offline boundary and bounds (48–53)

| # | Criterion | Executed evidence |
|---|---|---|
| 48 | only REPLAY/SIMULATED/LOCAL_SYNTHETIC modes exist | `harness::there_is_no_remote_or_live_mode`; cli `mcp_auth_security::tests::the_mode_enum_admits_only_the_three_local_modes` (rejects `live`, `remote`, `http`, `production`, `oauth`, `interactive`, `browser`) |
| 49 | no live OAuth/OIDC/IdP/MCP auth mode exists | the above, plus cli `the_prohibited_endpoint_and_credential_flags_do_not_exist` (23 flags) and `the_command_exposes_exactly_the_six_approved_flags`; `lib::revision_tests::this_crate_declares_no_transport_dependency_of_its_own` checks the manifest against 14 transport/OAuth/JWT crate names, and `the_only_cycle_002_reference_is_the_revision_constants` scans the crate's own source so nothing can reach the one transitive stack. `REGRESSION.md` §4.2 records that the earlier "not even transitively" wording was an overclaim and was corrected rather than defended |
| 50 | external egress budget is zero | `trials::a_plan_records_zero_state_changes_and_zero_egress`; `result::the_result_records_zero_state_changes_and_zero_egress`; `local_synthetic::the_budget_pins_state_changes_and_egress_to_zero`; `lib::limits::tests::the_zero_bounds_are_zero_and_stay_that_way`; every job CLI step asserts `budget.external_egress_bytes=0` on the written artifact |
| 51 | state-change budget is zero | the same four tests and the same job assertions on `budget.state_changes=0` |
| 52 | run-wide request/trial counters are hard bounded | `trials::run_wide_request_totals_do_not_reset_between_trials` (a counter that resets is not a bound), `the_per_trial_request_bound_is_enforced_too`, `retained_bytes_are_bounded_per_trial_and_per_run`, `a_ledger_stops_offering_trials_once_the_plan_is_done`; `lib::limits::tests::the_approved_bounds_are_exactly_what_design_records`, `per_trial_bounds_never_exceed_run_wide_ones` **Post-merge:** the bound now governs what is *kept*, not only what is counted — `post_merge_regressions::f08_accounted_bytes_are_the_bytes_actually_persisted`, `f08_persisted_bytes_stay_inside_both_hard_bounds`. |
| 53 | over-limit input is refused, never upward-clamped | `trials::an_over_bound_trial_count_is_refused_rather_than_clamped`, `a_zero_trial_count_is_refused`, `an_override_is_refused_above_the_crate_hard_maximum`, `clamping_to_an_available_source_only_reduces`; `scope::exceeding_the_retry_ceiling_is_refused_rather_than_clamped`; `metadata::too_many_authorization_servers_are_refused_rather_than_truncated`; `token::too_many_audiences_are_refused_rather_than_truncated`; `redirect::too_many_registered_redirects_are_refused`; `replay::an_over_bound_trace_is_refused`; cli `the_trial_count_cannot_exceed_the_hard_maximum` **Post-merge:** `--trials` may narrow what a scenario approved and never widen it — `trials::an_override_can_never_widen_what_a_scenario_approved`, `post_merge_regressions::f09_*`. |

## Fail-closed parsing (54–57)

| # | Criterion | Executed evidence |
|---|---|---|
| 54 | raw bearer/refresh/code/secret/key/cookie fields refused or redacted before persistence | `schema::a_credential_field_is_refused_at_any_depth`, `a_credential_field_is_refused_even_when_empty` (the field is what is wrong), `a_credential_shaped_value_is_refused_wherever_it_appears`, `every_credential_marker_is_lowercase`, `prose_about_credentials_stays_writable`, `a_short_bearer_like_string_is_not_treated_as_a_credential`; `hostile_fixtures.rs::a_credential_field_is_refused_whatever_it_holds`; `observation::evidence_text_is_masked_at_construction_rather_than_on_the_way_out` |
| 55 | executable/callback/command fields are refused | `schema::an_executable_or_remote_field_is_refused`; `protocol::the_envelope_rejects_unknown_and_executable_fields`; `model::a_scenario_type_has_no_field_for_an_expected_verdict` and `schema::a_verdict_field_is_refused` for the verdict-injection case |
| 56 | live endpoint / network instructions are refused | `schema::a_reachable_target_is_refused_by_value_even_in_an_allowed_field`; `protocol::a_synthetic_identifier_can_never_be_a_reachable_target`; `metadata::metadata_cannot_name_a_reachable_endpoint`; `redirect::a_redirect_can_never_be_a_reachable_target`; `registration::registration_cannot_name_a_reachable_redirect`; `hostile_fixtures.rs::a_registry_path_that_could_escape_the_root_is_refused`, `a_trace_cannot_claim_a_live_mode_or_production_evidence`; `violations_and_hygiene.rs::no_retained_observation_names_a_reachable_target` |
| 57 | hostile control/bidi/path-traversal identifiers are refused | `canonical::an_identifier_that_could_forge_a_log_line_is_refused`, `an_identifier_that_could_deceive_a_reader_is_refused`, `an_identifier_shaped_like_a_path_is_refused`, `an_empty_or_oversized_identifier_is_refused`, `padding_is_refused_because_it_makes_lookalikes_compare_differently`, `ordinary_identifiers_stay_usable`; `schema::a_control_character_is_refused_wherever_it_appears`, `a_newline_stays_allowed_in_free_form_text`, `deeply_nested_documents_are_refused_rather_than_recursed`, `an_oversized_document_is_refused_before_it_is_parsed`; `corpus::every_traversal_shape_is_refused` |

## Corpus and fixtures (58–60)

| # | Criterion | Executed evidence |
|---|---|---|
| 58 | at least 28 MCP-AUTH-LAB scenarios exist | **35** exist; `lab_scenarios.rs::the_corpus_meets_the_approved_minimum`, `the_register_covers_every_fixture_and_no_fixture_is_unregistered` (no unlisted fixture, no listed file that is absent) |
| 59 | secure/vulnerable pairs cover the critical invariants | `lab_scenarios.rs::the_paired_labs_differ_only_in_the_field_under_test` — one mutation per pair, so a verdict names a cause rather than a difference; `the_labs_between_them_exercise_every_invariant`, `the_labs_between_them_exercise_every_reporting_surface`; 16 benign controls including the second legitimate shape for registration (024) and credential exchange (028) |
| 60 | hostile fixtures prove fail-closed parser behaviour | **90** fixtures; `hostile_fixtures.rs::every_hostile_fixture_is_refused` through the engine's real three-stage admission path, `the_manifest_covers_every_fixture_on_disk`, `no_refusal_echoes_what_it_refused`, `no_refusal_reads_as_a_security_verdict`, `every_manifest_entry_says_why_rather_than_what_the_error_will_be`, `the_hostile_fixtures_are_not_corpus_vectors`; `error::a_refusal_is_never_a_security_verdict`, `no_error_message_reads_as_a_verdict`; `schema::a_schema_refusal_reports_the_path_and_never_the_value` |

## Profile and coverage integration (61–62)

| # | Criterion | Executed evidence |
|---|---|---|
| 61 | `mcp-auth-hardening-2026` profile is additive | cov `mcp_auth_profile::the_profile_matches_the_approved_requirement_levels_exactly`, `every_selected_property_exists_in_the_v1_registry`, `every_cycle_018_property_in_the_registry_is_selected` (nothing in the catalogue that no profile assesses), `the_profile_resolves_by_name`, `the_profile_is_deterministic`, `nothing_in_this_profile_is_conditional_or_optional`; job *MCP-auth coverage profile plans every surface it selects* |
| 62 | prior profiles and Cycle 006 denominator semantics unchanged | cov `mcp_auth_profile::no_earlier_profile_changed` (all seven, by id and count), `the_earlier_v1_profile_keeps_every_requirement_level_it_had`, `the_auth_profile_selects_no_property_an_earlier_profile_selects` (no overlap, which is how a number inflates without anyone editing one), `the_denominator_of_this_profile_is_its_own_property_count`; job *MCP baseline regression — the earlier denominator did not move* and *Every earlier profile still resolves to what it resolved to* |

## CLI and artifacts (63–65)

| # | Criterion | Executed evidence |
|---|---|---|
| 63 | `validate mcp-auth-security` exists with only local-safe flags | cli `the_command_exposes_exactly_the_six_approved_flags` — enumerates the command's real argument list, so a flag added later that nobody thought to forbid still fails; `a_trace_is_only_meaningful_in_replay_mode`; job *Offline CLI…* runs it and asserts twelve structured fields on the written result |
| 64 | prohibited remote/credential flags do not exist | cli `the_prohibited_endpoint_and_credential_flags_do_not_exist` — all fourteen the approval names, plus nine more that would each imply their own client; cli `the_help_text_names_what_this_command_never_reaches`, `the_help_text_keeps_the_forward_looking_work_out_of_the_requirements` |
| 65 | artifacts use bounded wording and retain standards provenance | `result::a_pass_never_claims_mcp_auth_is_secure`, `an_inconclusive_claim_says_it_is_not_a_pass`; cli `an_unbounded_summary_is_refused_before_it_is_written` (16 phrasings including "spec compliant", "authzen compliant", "oauth 2.1 compliant"), `a_summary_reports_every_surface_and_marks_the_untested_ones`, `the_summary_states_the_distinctions_it_was_built_to_keep_apart`, `an_inconclusive_run_says_so_and_never_reads_as_a_pass`, `a_summary_of_a_violated_run_still_carries_no_credential_or_canary`; `evidence_bridge::no_record_claims_conformance_or_universal_safety`, `every_record_denies_the_universal_claim_rather_than_omitting_it`, `the_central_relations_are_stated_in_every_record`, `a_standards_attribution_never_carries_a_retrieval_target`, `severity_is_never_inferred_from_the_verdict` |

## CI and regressions (66–72)

| # | Criterion | Executed evidence |
|---|---|---|
| 66 | CI job exists without changing the PR-open-only trigger | `.github/workflows/ci.yml` job `mcp-auth-security-2026`, 29 steps. The trigger was verified by **parsing** the YAML rather than reading it: `on.pull_request.branches=[main]`, `types=[opened]`, 16 jobs, the 15 earlier ones unchanged |
| 67 | actual local CI job execution recorded before PR creation | `REGRESSION.md` §1: `python scripts/run-ci-job-locally.py .github/workflows/ci.yml mcp-auth-security-2026` → **all 27 steps PASSED**. It was run with the real workflow file, and it found the two defects in §4 |
| 68 | Cycle 002/003/013/014/015/016/017 regressions pass | job *Cycle 001 evidence, Cycle 002 revision and Cycle 003 integrity regressions* (`dare-security-evidence`, `dare-mcp-discovery`, `dare-coaz-integrity`); job *Cycles 013–017 stayed independent* (`dare-prompt-injection`, `dare-tool-security`, `dare-identity-security`, `dare-memory-security`, `dare-rag-security`); job *Every earlier profile still resolves to what it resolved to* (five profile suites); each cycle's own gate re-run standalone per `REGRESSION.md` §1; `compat::the_memory_separation_rule_is_stated_where_it_is_tested` |
| 69 | Agentic registry/family/coverage regressions pass | job *Agentic baseline regression (Cycle 012)* and *No untested risk family renders as SECURE*; cov `agentic_registry` suite; cov `mcp_auth_profile::the_agentic_risk_families_still_number_exactly_ten` |
| 70 | MCP baseline regressions pass | job *MCP baseline regression — the earlier denominator did not move* asserts `profile.id=mcp-security-baseline`, `--count properties=10`, and that no `risk-family-coverage.json` is written for a v1 profile |
| 71 | workspace fmt/clippy/test/audit pass | `REGRESSION.md` §1: fmt clean, clippy 0 warnings, `cargo test --workspace` 2799 passing / 0 failing, `cargo audit` exit 0 with 0 vulnerabilities and 1 pre-existing allowed warning explained in §5 |
| 72 | EN/PT documentation builds pass | `mdbook build book/en` and `mdbook build book/pt`, both exit 0, mdBook 0.5.4; the two new pages render at `book/en/book/concepts/mcp-auth-security.html` and `book/en/book/reference/extending-mcp-auth-security.html`. `REGRESSION.md` §6 records that the Portuguese *capability pages* do not exist, as a scope decision matching Cycles 013–017, not as work reported done |

## Reproducibility and hygiene (73–76)

| # | Criterion | Executed evidence |
|---|---|---|
| 73 | generated fixtures are reproducible | five generators under `scripts/k18/`, each with `--check`, all run in job *Schemas, scenarios, corpus, traces and hostile fixtures are generated*: schemas (4), scenarios (35 labs), corpus (34 vectors), traces (6), hostile (90 cases). Each reproduces the committed bytes, so a hand-edited fixture is a CI failure rather than silent drift |
| 74 | no real token, secret, authorization code, private key or customer identifier in fixtures or artifacts | `scripts/k18/assert_no_real_credentials.py`, run in job *No real credential or reachable target in any fixture or artifact* — 176 files scanned, 13 hostile values checked. Ordinary files must carry no credential shape and no URL beyond the two that name a contract; the adversarial fixtures, which exist to carry such shapes, must carry only recognisable placeholders (zero-filled, an ordered alphabet, or a vendor's documented example). The detector was negative-tested in both directions before being relied on. Also `lab_scenarios.rs::no_fixture_carries_a_credential_a_secret_or_a_reachable_target`; `local_synthetic::the_snapshot_carries_identifiers_and_never_credential_material` |
| 75 | `REGRESSION.md` records exact execution evidence | `REGRESSION.md` — commands, results, per-suite counts, the before/after inventory, the two defects the gates found, the audit warning, and an explicit section on what was *not* run |
| 76 | `PROOF.md` maps all 76 criteria to executed evidence | this document; every test name in it was matched against the compiled test list rather than recalled |

---

## Post-merge security review

Cycle 018 merged with every criterion above mapped and every test green. A
review afterwards found **eleven defects**, nine of them paths that could report
`PASS` on a control that had not held. `POST-MERGE-REVIEW.md` has the full
account; this section records what it means for the mapping.

**Baseline corrected:** the review branched from
`main @ 4e2da94e6738cbecfa7a5243f4928e75c01c2e5b`, the merge of PR #28.

**Rows that were wrong, not merely incomplete:**

| # | What it claimed | What was true |
|---|---|---|
| 42 | Cycle 003's `compute_authorization_binding` and `changed_operation_fields` decided final-operation binding | Neither was called. `compat.rs` compared three fields with its own string comparison, and `changed_operation_fields` is a fixture helper that could not have done the job |
| 23 | exactly 14 invariants | 14 was right at merge and is now 15. The self-reported metadata boundary was filing findings under an invariant about credential forwarding |
| 40 | the boundary is checked on every trial | True, but the finding named the wrong invariant and carried no deciding evidence |
| 43 | post-permit mutation is caught | Only for `method`, `name` and `resource`. An argument, principal, tenant or scope mutation passed |

**The Cycle 003 composition, as it actually is now:**

`BindingMaterialV1` ← `binding_material_v1(method, name, MappingIdentity,
CanonicalValue::normalize(mapped), CanonicalValue::normalize(trusted),
request_digest)`, one per end. The decision is
`bindings_equal(compute_authorization_binding(a), compute_authorization_binding(b))`.

Dimensions bound: `method`, `name`, `resource`, mapped `arguments` (mapped
inputs); `principal`, `tenant`, `scopes` (trusted inputs).

**New regression tests:** 36 in
`crates/dare-mcp-auth-security/tests/post_merge_regressions.rs`, plus 13 added
or rewritten in `compat`, `protocol`, `trials`, `model` and `lab_scenarios`.
Every one is written against the *vulnerable* behaviour and would have failed
before its fix.

**Tests that asserted the defect** were rewritten rather than deleted, and are
named in `POST-MERGE-REVIEW.md`: `comparison_is_semantic_rather_than_byte_exact`,
`casing_alone_is_not_an_authorization_relevant_change`, and the
`properties.len() == 9` half of `every_surface_and_property_is_reachable_from_some_invariant`.
Two more were renamed because their names claimed more than they checked.

**Gates after the review:** `REGRESSION.md` §7.

## What this cycle does not establish

Recorded here because a proof document that only lists what was shown invites
the reader to assume the rest.

- A PASS means no invariant violation was observed **for the tested vectors
  under the recorded conditions**. It is not a claim that MCP authentication is
  secure, that authorization is correct, that a token cannot be misused, that a
  client cannot be impersonated, or that a deployment is specification-compliant.
- Nothing here was validated against a live MCP server, authorization server or
  identity provider. Every observation is synthetic or replayed from a sanitized
  local trace.
- No signature was verified, no token introspected, no metadata fetched, no
  client registered and no authorization code exchanged. A token's "validity" is
  a recorded state, not a verification performed here.
- DPoP, workload identity federation, ID-JAG, standardized token exchange and
  Enterprise-Managed Authorization were **not assessed** and are not
  requirements. COAZ and COAZ-MCP remain DRAFT; `openid/authzen#603` remains an
  OPEN_PROPOSAL. None was converted into a PASS condition.
- The standards statuses are pinned as of this cycle. **No upstream
  re-verification was performed**, and the provenance record says so in its own
  words rather than leaving it to be inferred.
