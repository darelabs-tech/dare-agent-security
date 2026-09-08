# Cycle 019 — Proof

Eighty-five acceptance criteria, each mapped to something that was executed.

Every name in backticks below is a test that exists in this tree, a function
that exists in this tree, or a file in this cycle's directory.
`scripts/k19/verify_proof_citations.py` runs as a step of the
`supply-chain-security-2026` CI job and fails the build if any of them does not
resolve — a proof document whose citations are unchecked is a claim about a
claim, and Cycle 016 shipped three citations naming tests that did not exist.

Execution figures live in [`REGRESSION.md`](REGRESSION.md) and are not repeated
here.

## What this cycle does not claim

Before the table, the boundary, because a proof document is exactly where a
reader is most likely to conclude more than was established:

- A `PASS` means the invariants that **applied** held under the documents that
  were **actually read**. It is not a statement that a supply chain is secure,
  that no component was substituted, or that a bill of materials is complete.
- Every verdict in this cycle came from local documents. No package registry,
  model hub, container registry, Git host, transparency log, signing service,
  key server or vulnerability database was contacted, and no artifact, model or
  archive was executed.
- Licence compliance, PII, copyright, bias and fairness were not assessed. The
  engine sees a dataset's identity and digest and never its contents.
- Tool-invocation authorization (Cycle 014) and agent-to-agent security
  (Cycle 020) are not answered here.

## The criteria

| AC | Claim | Executed evidence |
|---|---|---|
| AC-01 | baseline pinned to `83fee819` | `BASELINE.md` §1 records the merge-base and the measured baseline (2852 tests, v1=20, v2=40, 10 families, 8 profiles, 16 CI jobs, 48 predicates). `git merge-base --is-ancestor` verified before execution began. |
| AC-02 | `AGENTIC_SUPPLY_CHAIN` reused, not duplicated | `the_agentic_risk_family_count_is_still_exactly_ten` — family count stays 10 and no second supply-chain family appears. |
| AC-03 | `COMPONENT_PROVENANCE` id unchanged | `the_two_inherited_properties_are_unchanged`. Its predicate set is frozen, which is why `provenance_present` is engine-only rather than registry-gated. |
| AC-04 | `CAPABILITY_DRIFT` id unchanged | `the_two_inherited_properties_are_unchanged`; `src/capability.rs` supplies evidence to it and creates no second drift property. |
| AC-05 | exactly eight additive properties | `exactly_the_eight_approved_properties_were_added`. |
| AC-06 | no parallel `AGENT.SUPPLY.*` | `no_parallel_supply_namespace_was_introduced`, and `every_property_is_in_the_frozen_namespace` in `src/model.rs`. |
| AC-07 | OWASP ASI04 mapping with version/status provenance | `every_source_status_is_pinned_to_what_the_approval_froze` pins `OWASP_AGENTIC_TOP10_2026_ASI04` as NORMATIVE in `standards/supply-chain-security/2026/provenance.json`. |
| AC-08 | CycloneDX 1.7 bounded and version-validated | `an_unsupported_spec_version_is_refused`; SUPPLY-LAB-033 refuses a 1.4 document through the CLI in the local job. |
| AC-09 | SPDX 3.0.1 bounded and version-validated | `an_unsupported_spec_version_is_refused` (spdx), `a_well_formed_document_normalizes`. |
| AC-10 | SLSA status/version recorded | `every_source_status_is_pinned_to_what_the_approval_froze` — `SLSA_1_2` NORMATIVE. |
| AC-11 | in-toto status/version recorded | same test — `IN_TOTO_ATTESTATION_1_2` NORMATIVE. |
| AC-12 | Sigstore/Cosign informative only | same test — `SIGSTORE_COSIGN` INFORMATIVE. No Rekor, Fulcio or key server is contacted: `no_constant_in_this_crate_holds_a_reachable_endpoint`, `this_crate_declares_no_fetch_dependency_of_its_own`. |
| AC-13 | CycloneDX 2.0 is not a baseline requirement | same test — `CYCLONEDX_2_0_TEL` FUTURE; `promoting_the_future_source_is_refused`. |
| AC-14 | Cycle 006 NOT_TESTED / NOT_APPLICABLE preserved | `a_missing_supply_chain_control_is_a_gap_and_never_not_applicable`; `applicability.rs` returns NOT_TESTED for absent supply-chain evidence and NOT_APPLICABLE only for target shape. `the_evidence_and_shape_classifications_do_not_overlap`. |
| AC-15 | typed component schema closed | `an_unknown_wire_value_fails_closed_rather_than_defaulting`, `a_hostile_field_is_refused_before_any_component_is_built`. |
| AC-16 | all 14 component classes represented | `every_taxonomy_is_closed_and_uniquely_named`, `there_is_no_catch_all_component_type`. |
| AC-17 | name alone is not immutable identity | `resolve_identity` returns `NameOnly` without a version; `identity_strength_is_ordered_so_requirements_are_comparisons`; the equivalence pair compares over `semantic_key`. |
| AC-18 | name+version cannot satisfy immutable identity | `a_name_and_version_are_not_an_immutable_artifact`; `artifact_expectation_follows_what_a_class_actually_is`. |
| AC-19 | mutable references cannot satisfy immutable identity | `a_floating_tag_with_no_digest_fails_and_one_with_a_digest_does_not`; SUPPLY-LAB-005 (control) and SUPPLY-LAB-006 (attack). |
| AC-20 | digest algorithms allowlisted, malformed fail closed | `digest_lengths_are_pinned_per_algorithm`, `an_unallowlisted_hash_algorithm_is_refused`; SUPPLY-LAB-039 refuses a short SHA-256. |
| AC-21 | conflicting canonical identities fail closed | `one_artifact_under_two_ids_also_collides` (both directions), `one_artifact_under_two_ids_fails_identity_and_names_both`; SUPPLY-LAB-002 and SUPPLY-LAB-038. |
| AC-22 | closed relation enum | `every_taxonomy_is_closed_and_uniquely_named`, `an_unmappable_relationship_is_refused_rather_than_stored`. |
| AC-23 | dangling endpoints fail closed | `the_dangling_edge_entry_is_refused_and_not_silently_dropped`; SUPPLY-LAB-019 exits 1 in the local job. |
| AC-24 | CycloneDX normalizes into the internal model | `a_well_formed_document_normalizes`, `the_ledger_admits_before_the_model_is_built`; SUPPLY-LAB-030. |
| AC-25 | SPDX normalizes into the same model | `an_ai_package_becomes_a_model_and_a_dataset_becomes_a_dataset`, `relationships_are_recorded_as_observed`; SUPPLY-LAB-031. |
| AC-26 | cross-format fixtures normalize equivalently | `cyclonedx_and_spdx_halves_describe_the_same_system` asserts the bundles differ structurally *and* describe one system — without the first half the test could compare a bundle with itself. |
| AC-27 | manifest expresses identity/trust/relationship expectations | `the_fixture_manifest_validates`, `the_five_approved_identity_sets_are_separate_concepts`, `expected_lineage_is_expressed_as_an_id_and_not_a_name`. |
| AC-28 | no document can declare a verdict | `a_manifest_cannot_declare_a_verdict`, `provenance_presence_carries_no_trust_field`, `an_observation_cannot_carry_a_verdict`, `a_scenario_cannot_declare_a_verdict_or_run_anything`, `a_capture_cannot_carry_a_verdict`, `no_entry_declares_an_outcome_anywhere_in_its_evidence`. |
| AC-29 | byte budget enforced before persistence | `an_oversized_document_is_refused_before_it_is_parsed`, `the_ledger_admits_before_the_model_is_built`. |
| AC-30 | component/relationship budgets are admission boundaries | `the_component_ceiling_is_refused_rather_than_clamped`; SUPPLY-LAB-035 refuses `HARD_MAX_COMPONENTS + 1` during import. |
| AC-31 | provenance subject bound to the assessed component | `a_record_about_another_component_does_not_bind`, `missing_provenance_is_reported_once_and_not_twice`; SUPPLY-LAB-012. |
| AC-32 | provenance subject digest bound to artifact digest | `a_record_naming_a_different_digest_is_provenance_for_a_different_build`, `an_absent_digest_on_either_side_answers_nothing`; SUPPLY-LAB-010. |
| AC-33 | builder trust independent of provenance presence | `the_three_bindings_are_independent`, `provenance_for_a_different_build_and_an_unapproved_builder_are_two_findings`; SUPPLY-LAB-011. |
| AC-34 | attestation subject digest bound to the artifact | `an_attestation_for_another_artifact_does_not_satisfy_this_one`, `a_misbound_attestation_fails_even_when_a_valid_one_is_beside_it`; SUPPLY-LAB-014. |
| AC-35 | local verification status does not imply signer trust | `verification_status_and_trust_stay_separate_questions`, `a_recorded_verification_is_not_the_same_as_a_favourable_one`, `an_unapproved_signer_fails_however_valid_the_signature_is`. |
| AC-36 | unapproved signer deterministically fails | `an_unapproved_signer_is_named_rather_than_counted`; SUPPLY-LAB-015 exits 2 in the local job. |
| AC-37 | no Fulcio/Rekor/OCI/remote signature requests | `this_crate_declares_no_fetch_dependency_of_its_own`, `no_constant_in_this_crate_holds_a_reachable_endpoint`, `an_executable_or_fetch_field_is_refused`, `scripts/k19/assert_no_real_credentials.py`. |
| AC-38 | expected/observed edges have deterministic PASS and FAIL | `an_inserted_dependency_and_a_missing_one_are_separate_findings`; SUPPLY-LAB-016 (control) and 017/018 (attacks). |
| AC-39 | unexpected dependency insertion detected | `undeclared_dependencies`; SUPPLY-LAB-017. |
| AC-40 | missing expected dependency detected | `unobserved_dependencies`; SUPPLY-LAB-018. |
| AC-41 | capability drift has PASS/FAIL/INCONCLUSIVE | `an_unchanged_capability_set_has_not_drifted`, `an_introduced_capability_is_drift_and_is_named`, `one_side_alone_is_not_comparable`; SUPPLY-LAB-020/021/022. |
| AC-42 | model lineage has PASS/FAIL/INCONCLUSIVE | `an_approved_base_that_is_observed_matches`, `a_substituted_base_model_does_not_match`, `missing_lineage_evidence_is_undecidable_rather_than_a_match`, `a_missing_expectation_is_also_undecidable`; SUPPLY-LAB-023/024/025. |
| AC-43 | model name alone cannot prove lineage | `expected_lineage_is_expressed_as_an_id_and_not_a_name`, `the_right_base_with_the_wrong_digest_is_still_a_substitution`, `a_dependency_edge_is_not_lineage`. |
| AC-44 | dataset provenance has PASS and FAIL | `an_approved_dataset_with_a_matching_digest_binds`, `a_substituted_dataset_does_not_bind`, `an_approval_with_no_digest_leaves_integrity_undecided`; SUPPLY-LAB-026/027. |
| AC-45 | dataset scope does not expand into PII/copyright/fairness | `the_dataset_model_has_nowhere_to_record_a_privacy_finding` — no such field exists and `pii_detected`, `license_conflict`, `bias_score` all fail to decode. |
| AC-46 | tool/skill/plugin/MCP participate without duplicating Cycle 014 | `the_four_agentic_surface_classes_project_and_others_do_not`, `an_mcp_server_carries_the_same_supply_chain_questions_as_a_package`, `the_projection_cannot_record_a_cycle_014_authorization_decision`, `the_assessment_says_nothing_about_runtime_authorization`; SUPPLY-LAB-028. |
| AC-47 | external-agent inventory does not implement Cycle 020 | `the_inventory_cannot_record_an_a2a_authorization`, `an_external_agent_is_not_an_agentic_surface_of_this_deployment`, `an_unreferenced_external_agent_is_still_inventoried`. |
| AC-48 | observations closed; adapters cannot assert a verdict | `the_channel_set_is_closed_and_uniquely_named`, `the_twelve_design_channels_are_all_present`, `an_observation_cannot_carry_a_verdict`, `the_adapter_contract_has_no_way_to_report_a_verdict`. |
| AC-49 | exactly 12 invariants | `the_registry_holds_exactly_the_twelve_approved_invariants`, `the_property_mapping_is_exactly_the_one_design_fixed`, `twelve_invariants_report_under_ten_properties`, `the_twelve_evaluators_are_all_reachable`. |
| AC-50 | PASS requires positive invariant-specific evidence | `every_invariant_has_a_contract_and_every_contract_requires_something`, `an_empty_run_satisfies_no_contract`, `an_empty_run_is_inconclusive_and_never_passes`, `a_run_with_components_alone_covers_only_the_identity_invariants`. |
| AC-51 | missing deciding evidence yields INCONCLUSIVE | `a_missing_channel_is_named_in_the_reason`, `a_present_channel_that_compared_nothing_does_not_satisfy_a_contract`, `every_gap_is_undecidable_rather_than_passing_or_failing`, `an_applicable_invariant_with_thin_evidence_stays_undecided`; SUPPLY-LAB-012/022/025. |
| AC-52 | primary invariant cannot hide another concrete FAIL | `every_applicable_invariant_is_evaluated_regardless_of_which_one_a_fixture_targets`, `the_primary_invariant_does_not_filter_what_is_reported`, `the_primary_invariant_is_a_coverage_selector_and_not_a_verdict`. |
| AC-53 | all same-trial concrete FAILs retained | `collect_observed_violations`; `the_multi_violation_entry_retains_every_independent_finding`; the local job asserts three distinct invariants survive SUPPLY-LAB-036. |
| AC-54 | secondary outcomes do not erase primary semantics | `a_secondary_gap_does_not_erase_a_primary_failure`, `a_failure_outranks_a_later_harness_error`, `coverage_gates_pass_and_never_gates_fail`. |
| AC-55 | only STATIC/REPLAY/SIMULATED/LOCAL_SYNTHETIC | `there_are_exactly_four_modes_and_none_of_them_is_remote` — `REMOTE`, `LIVE`, `REGISTRY` and `NETWORK` all fail to decode. |
| AC-56 | external egress budget is zero | `the_zero_bounds_are_zero_and_stay_that_way`, `the_budget_pins_state_changes_egress_and_writes_to_zero`, `the_artifact_records_the_budget_it_ran_under`; asserted on every CLI artifact in the local job. |
| AC-57 | state-change budget is zero | same tests; `budget.state_changes=0` asserted by `scripts/assert-json.py` in the job. |
| AC-58 | no remote fetch path exists | `this_crate_declares_no_fetch_dependency_of_its_own`, `no_constant_in_this_crate_holds_a_reachable_endpoint`, `the_command_exposes_no_fetch_or_credential_flag`, `scripts/k19/assert_no_real_credentials.py`. |
| AC-59 | external references are inert metadata | `ordinary_bom_coordinate_fields_stay_readable` (purl, downloadLocation, externalReferences, repository all pass), `a_forbidden_scheme_is_refused_and_a_plain_coordinate_is_not`, `a_generated_document_carries_a_coordinate_and_nothing_fetches_it`, `a_purl_stays_in_the_fixtures_and_a_registry_host_does_not`. |
| AC-60 | no artifact/model/code execution | structural: no process spawner, archive extractor, model runtime or dynamic loader is declared — `this_crate_declares_no_fetch_dependency_of_its_own`; `an_executable_or_fetch_field_is_refused` covers the document surface. |
| AC-61 | hostile secret fields refused before persistence | `a_credential_field_is_refused_at_any_depth`, `a_credential_field_is_refused_even_when_empty`, `a_credential_shaped_value_is_refused_wherever_it_appears`, `every_credential_marker_is_lowercase`; SUPPLY-LAB-034. |
| AC-62 | executable/callback/command fields refused | `an_executable_or_fetch_field_is_refused`; `a_scenario_cannot_declare_a_verdict_or_run_anything` refuses `command` and `hook`. |
| AC-63 | path traversal and bidi/control spoofing refused | `a_control_character_is_refused_and_a_newline_is_not`, `a_hostile_provenance_identifier_is_refused`, `a_hostile_scenario_identifier_is_refused`, `a_path_shaped_evidence_name_is_refused_before_anything_is_opened`, `a_path_shaped_corpus_id_is_refused`. |
| AC-64 | oversized/deep/fan-out inputs fail closed | `an_oversized_document_is_refused_before_it_is_parsed`, `deeply_nested_documents_are_refused_rather_than_recursed`, `the_dependency_depth_ceiling_is_small_enough_to_stop_a_bomb`; SUPPLY-LAB-035. |
| AC-65 | run-wide limits cannot reset per component/trial | `run_wide_output_totals_do_not_reset_between_trials`, `per_component_bounds_never_exceed_run_wide_ones`. |
| AC-66 | at least 36 SUPPLY-LAB scenarios | `the_corpus_meets_the_minimum_and_the_recommended_size` — 40 entries, minimum 36. `staging_is_deterministic_for_every_entry` and `running_the_whole_corpus_twice_produces_identical_results`. |
| AC-67 | secure/vulnerable pairs cover every dimension | `the_corpus_covers_every_dimension_in_both_directions`, `a_meaningful_share_of_the_corpus_is_legitimate_activity` (16 of 40 are controls or gaps), `every_invariant_is_exercised_by_at_least_one_entry`. |
| AC-68 | multi-violation corpus proves independent retention | `the_multi_violation_entry_retains_every_independent_finding`, `the_multi_violation_behaviour_retains_every_independent_finding`; asserted end to end in the local job. |
| AC-69 | hostile fixtures prove refusal without state change or egress | `every_refusal_is_refused_before_anything_is_evaluated` (and the refusal echoes neither the planted credential nor the malformed digest), `a_refusal_never_echoes_what_it_refused`. |
| AC-70 | `agentic-supply-chain-security-2026` profile is additive | `the_profile_is_exactly_what_the_approval_authorized`, `every_selected_property_exists_in_the_agentic_registry`, `the_split_between_required_and_conditional_is_deliberate`. |
| AC-71 | existing agentic baseline semantics unchanged | `no_earlier_profile_moved`, `the_agentic_baseline_still_selects_what_it_always_selected`, `the_mcp_registry_is_untouched_by_a_supply_chain_property`. |
| AC-72 | Cycle 006 denominator semantics unchanged | `no_earlier_profile_moved` pins all eight earlier denominators; `the_profile_digest_is_stable`; full `dare-coverage` suite green (326 tests). |
| AC-73 | `validate supply-chain` exists with local-safe flags | `a_built_in_corpus_id_resolves_to_a_scenario`, `a_flag_from_another_mode_is_a_usage_error`, `replay_requires_a_manifest_the_capture_did_not_supply`; seven real invocations in the local job. |
| AC-74 | prohibited remote/credential/executable flags do not exist | `the_command_exposes_no_fetch_or_credential_flag` asserts over the rendered help — the surface an operator reads and a reviewer checks. |
| AC-75 | outputs bounded, with standards/evidence provenance | `a_clean_run_never_claims_the_supply_chain_is_secure`, `an_inconclusive_run_says_it_established_nothing`, `an_overstated_summary_is_refused`, `the_summary_of_a_clean_run_is_bounded`, `every_record_carries_the_rules_a_reader_needs_to_interpret_it`. |
| AC-76 | `supply-chain-security-2026` job exists, trigger unchanged | `.github/workflows/ci.yml` — the job is additive and the workflow trigger remains `pull_request: types: [opened]`. |
| AC-77 | real local execution recorded before PR creation | `REGRESSION.md` §6 — `python scripts/run-ci-job-locally.py .github/workflows/ci.yml supply-chain-security-2026`, 18 of 18 steps passing. |
| AC-78 | Cycle 012–018 regressions pass | `REGRESSION.md` §3 — 326/271/276/323/265/283/348 passing, 0 failed. |
| AC-79 | MCP baseline and coverage regressions pass | `the_mcp_registry_is_untouched_by_a_supply_chain_property`, `no_earlier_profile_moved`; whole `dare-coverage` and `dare-mcp-auth-security` suites green. |
| AC-80 | workspace fmt/clippy/test/audit pass | `REGRESSION.md` §4 — fmt clean, clippy `-D warnings` clean, 3249 tests passing, audit 0 vulnerabilities with 1 pre-existing allowed warning. |
| AC-81 | EN/PT documentation builds pass | `REGRESSION.md` §5 — `mdbook build book/en` and `mdbook build book/pt` both built. |
| AC-82 | generated fixtures are reproducible | `every_generated_document_is_byte_identical_between_runs`, `generated_documents_differ_between_behaviours_that_stage_different_things`, `generation_is_deterministic`, `evidence_record_ids_are_reproducible_and_distinct`, `results_are_deterministic`. |
| AC-83 | no real credentials, keys, customer identifiers or live endpoints | `no_generated_document_carries_a_credential_key_or_live_endpoint`, `no_corpus_bundle_carries_a_credential_key_or_live_endpoint`, `no_artifact_a_run_writes_carries_a_credential_key_or_live_endpoint`, `an_artifact_carrying_a_credential_is_not_written`, `a_refusal_never_echoes_what_it_refused`, plus `scripts/k19/assert_no_real_credentials.py` over shipping code, tests, the profile, the standards record and every written artifact. |
| AC-84 | `REGRESSION.md` records exact execution evidence | `REGRESSION.md` — every figure from an executed command, including the run that was red and what it found. |
| AC-85 | `PROOF.md` maps all 85 criteria to executed evidence | This document. `scripts/k19/verify_proof_citations.py` runs in the CI job and fails if any cited name does not exist in the tree. |

## Three things the tests changed

A proof document that recorded only what passed would hide the part worth
reading. Three claims in this cycle were wrong first and were corrected by
something that ran.

**A compliant bundle reported `INCONCLUSIVE`.** Found by the first real local
execution of the CI job, not by any unit test. A bundle of packages carries no
model, no dataset, no capabilities and no dependency edges, and four invariants
were being counted as undecided rather than as not arising. Outcomes now carry
`applicable`, read from the observations rather than declared, and the aggregate
ignores inapplicable ones — while a model that *is* present with no recorded
lineage stays applicable and inconclusive.

**Two invariants passed having compared nothing.** SUPPLY-LAB-022 and
SUPPLY-LAB-025 both reported `PASS` when first run. A capability context exists
as soon as *either* side supplies capabilities, and a lineage context exists for
*every* model whether or not a base was observed, so both invariants found the
channel they required and passed. `assess_coverage` now asks whether the
comparison was actually made.

**Identity ambiguity was refused instead of reported.** `validate` called
`assert_no_collisions`, so a fixture staging one artifact under two ids would
have produced `ERROR` — a run that could not observe — when the engine had
observed the ambiguity perfectly well. Collisions are now retained and reported
as the finding `COMPONENT_IDENTITY_UNAMBIGUOUS` exists for.

Two smaller corrections are recorded in [`REGRESSION.md`](REGRESSION.md) §8,
including a test whose name claimed something it never checked
(`a_model_with_no_digest_fails_completeness_and_a_framework_does_not` — a
`FRAMEWORK` does owe a digest, and the fixture had one).

## Frozen contracts, restated

| Contract | State |
|---|---|
| `AGENTIC_SUPPLY_CHAIN` risk family | reused; no second family |
| `AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE` | unchanged |
| `AGENT.SUPPLY_CHAIN.CAPABILITY_DRIFT` | unchanged |
| Additive property ids | exactly eight |
| `AGENT.SUPPLY.*` namespace | does not exist |
| Earlier profile denominators | all eight unchanged |
| Cycle 006 applicability semantics | unchanged |
| Workflow trigger | `pull_request: types: [opened]`, unchanged |
