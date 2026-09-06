# Cycle 017 — Proof of acceptance

Each of the 66 acceptance criteria in `DESIGN.md` §21 is mapped to **executed
evidence**: a test that ran, a workflow step that ran, or an artifact a run
wrote. Nothing here is satisfied by the existence of code, by design prose, or
by a claim that something looks correct.

Every named test passed in the run recorded in `REGRESSION.md`:
`cargo test --workspace` — 2436 passing, 0 failing; and
`python scripts/run-ci-job-locally.py .github/workflows/ci.yml rag-security-2026`
— all 41 steps PASSED.

Abbreviations: **rag** = `dare-rag-security`, **cov** = `dare-coverage`,
**prod** = `dare-product`, **cli** = `dare-agent-security`,
**job** = a step of the real `rag-security-2026` workflow job.

---

## Standards, taxonomy and properties (1–6)

| # | Criterion | Executed evidence |
|---|---|---|
| 1 | baseline frozen at `c0cd5edb…` | `BASELINE.md` records 2067 tests, 34 properties, 32 predicates, 10 families and 6 profiles at that head; `git merge-base --is-ancestor c0cd5edb… HEAD` → yes |
| 2 | LLM09:2026 provenance recorded without mislabeling as an Agentic family | cov `rag_security_standards::*` (21 tests) over the `assert_no_conformance_claim` and `assert_no_taxonomy_claim` validators; cov `rag_security_properties::every_rag_property_maps_to_llm09_and_nothing_else`, `no_rag_property_references_an_asi_identifier`, `the_provenance_manifest_and_the_registry_agree_on_the_six_properties` |
| 3 | Agentic risk-family count remains 10 | cov `rag_security_properties::the_agentic_family_count_is_still_exactly_ten`; cov `rag_security_profile::the_agentic_risk_families_still_number_exactly_ten`; job step *Agentic baseline regression (Cycle 012)* asserts `--count "=10"` on `risk-family-coverage.json` |
| 4 | six additive `AGENT.RAG.*` properties exist | cov `rag_security_properties::the_six_approved_properties_exist_and_no_others_were_added`; registry now holds 40 properties (34 + 6) |
| 5 | prior registry properties unchanged | cov `rag_security_properties::the_new_predicates_do_not_change_an_existing_property`, `facts_that_predate_this_cycle_still_decode`, `every_non_rag_agent_property_still_requires_a_family`; the four prior profile suites (`prompt_injection_*`, `tool_security_*`, `identity_security_*`, `memory_security_*`) all pass unchanged |
| 6 | applicability predicates closed / fail-closed | cov `rag_security_properties::the_five_new_predicates_exist_and_are_closed`, `an_unknown_predicate_fails_closed`, `a_target_without_retrieval_is_not_applicable_rather_than_failing` |

## Schemas and machine-readable bindings (7–14)

| # | Criterion | Executed evidence |
|---|---|---|
| 7 | versioned document/chunk schema | `schemas/rag-security/v1/document.schema.json`, `document-store.schema.json`; rag `schema::tests::every_compiled_schema_compiles`, `an_unsupported_or_missing_version_is_refused`; rag `document::tests::the_fixture_store_validates` |
| 8 | versioned retrieval-policy schema | `retrieval-policy.schema.json`; rag `policy::tests::the_fixture_policy_validates`, `the_policy_rejects_unknown_and_remote_fields` |
| 9 | versioned request/result schema | `scenario.schema.json` (queries, candidate sets) and `RESULT_SCHEMA_ID`; rag `harness::tests::the_fixture_scenario_validates`, `result::tests::the_same_run_twice_produces_the_same_artifact` |
| 10 | versioned scenario/corpus/trace schemas | 8 schemas under `schemas/rag-security/v1/`; rag `corpus::tests::a_well_formed_entry_validates`, `replay::tests::a_well_formed_trace_parses_and_replays` |
| 11 | principal/tenant/collection bindings explicit | rag `document::tests::the_three_isolation_axes_are_independent`, `a_document_disagreeing_with_its_collections_tenant_is_refused`, `a_document_in_an_undeclared_collection_is_refused` |
| 12 | document ACL machine-readable | rag `policy::tests::any_permits_everything_and_only_permits_the_listed_values`, `an_undeclared_dimension_denies_everything`, `a_dimension_declaring_any_and_listing_values_is_refused` |
| 13 | provenance machine-readable | rag `document::tests::provenance_needs_both_an_id_and_an_origin_to_be_machine_readable`, `a_chunk_claiming_another_documents_provenance_is_refused_at_declaration` |
| 14 | protected-document policy machine-readable | rag `policy::tests::a_protected_document_says_why_it_is_protected`, `a_classification_can_protect_a_document_nobody_listed_by_id`, `a_label_can_protect_a_document_too` |

## Evaluation model (15–20)

| # | Criterion | Executed evidence |
|---|---|---|
| 15 | deterministic ranking evidence, no live embedding inference | rag `invariant::tests::a_score_never_appears_in_a_verdict_path`; rag `offline_confidential::the_engine_declares_no_transport_provider_or_embedding_dependency` (bans `candle`, `ort`, `tokenizers`, `tiktoken`, `fastembed`); job step *A protected document ranked first is still a disclosure* asserts the reason names the boundary and not the score |
| 16 | closed normalized observation model | rag `observation::tests::the_event_model_is_closed_and_carries_no_verdict_variant`, `the_channel_set_is_closed_at_eleven`, `every_other_event_supplies_exactly_one_channel` |
| 17 | 12 deterministic invariants, total and closed | rag `invariant::tests::the_registry_is_closed_at_twelve`; rag `model::tests::the_twelve_invariants_are_closed_and_uniquely_named`, `the_approved_invariant_names_are_exactly_these`; rag `coverage::tests::the_contract_is_total_over_the_twelve_invariants` |
| 18 | no LLM/embedding/similarity heuristic as final judge | as #15, plus rag `offline_confidential::no_source_file_reaches_for_a_network_or_process_api` and `source::tests::trust_promotion_is_arithmetic_rather_than_a_judgement` |
| 19 | every PASS requires positive coverage | rag `coverage::tests::the_six_did_something_invariants_require_an_exercise_channel`, `seeing_a_policy_is_not_the_same_as_running_a_query`, `content_trust_needs_an_influence_observation_and_not_merely_a_retrieval`; job step *Retrieval without promotion passes only on positive evidence* |
| 20 | missing evidence → INCONCLUSIVE | rag `invariant::tests::an_empty_observation_set_is_inconclusive_for_every_invariant`; rag `coverage::tests::an_empty_run_satisfies_no_contract`, `a_run_of_only_harness_errors_satisfies_no_contract`; rag `result::tests::an_unobserved_channel_is_inconclusive_rather_than_a_pass`; job step *Absence of evidence is INCONCLUSIVE, never PASS and never FAIL* (RAG-LAB-021, exit 2) |

## Offline execution modes (21–25)

| # | Criterion | Executed evidence |
|---|---|---|
| 21 | replay offline | rag `offline_confidential::every_approved_mode_runs_fully_offline`, `a_trace_is_inert_data_and_starts_nothing`; job step *Replay reads only a local trace and stays offline* asserts `mode=REPLAY synthetic=true` with zero egress |
| 22 | simulated offline | rag `offline_confidential::every_approved_mode_runs_fully_offline`; cli `rag_security_cli::a_compliant_lab_exits_zero_and_writes_every_artifact` |
| 23 | local-synthetic offline with Cycle 009 controls | rag `local_synthetic::tests::the_budget_pins_state_changes_and_egress_to_zero`, `the_synthetic_step_is_read_only_by_construction`, `pointing_an_approved_run_at_another_scenario_trips_the_kill_switch`, `a_triggered_control_is_a_harness_outcome_and_never_a_verdict`; cli `rag_security_cli::the_local_synthetic_mode_runs_under_the_cycle_009_controls` |
| 24 | no live/remote retrieval mode | rag `harness::tests::there_is_no_remote_or_live_mode`; rag `offline_confidential::the_mode_enum_cannot_represent_a_remote_or_live_target`; job step *No live or remote retrieval mode can be selected* (8 rejected mode strings) |
| 25 | no live vector-store/provider dependency | rag `offline_confidential::the_engine_declares_no_transport_provider_or_embedding_dependency` (28 banned crates) and `no_source_file_reaches_for_a_network_or_process_api`; rag `schema::tests::every_vector_store_name_is_refused_as_a_field` |

## Detection — each failure mode can actually FAIL (26–36)

Each row names the lab that stages it, the job step that ran it, and the exit
code and verdict the run produced.

| # | Criterion | Executed evidence |
|---|---|---|
| 26 | cross-tenant retrieval can FAIL | RAG-LAB-002 → exit 2, `verdict=FAIL invariant=RETRIEVAL_TENANT_BOUNDARY_PRESERVED`; job step *A document from another tenant is a finding, however relevant*; cli `an_observed_violation_exits_two_and_names_the_invariant` |
| 27 | unauthorized document retrieval can FAIL | RAG-LAB-004 → exit 2, `invariant=DOCUMENT_ACL_ENFORCED`; job step *A document outside the allowed set fails…* |
| 28 | metadata-filter bypass can FAIL | RAG-LAB-006 → exit 2, `invariant=METADATA_FILTER_ENFORCED`; same job step; rag `policy::tests::a_missing_metadata_field_never_satisfies_a_mandatory_clause`, `a_negative_clause_also_requires_the_field_to_be_present`; rag `violations_and_hygiene::a_document_smuggled_past_the_filter_is_caught_from_the_corpus` |
| 29 | provenance mismatch can FAIL | RAG-LAB-008 → exit 2, `class=PROVENANCE invariant=RETRIEVAL_PROVENANCE_PRESERVED`; job step *Provenance detached from returned content is a finding, not a gap* |
| 30 | non-candidate result injection can FAIL | RAG-LAB-010 → exit 2, `invariant=RESULT_SET_WITHIN_APPROVED_CANDIDATES`; job step *A result that was never a candidate…* |
| 31 | top-k overflow can FAIL | RAG-LAB-012 → exit 2, `invariant=TOP_K_BOUND_PRESERVED`; same job step |
| 32 | untrusted content authority promotion can FAIL | RAG-LAB-014 → exit 2, `class=CONTENT_TRUST invariant=UNTRUSTED_RETRIEVED_CONTENT_NOT_PROMOTED_TO_AUTHORITY`; job step *Retrieving untrusted content does not make it authoritative* |
| 33 | protected-document retrieval can FAIL | RAG-LAB-016 → exit 2, `class=PROTECTED_NONDISCLOSURE invariant=PROTECTED_DOCUMENT_NOT_RETRIEVED`, staged at score 1.0; job step *A protected document ranked first is still a disclosure*; rag `lab_scenarios::a_high_score_never_rescues_a_boundary_crossing`; cli `a_high_scoring_protected_document_still_fails` |
| 34 | fallback authority widening can FAIL | RAG-LAB-018 → exit 2, `invariant=RETRIEVAL_FALLBACK_DOES_NOT_WIDEN_AUTHORITY`; job step *A broadened retrieval must not widen the authority it runs under*; rag `policy::tests::a_fallback_cannot_grant_what_the_policy_denies_outright`, `the_default_fallback_retries_without_widening_anything` |
| 35 | clean/no-promotion path needs positive evidence to PASS | RAG-LAB-013 → exit 0, `verdict=PASS class=CONTENT_TRUST`; job step *Retrieval without promotion passes only on positive evidence* asserts `coverage_satisfied=true` **and** a recorded `changed=false` influence; rag `lab_scenarios::a_pass_never_rests_on_an_empty_observation_set` |
| 36 | independent simultaneous violations retained | RAG-LAB-022; rag `violations_and_hygiene::three_simultaneous_violations_are_all_reported_from_one_trial`, `evaluating_one_invariant_never_consumes_or_hides_another`, `a_failing_run_of_one_invariant_leaves_the_others_independently_judged`; rag `invariant::tests::a_violation_is_reported_even_when_another_channel_is_missing`; job step *Independent violations are all recorded, never masked* |

## Bounds and budgets (37–39)

| # | Criterion | Executed evidence |
|---|---|---|
| 37 | hard document/chunk/candidate/result limits enforced | rag `limits::tests::the_approved_bounds_are_exactly_what_design_records`, `a_result_set_can_never_be_wider_than_the_candidate_set`; rag `document::tests::an_over_bound_store_is_refused_rather_than_truncated`, `an_over_bound_metadata_map_is_refused`, `an_over_bound_or_non_finite_vector_is_refused`; rag `policy::tests::a_top_k_above_the_hard_maximum_is_refused`, `an_over_bound_filter_is_refused`; RAG-LAB-023 → exit 3, no artifact (job step *An over-bound or smuggling scenario is refused before evaluation*) |
| 38 | total query limits enforced across trials | rag `limits::tests::per_trial_bounds_never_exceed_run_wide_ones`; job step *Trial hard maximum is enforced and never clamped upward* asserts `budget.max_total_queries=24` and `trials_planned=10` on a `--trials 10` run, and that `--trials 11` is refused with no artifact written |
| 39 | output/time/state/egress budgets enforced | rag `trials::tests::a_plan_records_zero_state_changes_and_zero_egress`; rag `local_synthetic::tests::exhausting_the_budget_stops_the_run_rather_than_failing_it`, `the_budget_pins_state_changes_and_egress_to_zero`; rag `result::tests::the_result_records_zero_state_changes_and_zero_egress`; rag `offline_confidential::every_run_records_zero_state_change_and_zero_egress` (6 labs) |

## Hostile input and secret safety (40–41)

| # | Criterion | Executed evidence |
|---|---|---|
| 40 | hostile executable/verdict/remote-store fields refused | 80 fixtures under `corpus/rag-security/v1/adversarial-parser-fixtures/`; rag `hostile_fixtures` (9 tests, every fixture fails closed); rag `schema::tests::an_executable_field_is_refused_at_any_depth`, `a_verdict_field_is_refused`, `every_vector_store_name_is_refused_as_a_field`, `a_remote_target_is_refused_by_value_even_in_an_allowed_field`; RAG-LAB-024 → exit 3, no artifact, refusal echoes neither the secret nor the endpoint (cli `a_scenario_the_engine_refuses_exits_three_without_writing_a_verdict`) |
| 41 | secret-shaped values redacted/refused before persistence | rag `observation::tests::a_canary_is_masked_before_it_is_stored`, `a_bearer_token_is_masked_while_the_word_stays_writable`, `an_armoured_key_block_is_masked_whole`, `a_secret_at_the_end_of_a_long_value_is_still_masked`, `an_unterminated_key_block_is_masked_to_the_end`; rag `violations_and_hygiene::evidence_text_is_masked_at_construction_rather_than_on_the_way_out`, `no_retained_text_from_any_lab_carries_a_canary_or_a_credential`; rag `offline_confidential::a_canary_never_survives_into_a_persisted_artifact` (22 labs × 3 artifacts); job step *No artifact leaks a canary, credential or store endpoint* over 60+ written files |

## Evidence and composition (42–46)

| # | Criterion | Executed evidence |
|---|---|---|
| 42 | evidence binds scenario/policy/query/candidate/result/document/provenance digests | rag `evidence_bridge::tests::every_bound_digest_reaches_the_record_hashes`, `evidence_ids_are_stable_and_move_when_the_corpus_moves`; rag `result::tests::every_document_keeps_a_separate_identity_and_content_digest`, `a_substituted_document_changes_the_recorded_binding`, `a_scenario_pinning_the_wrong_corpus_digest_is_refused`; job step asserts `--present scenario_digest store_digest context_digest policy_digest document_digests chunk_digests` |
| 43 | Cycle 001 evidence reused | rag `evidence_bridge::tests::evidence_reuses_the_cycle_001_contract_and_vocabulary`, `the_decision_vocabulary_is_borrowed_rather_than_redefined`, `retrieval_specifics_live_in_the_namespaced_extension_and_nowhere_else` |
| 44 | Cycle 013 trust-boundary semantics reused, no duplicate prompt engine | rag `compat::tests::every_retrieval_source_either_names_a_cycle_013_channel_or_explains_why_not`, `retrieved_content_is_always_indirect_in_the_cycle_013_sense`, `retrieving_untrusted_content_does_not_discharge_the_injection_boundary`, `retrieval_invariants_and_injection_invariants_are_disjoint`, `retrieval_families_and_injection_families_are_disjoint`, `the_two_trust_level_vocabularies_are_token_identical` |
| 45 | Cycle 015 principal/tenant semantics reused | rag `compat::tests::converting_an_identity_principal_preserves_kind_and_tenant_exactly`, `retrieval_adds_no_principal_kinds`, `relabelling_a_principals_kind_in_retrieval_is_refused`, `moving_a_principal_into_another_tenant_in_retrieval_is_refused`, `authority_origination_is_answered_by_cycle_015` |
| 46 | Cycle 016 memory boundary separate and green | rag `compat::tests::no_retrieval_observation_can_be_read_as_a_memory_event`, `retrieval_invariants_and_memory_invariants_are_disjoint`, `retrieval_and_memory_taxonomies_do_not_share_a_property_namespace`; `memory-security-2026` local job — all 39 steps PASSED; job step *Memory Security regression (Cycle 016)* also asserts `\| Memory items written \| 0 \|` |

## Profile and denominators (47–49)

| # | Criterion | Executed evidence |
|---|---|---|
| 47 | `rag-security-baseline-2026` exists | `profiles/rag-security-baseline-2026.json`; cov `rag_security_profile::the_profile_matches_the_approved_requirement_levels_exactly`, `the_profile_resolves_by_name`, `every_selected_property_exists_in_the_registry` |
| 48 | prior profiles unchanged | cov `rag_security_profile::no_earlier_profile_changed` (pins all six earlier profile ids and counts), `the_rag_profile_selects_no_property_an_earlier_profile_selects`; the four earlier profile suites all pass |
| 49 | Cycle 006 denominator semantics unchanged | as #48; plus cov `coverage_fixtures` and `cycle005_adapter` suites unchanged and passing; job step *No untested risk family renders as SECURE* |

## Prior-cycle regressions (50–55)

All executed as real workflow jobs, not equivalents.

| # | Criterion | Executed evidence |
|---|---|---|
| 50 | Cycle 013 regression green | `run-ci-job-locally.py … prompt-injection-2026` — all 22 steps PASSED; job step *Prompt Injection regression (Cycle 013)* → `verdict=PASS mode=SIMULATED` |
| 51 | Cycle 014 regression green | `… tool-security-2026` — all 28 steps PASSED; job step *Tool Security regression (Cycle 014)* → `verdict=PASS` |
| 52 | Cycle 015 regression green | `… identity-security-2026` — all 36 steps PASSED; job step *Identity Security regression (Cycle 015)* → `verdict=PASS` |
| 53 | Cycle 016 regression green | `… memory-security-2026` — all 39 steps PASSED; job step *Memory Security regression (Cycle 016)* → `verdict=PASS`, zero memory writes |
| 54 | Agentic baseline regression green | `… agentic-registry-2026` — all 5 steps PASSED; job step *Agentic baseline regression (Cycle 012)* → 10 families, each with ≥1 property |
| 55 | MCP baseline regression green | job step *MCP baseline regression* → `coverage-report.json` written, `risk-family-coverage.json` correctly absent |

## CLI and reporting (56–59)

| # | Criterion | Executed evidence |
|---|---|---|
| 56 | CLI exposes only local/replay/synthetic surface | cli `rag_security::tests::the_mode_enum_admits_only_the_three_local_modes`; job step *No live or remote retrieval mode can be selected* |
| 57 | CLI has no remote provider/store/credential/command flags | cli `rag_security::tests::the_prohibited_store_provider_and_credential_flags_do_not_exist` (17 flags); cli `rag_security_cli::a_forbidden_flag_is_rejected_by_the_parser` (14 flags, end to end); job step *Store, provider, credential and remote flags do not exist* (17 flags against the real binary) |
| 58 | reports use bounded wording and mark synthetic evidence | cli `rag_security::tests::an_unbounded_summary_is_refused_before_it_is_written`, `a_summary_reports_every_surface_and_marks_the_untested_ones`, `a_summary_of_a_violated_run_still_carries_no_retrieved_content`; prod `rag_security_metadata::*` (11 tests); cli `rag_security_product::*` (7 tests); rag `result::tests::a_pass_never_claims_retrieval_is_secure`, `the_artifact_never_carries_a_canary_a_credential_or_an_endpoint`; rag `evidence_bridge::tests::no_record_claims_conformance_or_universal_safety`; job steps *Report wording carries no universal RAG-security claim*, *The approved bounded wording is used verbatim on a pass*, *Summaries report each surface separately and name untested ones* |
| 59 | confidential/offline mode fail closed | rag `offline_confidential` (10 tests): `every_approved_mode_runs_fully_offline`, `the_engine_declares_no_transport_provider_or_embedding_dependency`, `no_source_file_reaches_for_a_network_or_process_api`, `a_canary_never_survives_into_a_persisted_artifact`, `no_shipped_fixture_or_corpus_entry_names_a_reachable_target`, `evidence_never_names_a_production_target`, `a_trace_is_inert_data_and_starts_nothing`; job step *Offline, confidential and no-remote-retriever regressions* |

## CI and release gates (60–66)

| # | Criterion | Executed evidence |
|---|---|---|
| 60 | dedicated `rag-security-2026` job uses local fixtures only | `.github/workflows/ci.yml` job `rag-security-2026`, 41 run-steps; every command reads `crates/dare-rag-security/tests/fixtures/…` or `corpus/rag-security/v1/…`; no step names a host, and the offline suite it runs proves the binary has no path to one |
| 61 | actual workflow job passes locally before PR | `python scripts/run-ci-job-locally.py .github/workflows/ci.yml rag-security-2026` → **all 41 steps PASSED**, executed from the YAML rather than a hand-written equivalent |
| 62 | fmt/clippy/workspace tests/audit pass | `cargo fmt --all --check` clean; `cargo clippy --workspace --all-targets -- -D warnings` 0 warnings; `cargo test --workspace` 2436 passing 0 failing; `cargo audit` exit 0, 0 vulnerabilities (1 pre-existing allowed yank, `REGRESSION.md` §7.2) |
| 63 | docs explain retrieval policy, provenance, isolation, LLM09 mapping and boundaries | `book/en/src/concepts/rag-security.md` and `book/en/src/reference/extending-rag-security.md`, registered in `SUMMARY.md` and cross-linked from `commands/validate.md`, `reference/exit-codes.md` and `reference/artifacts.md`; `mdbook build book/en` and `mdbook build book/pt` both built |
| 64 | `REGRESSION.md` records exact executed gates, defects, deviations and residual risks | `DARE/cycles/017-rag-retrieval-security/REGRESSION.md` — §1 gates with commands and results, §4 four defects found and fixed, §5 three defects in my own tests, §6 the one deviation, §7 five residual risks |
| 65 | `PROOF.md` maps all 66 criteria to executed evidence | this file; every row names a test, a workflow step or an artifact that ran |
| 66 | no PR opened before final branch push and local job green | no pull request existed at any point during implementation; the branch was pushed and the PR opened only after `rag-security-2026` passed all 41 steps locally and every gate in §1 of `REGRESSION.md` was green |

---

## What a PASS from this engine means

> No RAG/retrieval-security invariant violation was observed for the tested
> vectors under the recorded conditions.

It does not mean RAG is secure, that leakage is impossible, that a vector
database is safe, or that no retrieval attack is possible. No artifact this
cycle produces says any of those, and the wording is enforced at write time
rather than left to review.
