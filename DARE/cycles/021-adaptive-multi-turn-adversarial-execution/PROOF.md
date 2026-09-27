# Cycle 021 — Proof

**Cycle status:** COMPLETE — pending human final review  
**Baseline:** `main @ 4ca06b2` (3 767 tests) → Cycle 021 head (see §7 for measured totals)

Every acceptance item below maps to a test or command that was **executed**. Test
names are verified to exist by `python scripts/k21/verify_proof_citations.py`.

## 1. Objectives (DESIGN §2)

| # | Objective | Evidence |
|---|---|---|
| O-01 | Multi-turn-only failures detected | `every_entry_meets_its_class_contract_in_every_staged_mode`: all 15 ATTACK entries give FAIL, with their own invariant failing and deciding turns present |
| O-02 | No false PASS from early stop | `no_pass_is_ever_produced_for_a_gap_or_fault_in_any_mode`, `no_pass_without_every_conversation_reaching_a_terminal`, `another_invariant_that_is_inconclusive_for_a_real_reason_blocks_pass` |
| O-03 | Determinism | `every_entry_produces_byte_identical_artifacts_across_ten_runs` (≥ 40 entry/mode pairs × 10 runs), `refusals_are_deterministic_too`, `responses_are_deterministic` |
| O-04 | Closed adaptivity (0 turns outside the graph) | `every_executed_turn_is_a_graph_node_reached_by_a_declared_edge`, `a_turn_for_a_different_node_is_a_strategy_fault`, `the_graph_schema_has_no_generation_field_and_no_unclassifiable_edge` |
| O-05 | Zero egress / zero state change | `every_turn_passes_the_cycle_009_controls_and_changes_nothing`, `the_budget_allows_no_write_state_change_or_egress`, `the_snapshot_never_reports_state_change_or_egress`; the result schema pins both to `0` |
| O-06 | Controls stay green | the same contract test: all 12 CONTROL entries give PASS in every staged mode |
| O-07 | Compatibility | `every_pre_existing_registry_entry_is_byte_for_byte_unchanged`, `every_earlier_profile_is_unchanged`, `no_earlier_profile_denominator_moved`; `cargo test --workspace` green |

## 2. Functional requirements (DESIGN §4)

| ID | Requirement | Evidence |
|---|---|---|
| RF-01 | Conversation model with chained digests | `each_turn_links_to_the_previous_one`, `tampering_is_detected_at_the_first_altered_turn`, `raw_content_is_never_stored_only_its_digest` |
| RF-02 | Stateful adapter contract | `leaky_agent_carries_canaries_into_the_next_conversation_and_isolated_does_not` (one adapter instance across conversations); `this_crate_declares_no_network_or_generation_dependency` |
| RF-03 | Finite DAG strategy graph, digest-bound | `rule_1_version_and_hostile_content` … `rule_11_approval_must_match_the_role` (one test per rule), `the_digest_is_stable_across_runs_and_declaration_order` |
| RF-04 | Deterministic branch selection | `transitions_follow_declared_edges_only`, `the_observation_selects_the_next_node` |
| RF-05 | Closed observation classification | `rows_3_to_9_in_precedence_order`, `row_2_contradictory_signals_are_unclassifiable_but_the_action_is_kept`, `canaries_match_exactly_in_output_and_action_arguments` |
| RF-06 | Invariants I01–I07 | 20 tests in `invariant::tests`, one per FAIL/PASS/INCONCLUSIVE cell of Blueprint §4.8 (e.g. `i05_every_fail_condition`, `i07_fail_when_a_canary_crosses_into_another_principals_conversation`) |
| RF-07 | Path-complete PASS | `no_pass_without_every_conversation_reaching_a_terminal`, `i01_inconclusive_when_incomplete_or_without_a_baseline_refusal` |
| RF-08 | Concrete-FAIL preservation | `a_fail_on_any_invariant_survives_a_pass_on_the_primary`, `i01_fail_decides_even_when_the_run_did_not_complete` |
| RF-09 | REPLAY / SIMULATED / LOCAL_SYNTHETIC | `recorded_simulated_runs_replay_to_the_same_verdict`, `a_substituted_target_trips_the_kill_switch`, `the_budget_stops_the_next_turn_as_budget_exhausted` |
| RF-10 | Replay binding refuses tampering | `reordered_duplicated_and_gapped_indices_are_refused_at_binding`, `a_recorded_chain_digest_that_disagrees_is_refused_as_tampering`, `a_transcript_for_other_graphs_is_refused_at_binding` |
| RF-11 | MULTITURN-LAB (≥ 40, class not verdict) | `the_corpus_has_at_least_forty_entries_with_unique_ids` (45), `every_attack_theme_has_a_control`, `every_invariant_has_an_attack_and_a_control`, `no_fixture_states_its_own_outcome` |
| RF-12 | Hostile / refusal corpus | 13 tests in `tests/hostile_refusal.rs`, one per DESIGN §4.5 bullet (e.g. `any_cycle_is_refused`, `a_node_carrying_a_generator_directive_is_refused`) |
| RF-13 | CLI with a local-only surface | `the_help_offers_no_flag_that_could_reach_or_generate`, `refusals_exit_three_and_write_nothing`, `a_control_passes_and_writes_every_artifact` |
| RF-14 | Artifacts admitted before write | `output_budget_counts_the_result_artifact`, `over_budget_output_is_refused_and_not_charged` |
| RF-15 | Seven properties in existing families | `exactly_the_seven_approved_properties_were_added`, `no_multi_turn_namespace_was_introduced`, `every_new_property_is_gated_by_the_existing_stateful_agent_predicate` |
| RF-16 | Composition without taking verdict authority | `this_crate_takes_no_single_turn_engine_as_a_dependency`, `i04_same_turn_emission_is_delegated_not_failed` |
| RF-17 | Coverage and profile | `the_profile_matches_the_approval_exactly`, `decided_invariants_are_applicable_and_the_rest_are_not_tested_never_not_applicable`, `the_report_builds_over_the_seven_property_profile` |
| RF-18 | Strategy explainability | `the_summary_names_the_path_and_the_unreached_nodes` |

## 3. Security requirements (DESIGN §6)

| ID | Control | Evidence |
|---|---|---|
| RS-01 | Admission before use | `an_oversized_document_is_refused_before_parsing`, `nesting_beyond_the_depth_bound_is_refused_by_the_depth_check`, `an_unknown_field_is_rejected_and_the_value_is_not_echoed` |
| RS-02 | No raw content, canary or secret in artifacts | `the_excerpt_is_redacted_bounded_and_the_text_is_not_retained`, `records_carry_no_turn_content_or_canary`, `the_result_validates_against_its_schema_and_carries_no_raw_content` |
| RS-03 | Authority only from verified evidence | `i03_fail_on_accepted_authority_or_an_over_privileged_action`, `applicability_follows_the_blueprint_table` |
| RS-04 | No HIGH/CRITICAL advisory | `cargo audit`: exit 0 (§7) |
| RS-05 | No secrets or endpoints accepted | `credential_shaped_values_are_refused_but_prose_about_them_is_not`, `urls_are_inert_text_and_credentials_are_refused`; `scripts/k21/assert_no_real_credentials.py` |
| RS-06 | Closed adaptivity | `every_forbidden_field_group_is_refused_by_name`, `a_node_carrying_a_generator_directive_is_refused`, `the_graph_schema_has_no_generation_field_and_no_unclassifiable_edge` |
| RS-07 | No LLM / RNG / network | `this_crate_declares_no_network_or_generation_dependency`, `the_check_catches_a_forbidden_dependency_when_one_is_added` |
| RS-08 | Adaptivity cannot widen scope | `raising_any_bound_is_refused`, `bounds_above_the_hard_maxima_do_not_parse`, `the_step_carries_identifiers_only` |
| RS-09 | No false PASS | `no_pass_is_ever_produced_for_a_gap_or_fault_in_any_mode`, `a_non_applicable_invariant_says_so_and_never_passes` |
| RS-10 | Output admission including the result itself | `output_budget_counts_the_result_artifact` |

## 4. Compatibility (DESIGN §12)

| # | Claim | Evidence |
|---|---|---|
| 1 | Property IDs and denominators preserved | `every_pre_existing_registry_entry_is_byte_for_byte_unchanged` (baseline digest over 58 entries), `every_earlier_profile_is_unchanged` (10 digests), `no_earlier_profile_denominator_moved` |
| 2 | Cycle 009 controls on every LOCAL_SYNTHETIC turn | `every_turn_passes_the_cycle_009_controls_and_changes_nothing`, `a_substituted_target_trips_the_kill_switch` |
| 3 | No reinterpretation of Cycles 013–020 | `this_crate_takes_no_single_turn_engine_as_a_dependency`; the earlier lab suites pass unchanged under `cargo test --workspace` |
| 4 | Cycle 018 aggregation and Cycle 001 contracts | `a_fail_on_any_invariant_survives_a_pass_on_the_primary`, `every_verdict_produces_valid_cycle_001_evidence` |
| 5 | No network, credential, generation or LLM capability | `this_crate_declares_no_network_or_generation_dependency`, `the_help_offers_no_flag_that_could_reach_or_generate` |
| 6 | PR-open-only CI | `the_ci_trigger_is_still_pull_request_opened_only` |

Cycle 015/016 family tests were adjusted by Product Owner decision (see
`APPROVAL.md` and `REGRESSION.md` §7). The new guards
`the_only_later_identity_family_members_are_the_named_cycle_021_additions` and
`the_only_later_memory_family_members_are_the_named_cycle_021_additions` keep
those families closed to anything other than the named additions.

## 5. CI gate

`python scripts/run-ci-job-locally.py .github/workflows/ci.yml multi-turn-security-2026`
reports **all 12 steps PASSED**:
- unit tests;
- the lab contract with replay equivalence;
- the hostile corpus;
- determinism;
- compatibility;
- properties and profile;
- the Cycle 015/016 families;
- the CLI surface;
- the credential sweep;
- three offline CLI runs (PASS with exit 0, FAIL with exit 2, and a refusal with exit 3 that writes nothing).

## 6. Action image (Blueprint AD-10)

- **Static guarantee:** `embedded_assets_live_in_docker_copied_dirs`. Every
  `include_str!` in the crate resolves under a directory the root `Dockerfile` copies.
- **Container build (task-035):**
  - `docker build --target builder` compiled the whole workspace in release inside
    the image, with only the repository `Dockerfile`'s `COPY` lines providing files.
  - The resulting binary, run with `docker run --network none`, gave exit 0 / PASS
    for `multiturn-lab-001`, exit 2 / FAIL for `multiturn-lab-002` (local-synthetic)
    and exit 3 with nothing written for `multiturn-lab-041`.
- **Not built here:** the runtime stage's `apt-get` from `deb.debian.org`, which the
  session network policy denies. That stage copies only the binary, `vectors/` and
  the entrypoint, none of which Cycle 021 touches. The full image is proven by
  `action-e2e.yml` on the pull request.
- The repository `Dockerfile` is unchanged.

## 7. Measured totals

| Measure | Baseline (`4ca06b2`) | Cycle 021 | Delta |
|---|---|---|---|
| `cargo test --workspace` suites | 264 | 280 | +16 |
| Tests passed / failed / ignored | 3 767 / 0 / 3 | 3 955 / 0 / 3 | +188 |
| Workspace members | 20 | 21 | +1 (`dare-multi-turn-security`) |
| Registry v2 properties | 58 | 65 | +7 (appended) |
| Profiles | 10 | 11 | +1 (`multi-turn-security-baseline-2026`) |
| CI jobs in `ci.yml` | 18 | 19 | +1 (`multi-turn-security-2026`) |
| MULTITURN-LAB entries | — | 45 | 12 control, 15 attack, 11 gap, 2 fault, 5 refusal |

**Final gate:**

| Gate | Result |
|---|---|
| `cargo fmt --all --check` | green |
| `cargo clippy --workspace --all-targets -- -D warnings` | green |
| `cargo test --workspace` | 3 955 passed, 0 failed |
| `cargo audit` | exit 0 (305 crates) |
| `python scripts/run-ci-job-locally.py .github/workflows/ci.yml multi-turn-security-2026` | 13/13 steps |
| `mdbook build book/en` and `book/pt` (v0.4.40) | exit 0 |
| `python scripts/k21/verify_proof_citations.py` | every cited name verified |
| `python scripts/k21/assert_no_real_credentials.py` | clean |
| `python scripts/regen-canvas.py --check` | current |

## 8. What this proof does not claim

- It does not claim any agent is secure. A PASS covers only the path the target
  selected through an approved graph (`the_bounded_claim_never_overclaims`).
- It does not cover live or remote targets (Cycle 022), attack-path construction
  (Cycle 023), blast radius (Cycle 024) or runtime telemetry (Cycle 025).
- No turn was generated. No model, provider or network was used by the engine.
