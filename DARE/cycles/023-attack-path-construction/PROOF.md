# Cycle 023 — Proof

**Cycle status:** COMPLETE — pending human final review  
**Baseline:** `main @ 32909ea` (314 suites, 4 224 tests) → Cycle 023 head (see §8 for measured totals)

Every acceptance item below maps to a test or a command that was **executed**.
`python scripts/k23/verify_proof_citations.py` checks that every test name cited here
exists.

## 1. Objectives (DESIGN §2)

| # | Objective | Evidence |
|---|---|---|
| O-01 | Construction from real artifacts, no hand-written facts | `attack_path_lab`: 26 scenarios, each run through the real binary from the engines' own shipped scenarios. The harness refuses any file that looks like graph input, and declared edges unless `lab.json` justifies them. `every_fixture_bundle_binds` binds every committed bundle (real CLI output) |
| O-02 | Path recall on ground truth | `attack_path_lab`: every expected entry → target path of APL-001..026 is reported with its exact failed properties, and every `absent` path is absent |
| O-03 | No invented edge | `invariant_1_edge_evidence_rules_hold` (every edge cites an evidence id, an `input:<engine>:<hex>` pin or a model line); `declared_edges_and_trust_boundaries_come_from_the_model`; the per-engine row tests in `projection_tables.rs` (`tool_rows` … `multi_turn_rows`) |
| O-04 | No false `CONTROLS_HELD` | `the_state_is_never_better_than_the_weakest_edge` (every combination of up to 4 edges × 5 per-edge states); `structural_edges_need_no_guard_but_other_unguarded_edges_do`; `an_unguarded_edge_leaves_the_path_undecided_and_a_held_path_is_held`; `invariant_6_a_doctored_control_state_is_refused`; `narrowing_never_improves_a_verdict_beyond_inconclusive` |
| O-05 | Honest truncation | `the_per_pair_cap_is_reported_and_keeps_the_shortest`, `the_global_cap_and_the_step_bound_are_reported` (`truncated`, `stopped_by`, truncated pairs); `exit_2_when_a_feasible_path_is_undecided_or_enumeration_is_cut`; chokepoints `partial` when cut (`chokepoints_are_the_edges_every_failed_path_shares`) |
| O-06 | Determinism | `the_same_artifacts_in_any_order_build_byte_identical_output`; `ids_and_order_do_not_depend_on_input_order` (facts shuffled 10 times); `the_same_inputs_give_byte_identical_files`; `attack_path_lab` runs every scenario twice, with the artifacts reversed, and requires all six files byte-identical |
| O-07 | Provenance binding (every mismatch refused) | `an_edited_scenario_no_longer_binds`, `an_edited_pinned_sub_document_names_itself`, `a_one_byte_change_to_a_static_document_is_refused`, `a_changed_manifest_changes_the_rebuilt_evidence_and_is_refused`, `a_multi_turn_transcript_must_match_its_result`, `a_remote_result_must_match_the_022_schema`, `refusal_corpus_bundles_and_binding`; the in-image binary exits 3 on a tampered bundle (§7) |
| O-08 | Compatibility | `v1_output_is_byte_identical_to_the_baseline` (5 golden digests); `a_v2_path_is_eligible_exactly_when_the_v1_path_with_its_id_is`; `v2_impact_factors_equal_v1_on_the_v1_fixtures`; `dare-adversarial` and `dare-continuous` suites unchanged and green; `the_registries_and_every_profile_are_unchanged`; `the_engine_crates_are_unchanged` |
| O-09 | Boundedness | `a_two_thousand_node_graph_is_built_and_enumerated_within_bounds`: 2 000 nodes, 10 000 edges, 50 × 50 pairs, about 0.6 s in release (bound 10 s). `every_bound_refuses_zero_and_values_above_its_maximum`; `limits_and_unknown_fields_are_refused` |

## 2. Functional requirements (DESIGN §4)

| ID | Requirement | Evidence |
|---|---|---|
| RF-01 | Projectors 014–020, closed tables, `unprojected` counted | `tool_rows`, `tool_security_flags_follow_the_declared_operation_class`, `identity_rows`, `identity_principal_kinds_map_to_node_types`, `memory_rows`, `rag_rows`, `mcp_auth_rows`, `supply_chain_tables_are_exhaustive` (every enum variant), `supply_chain_rows_and_entity_narrowing`, `a2a_rows` |
| RF-02 | Projectors 013, 021, 022 | `prompt_injection_rows`, `multi_turn_rows`, `remote_multi_turn_runs_are_counted_not_guessed`, `a_remote_result_must_match_the_022_schema`; APL-026 asserts `dynamic_authorized` provenance; `only_the_cli_depends_on_this_crate` and `no_network_process_or_scheduler_dependency_is_declared` (no `dare-remote-validation`) |
| RF-03 | Input binding | `every_fixture_bundle_binds`, `static_bundles_verify_each_document_and_the_rebuilt_evidence`, `simulated_supply_chain_and_a2a_runs_are_rebuilt_through_the_engine`, `a_missing_scenario_is_refused_for_every_scenario_engine`, `the_loaders_match_the_engines_on_every_shipped_scenario` (127 scenario files) |
| RF-04 | System model | `the_schema_compiles_and_the_base_model_is_admitted`, `limits_and_unknown_fields_are_refused`, `the_file_loader_refuses_links_and_oversize`, `the_digest_ignores_key_order_and_whitespace_but_not_content` |
| RF-05 | Entity resolution by alias only | `the_same_local_id_in_two_runs_stays_two_nodes_without_an_alias`, `rule_3_one_local_id_maps_to_one_entity`, `an_alias_to_an_entity_of_another_type_is_refused`, `merged_nodes_that_disagree_on_their_tenant_are_refused`; APL-024 (no alias: two `user-7` nodes, no path) and APL-025 (alias: one path) |
| RF-06 | Edge evidence state | `invariant_1_edge_evidence_rules_hold`, `identical_edges_merge_by_the_stronger_evidence_and_unioned_guards`, `declared_edges_and_trust_boundaries_come_from_the_model` |
| RF-07 | Property binding per edge | `every_guard_property_exists_in_the_registries`, `run_scope_applies_the_decided_verdict_and_skips_undecided_properties`, `a_failure_naming_an_entity_fails_only_that_entitys_edges`, `a_failure_naming_no_entity_stays_run_scoped`, `delegated_failures_attach_only_to_their_entity_and_role` |
| RF-08 | Entry points and targets | `designations_follow_flags_then_the_model`, `a_cross_tenant_resource_is_a_target_for_an_entry_of_another_tenant`, `rule_5_a_designation_names_exactly_one_reference`; every lab expectation checks entry and target class |
| RF-09 | Path engine v2 | `paths_are_shortest_first_simple_and_validated`, `cycles_and_self_loops_do_not_repeat_nodes`, O-05 |
| RF-10 | Authority continuity | `c1_delegation_hands_authority_to_the_delegatee` … `c6_structural_edges_never_break_a_path` (each positive and negative), `discontinuous_paths_are_listed_apart`, `a_path_must_be_in_the_list_of_its_feasibility`; APL-022..023 are `DISCONTINUOUS` through the binary |
| RF-11 | Control state per path | O-04; `one_failing_guard_among_passing_guards_fails_the_edge` |
| RF-12 | Chokepoints | `chokepoints_are_the_edges_every_failed_path_shares`, `a_single_failed_path_makes_every_non_structural_edge_a_chokepoint_and_disjoint_paths_none`; the lab checks that every chokepoint lies on a feasible path |
| RF-13 | Artifacts | `exit_0_writes_six_files_when_nothing_is_failed_undecided_or_cut`, `the_projection_report_is_bound_to_its_graph`, `views_label_state_in_text_and_escape_hostile_labels`, `every_marker_and_a_bearer_credential_is_refused` (sweep before any write), `exit_1_on_an_internal_write_failure_before_any_file_is_written` |
| RF-14 | CLI | `help_names_the_bounds_and_offers_no_widening_flag`; exit codes 0, 1, 2 and 3 each covered in `attack_paths_cli.rs`; `validate attack-graph --facts` unchanged (`v1_output_is_byte_identical_to_the_baseline`) |
| RF-15 | ATTACK-PATH-LAB (≥ 25, control twins) | `attack_path_lab`: 26 scenarios; every chain class A–F has an attack scenario and a control twin that asserts the attacked properties no longer fail; NOT_TESTED twins APL-003, 007, 011, 015 |
| RF-16 | Product integration (SHOULD, BQ-3 (a)) | `a_v2_graph_is_validated_and_written_as_the_run_graph`, `without_the_field_the_attack_graph_artifact_is_unchanged`, `a_doctored_v2_graph_is_refused_without_echoing_it`, `the_path_is_confined_to_the_target_and_exclusive_with_v1_facts`, `the_product_does_not_depend_on_the_attack_path_engine` |
| RF-17 | Cycle 009 / 010 compatibility | `a_v2_path_is_eligible_exactly_when_the_v1_path_with_its_id_is` (`ensure_path_eligible`, every adversarial plan, `roe_valid` both ways); `dare-adversarial` and `dare-continuous` suites green |
| RF-18 | Path-engine defect correction (§4.9) | `a_path_naming_a_missing_edge_is_an_error_not_a_panic`; `v1_output_is_byte_identical_to_the_baseline`; REGRESSION "Path-engine defect correction" |

## 3. Corpora (DESIGN §4.5 and §4.8)

**§4.5 ATTACK-PATH-LAB.** `crates/dare-agent-security-cli/tests/fixtures/attack-path-lab/`
holds 26 scenarios in 9 classes. The README maps each class to its engines. REGRESSION
R-16..R-19 record where the realized chains differ from the Design table, and why.

| Class | Scenarios | Result |
|---|---|---|
| A document → principal → cross-tenant document / credential | 001–004 | `CONTROL_FAILED` on content trust + tenant isolation / privilege amplification; control twin `CONTROLS_HELD` (exit 0); NOT_TESTED twin absent; ENTITY narrowing `CONTROL_UNDECIDED` |
| B memory write → recall → credential | 005–008 | `CONTROL_FAILED` on write trust, tenant boundary, provenance, recall authority; control twin paths absent |
| C peer → assistant → service identity → credential | 009–012 | `CONTROL_FAILED` on skill authorization, peer identity binding; control twin `CONTROL_UNDECIDED` |
| D package → build → assistant → credential | 013–015 | `CONTROL_FAILED` on BOM completeness; control twin `CONTROL_UNDECIDED` (the declared edge is never assessed) |
| E MCP token → server → upstream credential → resource | 016–018 | `CONTROL_FAILED` on credential separation, self-reported metadata, final operation binding; control twin `CONTROLS_HELD` |
| F untrusted input / cross-turn → destructive tool | 019–021 | `CONTROL_FAILED` on user-input instruction boundary, cross-turn continuity; control twin `CONTROLS_HELD` |
| G unexplained authority change | 022–023 | `DISCONTINUOUS` at the unexplained edge; excluded from gating and chokepoints |
| H alias-only merging | 024–025 | no path without an alias; one path with it |
| I authorized remote run | 026 | `dynamic_authorized` provenance, `MULTI_TURN_RESULT_ONLY` counted |

**§4.8 hostile and refusal corpus.**

| Row | Evidence |
|---|---|
| Input digest mismatch; tampered evidence | `refusal_corpus_bundles_and_binding`, `refusal_corpus_evidence_and_files`, `the_evidence_index_validates_every_record_and_every_cited_id` |
| Unknown engine | `detection_needs_exactly_one_known_result` |
| Oversized, over-deep, linked or escaping input | `admission_refuses_links_escapes_oversize_and_depth`, `a_path_through_a_linked_directory_that_leaves_the_root_is_refused`, `a_linked_artifact_directory_is_refused`, `depth_is_counted_per_level` |
| Hostile labels, credential shapes | `hostile_labels_are_escaped_in_the_views_and_credential_shaped_ids_are_hashed`, `unsafe_labels_are_replaced_by_the_hashed_token`, `a_secret_like_label_is_refused_by_the_views`, `no_error_message_echoes_input` |
| Model: conflicting alias, unknown entity, type clash, no rationale, over the maxima | `rule_2_an_alias_must_name_a_known_entity`, `rule_3_one_local_id_maps_to_one_entity`, `an_alias_to_an_entity_of_another_type_is_refused`, `rule_6_declared_edges_carry_their_justification_and_known_entities`, `limits_and_unknown_fields_are_refused`, `refusal_corpus_system_model_and_bounds` |
| Path explosion, cycles, self-edges | `the_global_cap_and_the_step_bound_are_reported`, `cycles_and_self_loops_do_not_repeat_nodes`, O-09 |

## 4. Non-functional requirements (DESIGN §5)

| ID | Evidence |
|---|---|
| RNF-01 | O-06 |
| RNF-02 | O-05, O-09; `every_bound_refuses_zero_and_values_above_its_maximum` |
| RNF-03 | `cargo test -p dare-agent-security --test attack_path_lab`: 26 scenarios (with double runs) in about 13 s locally in debug; the `attack-path-2026` job ran every step locally (task-041) |
| RNF-04 | `no_network_process_or_scheduler_dependency_is_declared`, `the_source_reaches_no_socket_process_or_thread_pool`, `only_the_cli_depends_on_this_crate`, `the_product_does_not_depend_on_the_attack_path_engine` |
| RNF-05 | `the_projection_report_is_bound_to_its_graph`; node and edge `provenance` (artifact index, original kind, JSON-pointer locator) validated by `invariant_5_provenance_and_guards_name_known_artifacts` |
| RNF-06 | §8 |

## 5. Security requirements (DESIGN §6)

| ID | Evidence |
|---|---|
| RS-01 | the admission tests (§3); `the_evidence_index_validates_every_record_and_every_cited_id`; `limits_and_unknown_fields_are_refused` |
| RS-02 | `every_marker_and_a_bearer_credential_is_refused`, `hostile_labels_are_escaped_in_the_views_and_credential_shaped_ids_are_hashed`, `no_error_message_echoes_input`; `scripts/k23/assert_no_real_credentials.py` |
| RS-03 | `admission_refuses_links_escapes_oversize_and_depth`, `a_linked_artifact_directory_is_refused`, `the_path_is_confined_to_the_target_and_exclusive_with_v1_facts` |
| RS-04 | `cargo audit` exit 0; the only new package in `Cargo.lock` is `dare-attack-path` (task-044) |
| RS-05 | O-04; `narrowing_never_improves_a_verdict_beyond_inconclusive` |
| RS-06 | RF-05 |
| RS-07 | `the_source_reaches_no_socket_process_or_thread_pool`; `help_names_the_bounds_and_offers_no_widening_flag` |
| RS-08 | O-05, O-09 |

## 6. Review decisions (APPROVAL)

| Decision | Evidence |
|---|---|
| Q1 new crate | `only_the_cli_depends_on_this_crate`; workspace member `crates/dare-attack-path` |
| Q2 pinned inputs `STATICALLY_PROVEN`, model `INFERRED` | `invariant_1_edge_evidence_rules_hold`, `declared_edges_and_trust_boundaries_come_from_the_model` |
| Q3 019 rebuilt through the engine's public API | `static_bundles_verify_each_document_and_the_rebuilt_evidence`, `simulated_supply_chain_and_a2a_runs_are_rebuilt_through_the_engine` |
| Q4 Cycle 008 enums kept, closed table | `supply_chain_tables_are_exhaustive`, `produced_ids_match_the_v1_node_id_pattern_and_never_collide` |
| Q5 v1 defects fixed in v2 only; `unwrap` removed without output change | RF-18 |
| Q6 O-1 schema-id bridges out of scope | `the_engine_crates_are_unchanged`; REGRESSION "Baseline observations" |
| Q7 chokepoints as counts, `partial` when cut | RF-12 |
| BQ-1 structural edges exempt | `structural_edges_need_no_guard_but_other_unguarded_edges_do` |
| BQ-2 run-scoped ids, one `sut` per run | `the_same_local_id_in_two_runs_stays_two_nodes_without_an_alias`; APL-019..021 alias the prompt-injection and multi-turn `sut` to one assistant |
| BQ-3 (a) product reads v2 | RF-16 |
| BQ-4 exit 2 on failed, undecided or truncated | `exit_2_when_a_feasible_path_is_undecided_or_enumeration_is_cut`; `exit_0_writes_six_files_when_nothing_is_failed_undecided_or_cut` |

## 7. Container

The builder-stage `docker build` of the repository `Dockerfile` compiled the whole
workspace with Rust 1.88 inside the image, `dare-attack-path` included. The in-image
binary ran with networking disabled (`--network none`):
- on the identity bundle with an edited `inputs/scenario.json`, it refused with exit 3
  and wrote nothing;
- on the unedited bundle (control), it exited 2 and wrote six files (task-044).

## 8. Measured totals

The completion gate was run on the final cycle tree:

| Check | Command | Result |
|---|---|---|
| Format | `cargo fmt --all --check` | exit 0 |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| Tests | `cargo test --workspace` | **332 suites, 4 351 passed, 0 failed, 5 ignored** (baseline 314 / 4 224 / 0 / 4; +18 suites, +127 tests; the added ignored test is the static-input generator) |
| Advisories | `cargo audit` | exit 0 |
| Secrets | `python scripts/k23/assert_no_real_credentials.py` | exit 0 (38 shipping files, 17 test files, 139 artifacts) |
| Citations | `python scripts/k23/verify_proof_citations.py` | every cited name verified |
| Books | `mdbook build book/en`, `mdbook build book/pt` | both built |
| Canvas | `python scripts/regen-canvas.py --check` | current |
| Cycle job | `python scripts/run-ci-job-locally.py .github/workflows/ci.yml attack-path-2026` | 14 of 14 steps PASS |
| Container | builder-stage image, in-image refusal | see §7 |
