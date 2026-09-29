# Cycle 024 — Proof

**Cycle status:** COMPLETE — pending human final review (R-6 open)  
**Baseline:** `main @ d125081` (332 suites, 4 351 passed, 5 ignored) → Cycle 024 head
(see §8 for measured totals)

Every acceptance item below maps to a test or a command that was **executed**.
`python scripts/k24/verify_proof_citations.py` checks that every test name cited here
exists.

## 1. Objectives (DESIGN §2)

| # | Objective | Evidence |
|---|---|---|
| O-01 | Reach from real evidence | `every_blast_radius_lab_scenario_matches_its_expectation`: 20 scenarios. Each graph is built from an ATTACK-PATH-LAB scenario through the real binary (`build_apl` refuses anything that looks like hand-written graph input); no graph file is committed |
| O-02 | Reach recall on ground truth | the same test. Every expected target of BRL-001..020 is reported with its class, exposure, route, control state, failed properties and frontier properties, and every `absent` target is absent. The expectations were written from the graphs before the first run, and all matched (R-7) |
| O-03 | No false containment | `no_random_graph_yields_a_false_containment`: 200 fixed-seed random graphs, an independent exhaustive walk enumeration, 3014 pairs (1657 `CONTAINED`, 1357 `EXPOSED`), **0 false `CONTAINED`**. Also `every_contained_target_has_a_non_empty_frontier`, `a_truncated_uncontained_search_never_claims_containment`, `invariant_6_exposure_matches_the_routes_and_truncation` |
| O-04 | No invented reach | `invariant_2_routes_are_walks_of_known_ids_from_the_seed`, `invariant_3_every_step_is_explained`. Every engine document and every lab document passes `validate_blast_radius` before it is written or compared. `continuity_decides_every_step` |
| O-05 | Honest truncation | `depth_cut_and_state_bounds_are_reported` (`MaxStates`, `MaxStatesTotal`, `depth_cut`); `exit_2_when_a_target_is_exposed_or_a_search_is_truncated`; BRL-020 (`truncated`, `CONTAINMENT_UNKNOWN`, exit 2); `an_exhausted_budget_marks_the_delta_partial`; `a_state_explosion_stops_at_the_total_budget_and_says_so` |
| O-06 | Determinism | `ten_shuffles_give_identical_documents`; `two_runs_give_byte_identical_files`; the lab runs every scenario twice and requires all four files byte-identical |
| O-07 | Compatibility | `every_attack_path_lab_output_keeps_its_baseline_digest` (156 digests over the frozen runs, R-1) and `the_frozen_runs_match_the_lab`; `attack_path_lab.rs`, `attack_paths_cli.rs` and `attack_path_compatibility.rs` unchanged and green (`the_engine_crates_are_unchanged`, `the_registries_and_every_profile_are_unchanged`, `a_v2_path_is_eligible_exactly_when_the_v1_path_with_its_id_is`) |
| O-08 | Boundedness | `a_lab_shaped_graph_is_analysed_in_under_ten_seconds`: 2 000 nodes, 10 000 edges, 64 seeds, both views and the delta, 8.4–9.2 s in release (bound 10 s). `a_state_explosion_stops_at_the_total_budget_and_says_so`: no bound is overshot. **The margin is thin (R-6, open for Review)** |

## 2. Functional requirements (DESIGN §4)

| ID | Requirement | Evidence |
|---|---|---|
| RF-01 | Graph input | `a_graph_that_fails_v2_validation_is_refused`; `refusal_corpus_graph_files` (missing, symlink, oversize, too deep, non-graph, edited after sealing); `admission_refuses_links_size_depth_and_garbage` |
| RF-02 | Compromise scenario | `the_compromise_schema_enforces_its_shape`, `seeds_resolve_by_node_or_entity_and_sort`, `every_seed_rule_refuses_with_its_variant`, `refusal_corpus_scenarios_and_bounds` (including `AmbiguousSeed` on a resealed graph) |
| RF-03 | Seed from entry points (SHOULD) | `entry_points_become_seeds_and_misfits_are_skipped`, `entry_point_mode_seeds_every_fitting_entry`; BRL-019 |
| RF-04 | Compromise kinds | `the_kind_table_is_complete`, `initial_states_follow_the_kind_table`, `a_component_continues_through_unnamed_access_credentials_and_delegation` (R-3) |
| RF-05 | Continuity-respecting reach | `continuity_decides_every_step`, `walks_revisit_a_node_only_under_new_authority_and_cycles_terminate`, `invariant_3_every_step_is_explained`; BRL-017/018 (`refused_steps` ≥ 1, target absent) |
| RF-06 | Two views | `the_uncontained_view_skips_only_held_edges` (PASS skipped, FAIL/INCONCLUSIVE/ERROR/unguarded crossed, structural edges traversable), `exposure_follows_the_uncontained_view` |
| RF-07 | Witness routes | `the_witness_is_the_first_shortest_walk_in_id_order`, `invariant_4_control_fields_are_recomputed` (control fields from `path_control`) |
| RF-08 | Containment frontier | `invariant_7_the_frontier_is_the_held_edges_of_the_structural_route`, `totals_and_frontier_count_seed_target_pairs`; every `CONTAINED` lab expectation names its frontier properties (`the_lab_keeps_its_class_contract`) |
| RF-09 | Impact facts | `impact_counts_follow_each_view`, `cross_tenant_candidates_need_a_seed_tenant`, `invariant_8_counts_are_recomputed` (R-4) |
| RF-10 | Remediation delta (SHOULD) | `the_delta_counts_targets_each_failed_edge_would_contain`, `the_delta_recounts_through_alternatives_and_orders_by_count`, `the_delta_keeps_at_most_the_bound`, `an_exhausted_budget_marks_the_delta_partial`; BRL-014/015 and BRL-001/016: the delta count equals what the control twin contains |
| RF-11 | Artifacts | `exit_0_writes_four_files_when_nothing_is_exposed`, `the_result_document_round_trips_and_carries_no_score`, `hostile_labels_render_escaped_in_both_views`, `views_draw_only_the_reached_subgraph_with_text_tags`, `the_summary_counts_routes_and_ends_with_what_it_does_not_claim`, `a_credential_shaped_value_is_never_written` |
| RF-12 | CLI | `help_names_every_flag_and_offers_nothing_else`, `seeding_is_one_of_a_scenario_or_the_entry_points`; exit codes 0, 1, 2 and 3 are each covered in `blast_radius_cli.rs` (`exit_1_on_an_internal_write_failure`) |
| RF-13 | BLAST-RADIUS-LAB (≥ 20, control twins) | `every_blast_radius_lab_scenario_matches_its_expectation` (20 scenarios), `the_lab_keeps_its_class_contract`: every attack class A–G has a control twin |
| RF-14 | Product integration (COULD) | out of scope for v1 (Q6 (b)) |
| RF-15 | Shared continuity rule | `c1_delegation_hands_authority_to_the_delegatee` … `c6_structural_edges_never_break_a_path` (moved unchanged) and `step_c1_hands_authority_to_the_delegatee` … `step_c5_and_c6`; O-07 |

## 3. Non-functional requirements (DESIGN §5)

| ID | Evidence |
|---|---|
| RNF-01 Determinism | O-06 |
| RNF-02 Boundedness | `every_bound_refuses_zero_and_values_above_its_maximum`, `options_lower_the_bounds_and_are_refused_above_the_maximum`, `depth_cut_and_state_bounds_are_reported` |
| RNF-03 Lab performance | the full lab, including building the 13 APL graphs it uses, runs in about 10 s locally (bound 60 s) |
| RNF-04 Containment | `the_dependencies_are_exactly_the_blueprint_list`, `only_the_cli_depends_on_this_crate`, `the_source_reaches_no_socket_process_thread_or_environment` |
| RNF-05 Explainability | O-04 |
| RNF-06 Quality gate | §8 |

## 4. Security requirements (DESIGN §6)

| ID | Evidence |
|---|---|
| RS-01 Untrusted, bounded, validated inputs | RF-01, RF-02 |
| RS-02 Labels escaped, no credential shape, no echo | `no_error_message_echoes_input`; canaries in `refusal_corpus_graph_files` and `refusal_corpus_scenarios_and_bounds`; `hostile_display_names_are_escaped_in_the_views`; `a_credential_shaped_value_is_never_written`; `python scripts/k24/assert_no_real_credentials.py` |
| RS-03 Only the two supplied paths, no symlink, no URI | `admission_refuses_links_size_depth_and_garbage`, `refusal_corpus_graph_files` |
| RS-04 No new third-party dependency, audit clean | `the_dependencies_are_exactly_the_blueprint_list`. The `Cargo.lock` diff against the baseline adds only `dare-blast-radius`. `cargo audit` exit 0 |
| RS-05 No secret, no environment | `the_source_reaches_no_socket_process_thread_or_environment` |
| RS-06 No false containment | O-03 |
| RS-07 No score | `the_result_document_round_trips_and_carries_no_score`; summary and docs say the delta is "not a ranking of risk" |
| RS-08 Analysis only | `the_source_reaches_no_socket_process_thread_or_environment`; `the_job_references_no_secret_and_no_network_target`; the in-image run with `--network none` (§7) |
| RS-09 Bounded resource use | O-05, O-08 |

## 5. Review decisions (APPROVAL)

| Decision | Evidence |
|---|---|
| Q1 (a) new crate, one continuity rule | RNF-04, RF-15 |
| Q2 (a) v2 graph input only | RF-01 |
| Q3 (a) no weighting | RS-07 |
| Q4 (a) A2A delegated-subject limitation out of scope | continuity unchanged (RF-15) |
| Q5 (a) delta SHOULD, ≤ 64, counts | RF-10 |
| Q6 (b) product integration out of scope | RF-14 |
| Q7 (a) two views | RF-06 |
| BQ-1 witness = first BFS reach over sorted adjacency | `the_witness_is_the_first_shortest_walk_in_id_order` |
| BQ-2 `CONTAINMENT_UNKNOWN` | `a_truncated_uncontained_search_never_claims_containment`, BRL-020 |
| BQ-3 states keyed by `(node, principal, actors)` | `walks_revisit_a_node_only_under_new_authority_and_cycles_terminate` (R-2: walks) |
| BQ-4 no cross-tenant targets without a seed tenant | `cross_tenant_candidates_need_a_seed_tenant` |
| BQ-5 exit 2 on EXPOSED or truncation | `exit_2_when_a_target_is_exposed_or_a_search_is_truncated`, `exit_0_writes_four_files_when_nothing_is_exposed` |

## 6. Frozen boundaries

| Boundary | Evidence |
|---|---|
| No engine crate change | `the_engine_crates_are_unchanged` |
| Cycle 023 / 008 outputs unchanged | O-07; `v1_output_is_byte_identical_to_the_baseline` |
| C1–C6 and the control rule unchanged | the six moved tests are unchanged; the 156 goldens |
| `CONTAINED` only within bounds and when not truncated | O-03, BQ-2 |
| No score | RS-07 |
| No network, engine or `dare-attack-path` dependency | RNF-04 |
| No property or profile change | `the_registries_and_every_profile_are_unchanged` |

## 7. Container

The builder-stage `docker build` of the repository `Dockerfile` compiled the whole
workspace with Rust 1.88 inside the image, `dare-blast-radius` included. The in-image
binary ran with networking disabled (`--network none`) and the graph mounted read-only:
- on a graph edited after sealing, it refused with exit 3 and created no output
  directory;
- on the unedited graph (control), it exited 2 and wrote the four files (task-026).

## 8. Measured totals

The completion gate was run on the final cycle tree:

| Check | Command | Result |
|---|---|---|
| Format | `cargo fmt --all --check` | exit 0 |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| Tests | `cargo test --workspace` | **347 suites, 4 433 passed, 0 failed, 9 ignored**. Against the baseline (332 / 4 351 / 0 / 5): +15 suites, +82 tests. The added ignored tests are the two release-only scale tests in debug builds, the goldens regenerator and the lab `dump` tool |
| Release scale | `cargo test -p dare-blast-radius --release --test scale` | both pass (O-08, R-6) |
| Advisories | `cargo audit` | exit 0 |
| Secrets | `python scripts/k24/assert_no_real_credentials.py` | exit 0 (17 shipping files, 17 test files, 166 artifacts) |
| Citations | `python scripts/k24/verify_proof_citations.py` | every cited name verified (69) |
| Books | `mdbook build book/en`, `mdbook build book/pt` | both built |
| Canvas | `python scripts/regen-canvas.py --check` | current |
| Cycle job | `python scripts/run-ci-job-locally.py .github/workflows/ci.yml blast-radius-2026` | 13 of 13 steps PASS |
| Container | builder-stage image, in-image refusal | see §7 |

## 9. Open for Review

- **R-6.** O-08 is met (8.4–9.2 s against 10 s), but the margin is thin. A deterministic
  threaded variant, which measured 7.3 s / 3.4 s, needs an amendment to the Blueprint's
  RS-08 source scan, which forbids `std::thread`. It is kept in
  `EXECUTION/task-018-parallel-option.patch` and was not applied.
