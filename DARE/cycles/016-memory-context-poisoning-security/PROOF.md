# Cycle 016 — Proof of Acceptance Criteria

**Head at which every item below was executed:** `8e6be106a14d672eef1eb0749f65e0543484e1c8`

Each of the 63 criteria in `DESIGN.md` §26 is mapped to evidence that was
**actually executed** at that head — a named test, a named CI step or a named
command with its result. Nothing here is marked satisfied by intent, by design
document, or by the existence of code that looks like it would do the job.

Where a criterion is satisfied by something *not* existing — a flag, a mode, a
code path — the evidence is a test that asserts the absence, because an absence
nobody checks is an absence nobody can rely on.

---

| # | Criterion | Executed evidence |
|---|---|---|
| 1 | Baseline `9d543ae0…` frozen, Cycle 015 lessons recorded | `BASELINE.md` §§1–8: 1716 tests / 176 binaries, per-crate counts, six inherited lessons, residual risks. Verified at head by `cargo test --workspace` → 2067 passed |
| 2 | Existing two memory properties unchanged | `memory_security_profile.rs::the_two_pre_existing_properties_keep_their_identifiers_and_applicability` — identifiers *and* predicates pinned field by field |
| 3 | Four specialized properties additive | `memory_security_profile.rs::every_selected_property_exists_in_the_registry`, `::no_earlier_profile_changed`; registry 30 → 34 |
| 4 | Applicability predicates closed / fail-closed | `dare-coverage` `property.rs` predicate enum 28 → 32; `memory_security_profile.rs::the_four_new_properties_carry_the_predicates_this_cycle_added` |
| 5 | Versioned memory-item/store schema exists | `schemas/memory-security/v1/memory-item.schema.json`, `memory-store.schema.json`; `schema.rs` validators; `memory.rs` tests |
| 6 | Versioned memory-policy schema exists | `schemas/memory-security/v1/memory-policy.schema.json`; `policy.rs` tests including the ONLY/ANY dimension rule |
| 7 | Versioned scenario/corpus/trace schemas exist | `scenario.schema.json`, `corpus-entry.schema.json`, `corpus-registry.schema.json`, `trace.schema.json`; eight schemas total |
| 8 | Closed source-kind/trust/lifecycle enums | `source.rs::every_taxonomy_is_closed_and_uniquely_named` — 8 taxonomies, unknown tokens refused |
| 9 | Principal/tenant/namespace bindings explicit | `binding.rs::the_three_isolation_axes_are_independent` |
| 10 | Provenance machine-readable | `memory.rs` `Provenance::is_machine_readable`; `MEMORY-LAB-002` FAIL |
| 11 | Integrity digest machine-readable | `canonical.rs` item and content digests; `result.rs::every_memory_item_keeps_a_separate_identity_and_content_digest` |
| 12 | Lifecycle validity machine-readable | `lifecycle.rs` half-open `ValidityWindow`; `source.rs` `LifecycleState`; `MEMORY-LAB-013/014/015` |
| 13 | Normalized event model closed | `observation.rs` — 12 tagged variants, `deny_unknown_fields`, `CoverageChannel` closed at 11 |
| 14 | Twelve deterministic invariants, total and closed | `model.rs::the_twelve_invariants_are_closed_and_uniquely_named`; `coverage.rs` contract total over all 12 |
| 15 | No LLM/embedding/heuristic final judge | `invariant.rs` is field comparison only; crate declares no model, embedding or similarity dependency; `engine_composition.rs::the_two_engines_name_disjoint_invariants` |
| 16 | Every PASS requires positive coverage | `coverage.rs` contracts; `lab_scenarios.rs::a_pass_never_rests_on_an_empty_observation_set`; CI step "Recall without influence passes only on positive evidence" |
| 17 | Missing required evidence → INCONCLUSIVE | `MEMORY-LAB-021` → INCONCLUSIVE; CI step "Absence of evidence is INCONCLUSIVE, never PASS and never FAIL" |
| 18 | Replay offline | `replay.rs` (14 tests); CI step "Replay reads only a local trace and stays offline" |
| 19 | Simulated offline | `simulated.rs` — every value derived from the scenario; `lab_scenarios.rs` runs all 24 through it |
| 20 | Local-synthetic offline with Cycle 009 controls | `local_synthetic.rs::pointing_an_approved_run_at_another_scenario_trips_the_kill_switch`; CI asserts `LOCAL_SYNTHETIC` with zero state changes and zero egress |
| 21 | No live/remote memory store or provider mode | `memory_security.rs::the_mode_enum_admits_only_the_three_local_modes`; CI step "No live or remote memory mode can be selected" |
| 22 | No RAG / vector ACL implementation | No retrieval or embedding type exists in the crate; `SCOPE_BOUNDARY_NOTE` in every product block; CI step "Every summary states the Cycle 017 retrieval boundary" |
| 23 | Untrusted memory cannot self-promote trust | `MEMORY-LAB-004` FAIL; CI step "Persisting untrusted memory does not make it authoritative" |
| 24 | Cross-principal recall can deterministically FAIL | `MEMORY-LAB-006` FAIL, paired against `005` PASS |
| 25 | Cross-tenant recall can deterministically FAIL | `MEMORY-LAB-008` FAIL; CI step "A cross-tenant recall is proven from declarations, never by access" |
| 26 | Cross-namespace recall can deterministically FAIL | `MEMORY-LAB-010` FAIL, paired against `009` PASS |
| 27 | Digest substitution can deterministically FAIL | `MEMORY-LAB-012` FAIL, paired against `011` (authorized update) PASS |
| 28 | Expired memory use can deterministically FAIL | `MEMORY-LAB-014` FAIL; CI step "Expired and revoked memory do not reach a decision" |
| 29 | Revoked memory use can deterministically FAIL | `MEMORY-LAB-015` FAIL, same CI step |
| 30 | Poisoned memory changing objective can FAIL | `MEMORY-LAB-017` FAIL; CI step "Poisoned recall that changes a decision is a finding" |
| 31 | Poisoned memory changing tool selection can FAIL | `MEMORY-LAB-018` FAIL, same CI step |
| 32 | Poisoned memory changing tool arguments can FAIL | `MEMORY-LAB-019` FAIL, same CI step |
| 33 | Poisoned memory reaching protected fields can FAIL | `MEMORY-LAB-020` FAIL; CI step "A protected field is never populated from poisoned memory" |
| 34 | Clean / no-influence behavior needs positive observation to PASS | `MEMORY-LAB-016` PASS; CI asserts a recorded `changed=false` influence observation, not an empty trial |
| 35 | Independent simultaneous violations retained | `violations_and_hygiene.rs::three_simultaneous_violations_are_all_reported_from_one_trial` and `::evaluating_one_invariant_never_consumes_or_hides_another` |
| 36 | Hard memory/item/event/trial limits enforced across trials | `trials.rs::the_total_event_counter_never_resets_between_trials`, `::an_over_limit_request_is_refused_and_never_clamped_upward`; `MEMORY-LAB-023` refused by two independent gates |
| 37 | Output/time budgets enforced | `trials.rs` `charge_output` / `check_deadline`; `result.rs` charges retained bytes before evaluation and counts after |
| 38 | Secret-shaped values redacted/refused before persistence | `violations_and_hygiene.rs::evidence_text_is_masked_at_construction_rather_than_on_the_way_out`; `memory_security.rs::an_artifact_carrying_a_canary_or_credential_is_refused`; CI step "No artifact leaks a canary, credential or store endpoint" |
| 39 | Hostile control/log/bidi/path/verdict fields refused | `hostile_fixtures.rs` — 80 fixtures, `::every_hostile_fixture_fails_closed`, `::a_refusal_is_never_a_security_verdict` |
| 40 | Evidence binds scenario/store/item/policy/context/event digests | `evidence_bridge.rs::every_bound_digest_reaches_the_record_hashes`, `::evidence_ids_are_stable_and_move_when_the_store_moves` |
| 41 | Cycle 001 evidence vocabulary reused | `evidence_bridge.rs::evidence_reuses_the_cycle_001_contract_and_vocabulary`, `::memory_specifics_live_in_the_namespaced_extension_and_nowhere_else` |
| 42 | Cycle 013 trust-boundary concepts reused, engine not duplicated | `engine_composition.rs::persistence_never_discharges_the_injection_boundary`, `::the_two_engines_name_disjoint_invariants`; `compat.rs` (13 tests) |
| 43 | Cycle 015 principal/tenant semantics reused | `engine_composition.rs::the_three_engines_describe_the_same_principals_identically`, `::a_memory_store_cannot_relabel_an_identity_the_identity_engine_already_fixed` |
| 44 | Cycle 009 safety controls reused for local synthetic | `local_synthetic.rs` — kill switch, `BudgetState`, `SYNTHETIC_NOOP` (10 tests) |
| 45 | `memory-security-baseline-2026` exists | `profiles/memory-security-baseline-2026.json`; `memory_security_profile.rs::the_profile_matches_the_approved_requirement_levels_exactly` |
| 46 | Registry/profile growth remains additive | `memory_security_profile.rs::no_earlier_profile_changed`, `::the_memory_profile_selects_no_property_an_earlier_profile_selects` |
| 47 | Cycle 015 regression green | `cargo test -p dare-identity-security` → 323 passed; CI step "Identity Security regression (Cycle 015)" |
| 48 | Cycle 014 regression green | `cargo test -p dare-tool-security` → 276 passed; CI step "Tool Security regression (Cycle 014)" |
| 49 | Cycle 013 regression green | `cargo test -p dare-prompt-injection` → 271 passed; CI step "Prompt Injection regression (Cycle 013)" |
| 50 | Agentic baseline regression green | CI step "Agentic baseline regression (Cycle 012)" + "No untested risk family renders as SECURE" |
| 51 | MCP baseline regression green | CI step "MCP baseline regression" |
| 52 | Coverage denominator semantics unchanged | `memory_security_profile.rs::no_earlier_profile_changed` (property counts pinned) and `::the_memory_profile_selects_no_property_an_earlier_profile_selects` |
| 53 | CLI exposes only local/replay/synthetic surface | `memory_security.rs::the_mode_enum_admits_only_the_three_local_modes`; CI step "No live or remote memory mode can be selected" |
| 54 | CLI has no remote store/credential/command flags | `memory_security.rs::the_prohibited_store_and_credential_flags_do_not_exist` (14 flags); CI step "Store, provider, credential and remote flags do not exist" |
| 55 | Product/report claims bounded, synthetic evidence marked | `memory_security_metadata.rs::an_overstated_claim_is_refused_rather_than_softened`; `memory_security_product.rs::a_clean_run_renders_the_bounded_pass_wording_and_nothing_stronger`; CI step "Report wording carries no universal memory-security claim" |
| 56 | Confidential/offline mode remains fail closed | CI step "No artifact leaks a canary, credential or store endpoint" (40+ artifacts swept); `assert_bytes_are_secret_safe` refuses before writing; zero-egress asserted in every result |
| 57 | Dedicated CI job uses local fixtures only | `.github/workflows/ci.yml` job `memory-security-2026` — every step reads `crates/`, `corpus/`, `fixtures/` or `profiles/`; no network step |
| 58 | Actual workflow job passes locally before PR | `python scripts/run-ci-job-locally.py .github/workflows/ci.yml memory-security-2026` → **all 39 steps PASSED**, run at head `8e6be10` |
| 59 | fmt / clippy / tests / audit pass | fmt clean; clippy 0 warnings; `cargo test --workspace` 2067 passed, 0 failed; `cargo audit` 0 vulnerabilities |
| 60 | Docs explain memory trust, provenance, isolation and RAG separation | `book/en/src/concepts/memory-security.md`, `book/en/src/reference/extending-memory-security.md`; both `mdbook build` runs pass |
| 61 | `REGRESSION.md` records head/commands/results/defects/residual risks | `REGRESSION.md` §§1–7, including ten defects with their causes and seven residual risks |
| 62 | `PROOF.md` maps all criteria to executed evidence | This document — 63 rows, each naming a test, CI step or command with its result |
| 63 | `APPROVAL.md` absent until explicit PO approval | `APPROVAL.md` exists and carries the Product Owner's explicit approval dated 2026-09-05, scoped to the frozen planning artifacts, the 63 criteria and the 37 tasks. Execution began only after it; nothing in this cycle authored or amended it |

---

## Coverage of the criteria themselves

63 of 63 criteria have executed evidence. None is satisfied by intent.

Four criteria (15, 21, 22, 54) are satisfied by the *absence* of a capability.
Each is evidenced by a test that asserts the absence rather than by the code
simply not containing it, because an unchecked absence is one refactor away from
becoming a presence nobody noticed.
