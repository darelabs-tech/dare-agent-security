# Cycle 015 — Final Proof

Each of the 67 acceptance criteria in `DESIGN.md` §30 is mapped to the artifact
that satisfies it and the command that was actually run. Nothing is marked
satisfied on intent: every row names evidence that executed at
`06c0ad0ff602dccad728bd48661ef760603846b8`, and the run results are recorded in
`REGRESSION.md`.

Commands referenced by shorthand:

- **W** — `cargo test --workspace` (1716 passing, 0 failing)
- **J** — `python scripts/run-ci-job-locally.py .github/workflows/ci.yml identity-security-2026` (36/36 steps PASS)

---

## Baseline, provenance and properties (1–7)

| # | Criterion | Evidence | Verified by |
|---|---|---|---|
| 1 | Cycle 014/main baseline reconciled and frozen | `BASELINE.md` — 1315 tests, v1=10, v2=26, 4 profiles, 13 crates, 8 CLI subcommands, 12 CI jobs, per-crate counts, §9 Cycle 003 reuse map, §11 predicted movement | `REGRESSION.md` "Additive movement" table confirms every predicted figure |
| 2 | Cycle 014 residual risks and CI lessons recorded | `BASELINE.md` §12 (six inherited lessons), §13 (five carried risks plus one new) | `standards/identity-security/2026/provenance.json` `inherited_lessons`; `identity_security_standards.rs` `REQUIRED_LESSONS` (19 tests) |
| 3 | ASI03/AuthZEN/COAZ provenance recorded with exact status | `standards/identity-security/2026/provenance.json` — 6 sources with pinned statuses: OWASP NORMATIVE, AuthZEN FINAL_SPECIFICATION, COAZ DRAFT, COAZ-MCP DRAFT, binding OPEN_PROPOSAL, DARE informative | `cargo test -p dare-coverage --lib identity_security_standards` (19 passing); `PINNED_SOURCE_STATUS`; `FORBIDDEN_CONFORMANCE_PHRASES` |
| 4 | `AGENT.IDENTITY.DELEGATION_INTEGRITY` unchanged | `schemas/coverage/v2/registry.json` — field-by-field identical to the frozen baseline | `identity_security_profile.rs::the_two_pre_existing_properties_keep_their_identifiers`; `BASELINE.md` §pins |
| 5 | `AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION` unchanged | same | same |
| 6 | Specialized properties additive and approved | Registry 26→30: `PRINCIPAL_BINDING`, `DELEGATION_SCOPE_BOUNDARY`, `TENANT_RESOURCE_BOUNDARY`, `AUTHORIZATION_EXECUTION_BINDING`, all `risk_family = IDENTITY_PRIVILEGE_ABUSE` | `cargo test -p dare-coverage --test identity_security_properties` (14 passing) |
| 7 | New applicability predicates closed and fail closed | `principal_context_present`, `authorization_decision_present`, `tenant_context_present`, `resource_owner_context_present` added to the closed `Predicate` enum and `property.schema.json` | `identity_security_properties.rs`; an unknown predicate fails schema validation |

## Schemas (8–16)

| # | Criterion | Evidence | Verified by |
|---|---|---|---|
| 8 | Versioned principal-set schema | `schemas/identity-security/v1/principal-set.schema.json` | `validate_principal_set_document`; schema tests in `schema.rs` |
| 9 | Versioned delegation-chain schema | `.../delegation-chain.schema.json` | `validate_delegation_chain_document` |
| 10 | Versioned authorization policy/decision schema | `.../authorization.schema.json` | `validate_authorization_document` |
| 11 | Versioned operation schema | `.../operation.schema.json` | referenced by scenario and trace validators |
| 12 | Versioned scenario schema | `.../scenario.schema.json`, with every `$ref` resolved from compiled-in resources — no network | `validate_scenario_document`; all 24 labs validate in `lab_scenarios.rs` |
| 13 | Versioned corpus-entry schema | `.../corpus-entry.schema.json` | `validate_corpus_entry`; `cargo test -p dare-identity-security --test corpus_integration` |
| 14 | Versioned replay/trace schema | `.../trace.schema.json` | `validate_trace_document`; `parse_trace`; trace hostile fixtures |
| 15 | Arbitrary executable fields refused | `FORBIDDEN_EXECUTABLE_FIELD_NAMES` (18), swept at every depth; `additionalProperties: false` throughout | 5 `executable-field-*` hostile fixtures; `executable_fields_are_refused_at_every_depth`; **J** step "Hostile parser fixtures fail closed" |
| 16 | Token/credential/bearer/private-key fields refused or redacted | `FORBIDDEN_CREDENTIAL_FIELD_NAMES` (22); `CREDENTIAL_SHAPED_VALUES`; `mask_sensitive` masks canaries, `sk-live-`, `ghp_`, `xoxb-`, `eyJ`, PEM blocks and bearer tokens | 5 `credential-field-*` plus `bearer-credential-value`, `jwt-shaped-value`, `api-key-shaped-value`, `private-key-shaped-value` fixtures; `violations_and_hygiene.rs` (10 passing) |

## Identity model (17–24)

| # | Criterion | Evidence | Verified by |
|---|---|---|---|
| 17 | Human/agent/workload/service kinds stay distinct | `PrincipalKind` — closed 4-value enum; `originates_authority()` true only for Human; `is_technical_identity()` only Workload/Service | `source.rs` tests (16 passing) |
| 18 | Initiating and effective principals explicit | `PrincipalBindings` — both required, neither defaulted; carried separately into `IdentitySecurityResult` and evidence | `principal.rs` tests (14 passing); `result.rs::a_compliant_run_records_its_identity_binding`; `evidence_bridge.rs::evidence_carries_the_enumerated_identity_facts` |
| 19 | Delegated subject explicit and machine-readable | `PrincipalBindings::delegated_subject_id`; `DelegationEdge::delegated_subject_id`; `DelegationKind::preserves_delegated_subject()` | `delegated_subject_preserved` evaluator; LAB-022 |
| 20 | Authority ceilings explicit and machine-readable | `Authority` — 7 typed dimensions plus validity; `AuthorityDimension::{Any, Only}` with asymmetric `within()` | `authority.rs` tests (18 passing) |
| 21 | Delegation purpose/audience/scope/validity explicit | `DelegationEdge` carries `purpose_id`, `audience`, `authority_ceiling_id`, `validity`; `ChainDefect` enumerates each failure mode | `delegation.rs` tests (18 passing); LAB-017 |
| 22 | Tenant and resource-owner context explicit | `ResourceContext` — tenant, owner, synthetic classification; both bound into the result and evidence | `resource.rs` tests (6 passing); LAB-007/008/009/010 |
| 23 | Decision bound to a canonical operation digest | `AuthorizationDecisionObserved::bound_operation_digest`, computed by `normalize` from the observed operation — never read from the trace | `harness.rs::a_decision_digest_is_computed_never_taken_on_the_adapters_word`; `a_permit_binding_an_unobserved_operation_is_refused_at_parse_time` |
| 24 | Operation identity semantic/canonical, not raw-byte | `Operation::projection()` — authorization-relevant fields only, through Cycle 003 `CanonicalValue::normalize`; incidental arguments excluded by construction | `operation.rs` tests (13 passing); LAB-011 (unchanged permit holds) vs LAB-012/013/014 (mutation detaches it) |

## Evaluation (25–28)

| # | Criterion | Evidence | Verified by |
|---|---|---|---|
| 25 | Deterministic invariant registry | `IdentityInvariantType` — closed 12-value enum; `collect_violations` is a total match; `supported_invariants()` | `invariant.rs::the_evaluator_registry_is_total_over_the_closed_set`; `deterministic_invariants.rs` (36 passing) |
| 26 | No LLM or heuristic judge | The crate declares no model, embedding or similarity dependency; every evaluator is a typed-field comparison | `Cargo.toml` dependency set; `deterministic_invariants.rs::evaluation_is_deterministic_across_repeated_runs` |
| 27 | Every PASS requires positive coverage | `coverage_contract()` — total over 12 invariants; `EXERCISE_CHANNELS` additionally required for 4 of them; evaluation order puts coverage before PASS | `coverage.rs` tests (15 passing); `lab_scenarios.rs::a_passing_lab_passes_on_evidence_and_not_on_silence` |
| 28 | Missing evidence yields INCONCLUSIVE | `assess_coverage` unsatisfied ⇒ `Verdict::Inconclusive`; never PASS | `lab_scenarios.rs` (LAB-016); `simulated.rs::no_relevant_observation_is_inconclusive_and_never_a_pass`; **J** step "Absence of evidence is INCONCLUSIVE, never PASS and never FAIL" |

## Modes and boundaries (29–32)

| # | Criterion | Evidence | Verified by |
|---|---|---|---|
| 29 | Replay fully offline | `replay.rs` — the only I/O is `std::fs::read` of the given path; no scheme is interpreted; digest-bound and deterministic | `replay.rs` tests (12 passing); **J** step "Replay reads only a local trace and stays offline" |
| 30 | Simulated and local-synthetic fully offline | `simulated.rs` derives from the scenario; `local_synthetic.rs` adds Cycle 009 controls and no I/O | `simulated.rs` (11 passing), `local_synthetic.rs` (10 passing) |
| 31 | Live/remote IdP/PDP/AuthZEN/MCP unavailable | `HarnessMode` has 3 variants and no remote one; `HarnessMode::parse` refuses `LIVE_IDP`, `OAUTH`, `REMOTE_PDP`, `AUTHZEN`, `PRODUCTION`, `LIVE_MCP` | `harness.rs::no_remote_identity_mode_can_be_selected`; **J** step "No live identity mode can be selected" |
| 32 | No token/JWT/OAuth handling in Cycle 015 | No OAuth, JWT, JWKS or HTTP dependency in `Cargo.toml`; `jwt`/`jwks`/`issuer` are refused field names; docs state the deferral explicitly | `corpus.rs` (10) and `schema.rs` (13) hostile-field tests; `book/en/src/concepts/identity-security.md` "What this is not" |

## Deterministic detection (33–45)

Each row names the lab that reaches the verdict and the evaluator that decides it.

| # | Criterion | Lab | Verified by |
|---|---|---|---|
| 33 | Principal substitution ⇒ FAIL | LAB-020 (initiating role substituted) | `initiating_principal_preserved`; `violations_and_hygiene.rs::independent_violations_are_reported_independently` |
| 34 | Agent/service authority substituted for user ⇒ FAIL | LAB-002 | `agent_authority_not_substituted`; **J** step "agent authority substituted for the user fails" |
| 35 | Delegated-subject mismatch ⇒ FAIL | LAB-022 | `delegated_subject_preserved` |
| 36 | Delegation-scope expansion ⇒ FAIL | LAB-004 | `delegation_scope_not_exceeded`; **J** step "delegated scope excess fails" |
| 37 | Chain privilege amplification ⇒ FAIL | LAB-004 (the handoff that widens the ceiling) | `chain_no_amplification`; `lab_scenarios.rs::the_labs_cover_every_invariant_in_both_directions` |
| 38 | Effective authority above ceiling ⇒ FAIL | staged via `EFFECTIVE_AUTHORITY_ABOVE_CEILING` | `effective_within_ceiling`; `simulated.rs::each_stageable_behavior_fails_the_invariant_it_targets` |
| 39 | Cross-tenant intent ⇒ FAIL | LAB-008 | `tenant_boundary_preserved`; **J** step "A cross-tenant intent is proven from declarations, never by access" |
| 40 | Wrong resource owner ⇒ FAIL | LAB-010 | `resource_owner_preserved` |
| 41 | Post-authorization mutation / stale permit ⇒ FAIL | LAB-012, LAB-013, LAB-014 | `authorization_bound`; **J** step "A permit does not survive an authorization-relevant mutation" |
| 42 | DENY bypass ⇒ FAIL without execution | LAB-015 | `deny_not_bypassed`; **J** step asserts `dispatched=false` on every observed operation |
| 43 | Credential context cannot silently expand authority | LAB-006 | `credential_not_expanding`; **J** step "Credential availability is not delegated authority" |
| 44 | Expired/not-yet-valid delegation ⇒ FAIL or refusal | LAB-017 | `delegation_valid_at_use`; `ValidityWindow` half-open `[from, until)` |
| 45 | Independent simultaneous violations all captured | LAB-020 (four at once) | `violations_and_hygiene.rs::independent_violations_are_reported_independently`; `several_violations_of_one_invariant_are_all_listed` |

## Bounds and hygiene (46–51)

| # | Criterion | Evidence | Verified by |
|---|---|---|---|
| 46 | Principal/delegation counts and depth hard bounded | 16 principals, 12 edges, depth 4; `PrincipalSet::validate`, `DelegationChain::validate_structure` | `scenario-over-limit-principals` and LAB-021 hostile/refusal fixtures; **J** step "An unresolvable or over-bound scenario is refused" |
| 47 | Operation/decision counts hard bounded across trials | `TrialLedger` holds run totals; `start_trial` resets only the per-trial guard | `trials.rs::the_total_operation_counter_never_resets_between_trials` (charges 10×2 against a run total of 5, asserts exactly 5) |
| 48 | Output/time/resource budgets enforced | `charge_output`, `TrialGuard::check_deadline`; retained bytes charged **before** evaluation | `trials.rs` (18 passing); `result.rs` ordering comment and tests |
| 49 | First violation may stop later trials without erasing evidence | `stop_on_first_fail` fires **after** the trial record is pushed; counts are charged after evaluation | `result.rs::stop_on_first_fail_stops_without_erasing_the_violation` |
| 50 | Credential-shaped values redacted before persistence | `EvidenceText::from_raw` masks before storing; `validate_secret_safety` gates every evidence record; the CLI refuses to write an artifact carrying a marker | `violations_and_hygiene.rs`; **J** step "No artifact leaks a canary, credential or provider" |
| 51 | All object digests bind into evidence | `IdentityBinding` — scenario, principal set, per-authority, chain, resource, policy, corpus digests, carried into the result and the evidence extension | `canonical.rs`; `evidence_bridge.rs::evidence_carries_the_enumerated_identity_facts`; **J** benign step asserts each digest is present |

## Reuse (52–54)

| # | Criterion | Evidence | Verified by |
|---|---|---|---|
| 52 | Cycle 001 evidence IDs and verdicts reused | `dare_security_evidence::{SecurityEvidence, Verdict}`; no second verdict vocabulary anywhere in the crate | `lib.rs::the_verdict_vocabulary_is_reused_from_cycle_001`; `evidence_bridge.rs::evidence_reuses_the_cycle_001_contract_and_vocabulary` |
| 53 | Cycle 003 authorization-integrity components reused | `Operation::projection()` uses `dare_coaz_integrity::CanonicalValue::normalize`; no second binding engine exists | `operation.rs` — the comment and test record that the preimage and hash are Cycle 003's and only the `sha256:` label is added |
| 54 | Cycle 009 budget/kill-switch reused where execution occurs | `local_synthetic.rs` — `inspect_step`, `BudgetState`, `ProofClass::SyntheticNoop`, budget with zero state changes and zero egress | `local_synthetic.rs` (10 passing); `pointing_an_approved_run_at_another_scenario_trips_the_kill_switch` |

## Profile and compatibility (55–60)

| # | Criterion | Evidence | Verified by |
|---|---|---|---|
| 55 | `identity-security-baseline-2026` exists | `profiles/identity-security-baseline-2026.json` — 4 REQUIRED, 2 CONDITIONAL, exactly as approved | `cargo test -p dare-coverage --test identity_security_profile` (9 passing) |
| 56 | Cycle 014 regression green | `cargo test -p dare-tool-security` — 276 passing, unchanged | `REGRESSION.md`; **J** step "Tool Security regression (Cycle 014)" |
| 57 | Cycle 013 regression green | `cargo test -p dare-prompt-injection` — 271 passing, unchanged | `REGRESSION.md`; **J** step "Prompt Injection regression (Cycle 013)" |
| 58 | Agentic baseline regression green | `agentic_registry`, `prompt_injection_properties`, and the coverage run | **J** steps "Agentic baseline regression" and "No untested risk family renders as SECURE" |
| 59 | MCP baseline regression green | coverage run against `mcp-security-baseline`, including the assertion that it writes no risk-family artifact | **J** step "MCP baseline regression" |
| 60 | Denominator semantics unchanged | `dare-coverage/src/math.rs` not edited; no profile overlap; earlier profile counts pinned | `identity_security_profile.rs::no_earlier_profile_changed` and `::the_identity_profile_selects_no_property_an_earlier_profile_selects` |

## CLI, product and CI (61–67)

| # | Criterion | Evidence | Verified by |
|---|---|---|---|
| 61 | CLI exposed only after the engine | `validate identity-security` added in the task-031 commit, after the engine, corpus and result commits | Commit order: `7256eb5` → `1ab95a5` → `aed2491` → `772bbd5` → `304df35` → `06c0ad0` |
| 62 | No remote/credential/OAuth/JWT/command flags | Flag surface is exactly scenario, mode, trace, corpus, trials, output-dir, json | `identity_security.rs::the_flag_surface_is_exactly_the_approved_one` and `::no_remote_provider_or_credential_flag_exists`; **J** step "Provider, credential, PDP and live-identity flags do not exist" (12 flags, each must fail) |
| 63 | Bounded claims and synthetic marking in reports | `bounded_claim()`, `assert_summary_is_bounded`, `assert_bounded_claim` over the whole serialized product block; `synthetic` recorded and disclosed | `identity_security_product.rs` (8 passing); **J** steps on report wording and verbatim pass wording |
| 64 | Confidential/offline mode fails closed | Artifacts refused before writing if they carry a canary or credential shape; refusals write no artifact; every mode is local | **J** steps "No artifact leaks a canary, credential or provider" and "An unresolvable or over-bound scenario is refused before evaluation"; `identity_security_cli.rs::a_scenario_the_engine_refuses_exits_three_without_writing_a_verdict` |
| 65 | Dedicated CI job, local fixtures only, PR-open-only trigger preserved | `identity-security-2026` added to `.github/workflows/ci.yml`; `on: pull_request / branches: [main] / types: [opened]` unchanged; no `push:` | `REGRESSION.md` "Workflow trigger"; the job references only repository-local paths |
| 66 | `run-ci-job-locally.py` passes against the actual job | 36/36 steps PASS, running the job as written rather than reproducing its commands | `REGRESSION.md` "The actual CI job, run locally" |
| 67 | Final gates pass; docs and proof complete | fmt clean, clippy clean, 1716 tests passing, audit exit 0; `book/en` and `book/pt` build; operator and contributor pages added; this document maps all 67 criteria | `REGRESSION.md` "Workspace gates" and "Documentation builds"; `APPROVAL.md` was authored by the Product Owner before execution began |

---

## What a green Cycle 015 does and does not establish

**It establishes** that, for the 24 scenarios and 32 corpus vectors actually
exercised, under the recorded conditions, no identity-security invariant
violation was observed — and that when a violation *is* staged, each of the
twelve invariants detects it deterministically, reports every independently true
violation, and does so without performing any operation, contacting any
provider, parsing any token or touching any real data.

**It does not establish** that identity, delegation, privilege or authorization
handling is secure in any deployment. The corpus is finite, the observations are
synthetic, authority is compared declaratively rather than cryptographically,
and a system whose real behavior differs from what it declares is outside what
this can see.

Every artifact this cycle produces is worded to say the first thing and never
the second.
