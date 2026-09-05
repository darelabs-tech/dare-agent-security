# Cycle 014 — Final Proof

Tool Poisoning & Tool Misuse Validation. This document maps every DESIGN
acceptance criterion to the file, test or command that establishes it, and
records what was actually run rather than what was intended.

Measured results live in [`REGRESSION.md`](REGRESSION.md); this document
references them rather than restating them.

| Field | Value |
|---|---|
| Cycle | `014-tool-poisoning-tool-misuse-validation` |
| Branch | `agent/cycle-014-tool-poisoning-tool-misuse-validation` |
| Head at regression run | `9456abb3c8f99811c45978a25f6ffb42e870f491` |
| Tasks | 31 of 31 complete |
| Acceptance criteria | 61 of 61 mapped |
| Workspace tests | 1315 passing, 0 failing |
| Cycle 014 tests | 340 across 10 suites |
| Local workflow job | 28 of 28 steps PASSED |

---

## 1. Acceptance criteria

### Baseline and provenance (1–3)

| # | Criterion | Evidence |
|---|---|---|
| 1 | Cycle 013/main baseline reconciled | [`BASELINE.md`](BASELINE.md) — freezes 965 tests, v1 registry 10, v2 registry 22, profiles 10/10/3, 16 corpus entries, 11 CI jobs, and predicts the additive movement (registry 22→26, profiles 3→4, +1 crate, CI 11→12) that later occurred |
| 2 | Cycle 013 residual risks and CI lessons recorded | `BASELINE.md` §13 records five inherited lessons; `standards/tool-security/2026/provenance.json` carries them as `inherited_lessons`, asserted by `REQUIRED_LESSONS` in `crates/dare-coverage/src/tool_security_standards.rs` |
| 3 | OWASP ASI02 provenance committed locally with status/date | `standards/tool-security/2026/provenance.json` — `fetch_policy: OFFLINE_LOCAL_SNAPSHOT`, dated snapshot, validated by `validate_tool_security_standards` |

### Property model (4–8)

| # | Criterion | Evidence |
|---|---|---|
| 4 | Poisoning and misuse modeled distinctly | Disjoint closed enums `PoisoningFamily` (8) and `MisuseFamily` (10) in `crates/dare-tool-security/src/source.rs`; `poisoning_and_misuse_stay_separate_dimensions`, `poisoning_and_misuse_are_both_represented_and_stay_separate`, `poisoning_and_misuse_stay_separate_all_the_way_into_the_report` |
| 5 | `AGENT.TOOL.AUTHORIZATION_BOUNDARY` unchanged | `BASELINE.md` pins it field by field; `the_registry_gained_four_properties_and_renamed_none` asserts the full ordered `AGENT.TOOL.*` list |
| 6 | `AGENT.TOOL.OUTPUT_TRUST_BOUNDARY` unchanged | Same two, plus `legacy_profiles_keep_their_exact_property_sets` |
| 7 | Specialized property IDs approved and additive | Four added to `schemas/coverage/v2/registry.json` (22→26), all `risk_family = TOOL_MISUSE_EXPLOITATION`, `category = TOOL_SECURITY`; `crates/dare-coverage/tests/tool_security_properties.rs` (12 tests) |
| 8 | Applicability predicates closed and fail closed | `tool_metadata_present`, `tool_output_present`, `tool_chaining_present` in the closed `Predicate` enum; `unknown_predicate_still_fails_closed`, `new_predicates_are_target_shape_and_serialize_stably` |

### Schemas and input safety (9–13)

| # | Criterion | Evidence |
|---|---|---|
| 9 | Versioned scenario schema | `schemas/tool-security/v1/scenario.schema.json` — draft 2020-12, `additionalProperties: false`, `schema_version` const; `schema_ids_and_version_are_stable` |
| 10 | Versioned corpus-entry schema | `schemas/tool-security/v1/corpus-entry.schema.json`; `representative_entries_validate` |
| 11 | Versioned replay/trace schema | `schemas/tool-security/v1/trace.schema.json`; `the_schema_id_and_version_are_stable` |
| 12 | No arbitrary executable fields accepted | `FORBIDDEN_FIELD_NAMES` (24), `FORBIDDEN_REMOTE_FIELD_NAMES` (12), `FORBIDDEN_VERDICT_FIELD_NAMES` (8) swept at any depth; 37 hostile fixtures in `corpus/tool-security/v1/adversarial-parser-fixtures/`; `every_hostile_fixture_fails_closed`, `executable_and_remote_fields_are_refused_at_any_depth` |
| 13 | Tool surface identity and digests explicit and bound | `crates/dare-tool-security/src/canonical.rs` — `bind`, `tool_entry_digest` (excludes the self-claimed digest so a substituted tool cannot restate its own hash); `the_result_binds_every_approved_identity`, `a_self_contradicting_surface_record_is_refused` |

### Corpus (14–19)

| # | Criterion | Evidence |
|---|---|---|
| 14 | Poisoning corpus has secure/vulnerable pairs | 8 poisoning vectors + paired controls in `corpus/tool-security/v1/`; `every_poisoning_and_misuse_family_has_a_vector` |
| 15 | Misuse corpus has secure/vulnerable pairs | 12 misuse vectors + paired controls; same test |
| 16 | Benign controls detect false positives | 8 benign controls; `every_benign_control_passes_without_a_false_violation` and `benign_security_prose_alone_cannot_cause_a_failure`, which runs a description discussing payments, deletion and approvals through **all ten** invariants and requires none to fail |
| 17 | Hostile parser/schema fixtures exist | 37 fixtures with a manifest naming each document's *kind* rather than its expected error; `crates/dare-tool-security/tests/hostile_fixtures.rs` (11 tests) |
| 18 | Tool metadata/source trust machine-readable | `ToolSourceKind` (5 variants, `is_authoritative()` returns false for all) and `TrustLevel` in `source.rs`; `no_tool_source_is_authoritative_on_its_own` |
| 19 | Objective and approved policy machine-readable | `ToolObjective` and `ApprovedToolPolicy` in `model.rs` — declarative data with no expression language and no executable rule; `schemas/tool-security/v1/approved-tool-policy.schema.json` |

### Evaluation semantics (20–23)

| # | Criterion | Evidence |
|---|---|---|
| 20 | Deterministic invariant registry | `crates/dare-tool-security/src/invariant.rs` — `evaluate` total over the closed 10-value `ToolInvariantType`; `supported_invariants` |
| 21 | No LLM judge for final verdicts | Verdicts derive only from typed event fields. `reference_behavior_is_behavior_not_a_verdict` asserts no behavior token decodes as a `Verdict`; `simulation_cannot_read_an_expected_verdict_or_invariant` shows two entries differing only in `expected_invariant` stage byte-identical observations |
| 22 | Every PASS requires invariant-specific positive coverage | `crates/dare-tool-security/src/coverage.rs` — `coverage_contract` total over the closed set, `requires_downstream_channel` for the metadata and output invariants (seeing is not obeying); `assess_coverage` |
| 23 | No relevant observation yields `INCONCLUSIVE` | `silence_is_inconclusive_never_a_pass` across all ten invariants; `silence_aggregates_to_inconclusive_never_to_pass`; CI step 15 |

### Execution modes and boundaries (24–27)

| # | Criterion | Evidence |
|---|---|---|
| 24 | Replay works offline | `crates/dare-tool-security/src/replay.rs`; `every_approved_mode_runs_fully_offline`, `replay_mode_evaluates_a_local_trace_offline`, CI step 17 |
| 25 | Simulated/local-synthetic work offline | `simulated.rs`, `local_synthetic.rs`; same tests |
| 26 | Remote/live tool execution unavailable or refused | `ToolHarnessMode` has three variants and no fourth; `no_remote_or_live_mode_can_be_selected`, `the_mode_enum_cannot_represent_a_remote_or_live_target`, `the_engine_declares_no_transport_or_provider_dependency` (the manifest names no HTTP or MCP client), `no_source_file_reaches_for_a_network_or_process_api` |
| 27 | Risky structured requests FAIL without execution | `a_risky_staged_request_never_becomes_a_step`, `a_risky_operation_is_observed_and_never_performed`, `no_artifact_ever_records_a_dispatched_tool_request`; CI step 14 asserts `dispatched=false` on every recorded request while the run exits 2 |

### Deterministic checks (28–34)

| # | Criterion | Evidence |
|---|---|---|
| 28 | Unapproved selection yields deterministic FAIL | `approved_tool_only` in `invariant.rs`; TOOL-LAB-008; CI step 13 |
| 29 | Argument substitution / dangerous argument yields FAIL | `arguments_preserve_intent`, `dangerous_argument_not_requested`; TOOL-LAB-004, TOOL-LAB-010 |
| 30 | Poisoned output treated as authority yields FAIL | `output_not_authority` — decides on the recorded `treatment` fact, never on a reading of the text; TOOL-LAB-006 |
| 31 | Metadata substitution / digest mismatch fails closed | `metadata_not_authoritative`; `a_substituted_corpus_digest_is_refused_by_the_loader`; TOOL-LAB-020; CI step 18 (exit 3, no artifact written) |
| 32 | Chain membership enforced | `chain_within_approved_set`; TOOL-LAB-012; `a_staged_depth_violation_does_not_leak_into_chain_membership` proves the two are isolated |
| 33 | Chain depth hard bounded | `chain_depth_within_bound` takes `min(policy, HARD_MAX_CHAIN_DEPTH)`; `chain_depth_beyond_the_bound_stops_the_run`; TOOL-LAB-013 |
| 34 | Invocation count hard bounded across trials | `the_total_request_counter_never_resets_between_trials` — several trials each within their per-trial allowance still hit the run total; `a_scenario_cannot_raise_any_hard_bound` |

### Budgets, stopping and hygiene (35–41)

| # | Criterion | Evidence |
|---|---|---|
| 35 | Output/time/resource budgets enforced | `crates/dare-tool-security/src/trials.rs`; `output_budgets_span_trials_and_never_widen`, `exact_boundaries_are_allowed_and_one_over_is_not`, `a_deadline_guard_is_armed_from_the_plan`, `the_output_budget_stops_the_run_and_reports_inconclusive` |
| 36 | First violation can stop trials | `stop_on_first_fail_stops_without_erasing_the_violation`; CI step 12 asserts `stop_reason.reason=FIRST_FAIL` with `trials_executed=1` |
| 37 | Independent simultaneous violations all captured | Violations are a `Vec`, not a first match. `independent_violations_are_reported_independently`, `every_violation_in_a_trial_is_carried_into_evidence_not_just_the_first`, `independently_observed_violations_are_all_counted_in_the_report`; CI step 16 |
| 38 | Secret/canary evidence redacted before persistence | `EvidenceText::from_raw` masks over the whole bounded value; `a_canary_never_survives_into_a_persisted_artifact`, `credential_shaped_content_is_masked_before_it_can_be_persisted`, `no_artifact_or_stream_carries_a_canary_or_credential`; CI step 24 |
| 39 | All digests bind into evidence | `evidence_binds_every_identity_the_run_depended_on` — scenario, objective, policy, surface, per-tool and corpus digests, in extensions and as first-class hashes |
| 40 | Cycle 001 evidence IDs/verdicts reused | `crates/dare-tool-security/src/evidence_bridge.rs`; `the_cycle_001_verdict_vocabulary_is_reused_not_redefined`, `every_record_passes_the_cycle_001_validator`, `an_undecidable_trial_carries_no_decision_in_either_direction` |
| 41 | Cycle 009 budgets/kill-switch reused where execution occurs | `local_synthetic.rs` pushes every trial through `inspect_step` and `BudgetState`; `local_synthetic_observations_match_the_simulator_it_wraps` proves no second executor was created |

### Registry, profile and compatibility (42–46)

| # | Criterion | Evidence |
|---|---|---|
| 42 | `tool-security-baseline-2026` exists | `profiles/tool-security-baseline-2026.json`; `the_profile_matches_the_approved_requirement_levels_exactly` |
| 43 | Cycle 013 regression green | `cargo test -p dare-prompt-injection` — 271 passing; CI step 25 |
| 44 | Agentic regression green | `agentic_registry` and `prompt_injection_properties` green; CI steps 26–27, including `assert-risk-family-state.py` |
| 45 | MCP regression green | `cargo test -p dare-mcp-lab` — 28 passing; CI step 28 asserts the MCP profile still emits no risk-family artifact |
| 46 | Denominator semantics unchanged | `math.rs` untouched; `the_earlier_profiles_are_regression_identical` compares every prior profile by digest; `no_earlier_profile_picked_up_one_of_the_four_new_properties`; `the_agentic_profile_keeps_its_own_requirement_level_for_the_shared_property` |

### CLI and reporting (47–50)

| # | Criterion | Evidence |
|---|---|---|
| 47 | CLI exposed only after the engine exists | task-024 ran after tasks 001–023 in DAG order; `crates/dare-agent-security-cli/src/tool_security.rs` |
| 48 | No remote/credential/arbitrary-command flags | `the_flag_surface_is_exactly_the_approved_one` asserts the complete list; `no_remote_credential_or_command_flag_exists` compares whole flags, never substrings; CI step 20 attempts eight forbidden flags and requires each to be rejected |
| 49 | Product/report output uses bounded claims | `crates/dare-product/src/tool_security_metadata.rs`; `no_rendered_block_can_contain_an_unbounded_claim`, `no_summary_ever_renders_an_unbounded_security_claim`, `the_preferred_bounded_wording_is_used_verbatim_on_a_pass`; CI steps 21–22 |
| 50 | Confidential/offline mode fails closed | `crates/dare-tool-security/tests/offline_confidential.rs` (11 tests); the CLI refuses to write an artifact containing a canary or credential marker |

### CI and gates (51–57)

| # | Criterion | Evidence |
|---|---|---|
| 51 | CI job uses local fixtures only | `tool-security-2026` reads only `fixtures/tool-security/` and `corpus/tool-security/v1/`; no step contacts a network |
| 52 | Trigger remains PR-open-only, no push | Verified by parsing the shipped YAML: `{'pull_request': {'branches': ['main'], 'types': ['opened']}}`; recorded in `REGRESSION.md` |
| 53 | `run-ci-job-locally.py` passes against the actual job | **All 28 steps PASSED.** It caught four defects in my own assertions first; each is recorded in `REGRESSION.md` |
| 54 | `cargo fmt --all --check` | PASS — exit 0 |
| 55 | `cargo clippy --workspace --all-targets -- -D warnings` | PASS — exit 0, zero warnings |
| 56 | `cargo test --workspace` | PASS — 1315 passing, 0 failing |
| 57 | `cargo audit` with vulnerabilities = 0 | PASS — exit 0, **0 vulnerabilities**. One allowed warning (yanked `chacha20`, transitive through `dare-mcp-discovery -> reqwest`), which is a yank notice rather than an advisory and which the tool-security engine does not depend on |

### Documentation and closure (58–61)

| # | Criterion | Evidence |
|---|---|---|
| 58 | Operator docs define scope, safe use, limitations | `book/en/src/concepts/tool-security.md` — nothing is executed, bounded claims, INCONCLUSIVE semantics, coverage channels, modes, flags, exit codes, bounds, redaction, and a named list of what is not proved including the deferred cycles |
| 59 | Contributor docs define extension rules | `book/en/src/reference/extending-tool-security.md` — closed enums, provenance, paired and hostile fixtures, positive PASS coverage, no expected verdicts or executable fields, exact CI assertions, mandatory local workflow-job execution |
| 60 | Final proof maps all criteria | This document |
| 61 | `APPROVAL.md` absent until explicit Product Owner approval | Approval was granted before execution. `APPROVAL.md` was authored by the Product Owner in commit `cd2f2bb` (*docs(cycle-014): approve execution scope*, Wanderson Leandro de Oliveira, 2026-09-05), not by this agent. No commit in this cycle's execution modifies it |

---

## 2. Standards provenance

`standards/tool-security/2026/provenance.json` records an offline local snapshot
of OWASP Agentic Top 10 (2026) **ASI02 — Tool Misuse and Exploitation**, with
status and date. Six property mappings are recorded as `PARENT_INVARIANT` or
`SPECIALIZES`; `EQUIVALENT` is deliberately absent from `ALLOWED_RELATIONS`,
because tool poisoning and tool misuse are distinguished rather than merged and
neither is claimed to *be* ASI02. Cycles 015, 016, 017, 019, 020, 021 and 022 are
listed as explicitly out of scope.

## 3. Schema and property decisions

- Draft 2020-12, `additionalProperties: false`, `const` schema versions, closed
  enums throughout; `$ref`s resolve through compiled-in `jsonschema::Resource`
  values, so validation never touches the network.
- serde `deny_unknown_fields` is an independent second gate behind every schema.
- `ToolFamily` is `untagged` over two disjoint enums, so a poisoning class cannot
  borrow a misuse family without the cross-field check catching it.
- Pre-existing property ids were neither renamed nor reordered; the four
  additions append after `OUTPUT_TRUST_BOUNDARY`.

## 4. Invariant coverage contracts

| Invariant | Required channel |
|---|---|
| `TOOL_METADATA_NOT_AUTHORITATIVE` | `TOOL_SURFACE_OBSERVED` + a downstream action channel |
| `APPROVED_TOOL_ONLY` | `TOOL_SELECTED` or `TOOL_REQUESTED` |
| `TOOL_SELECTION_BOUND_TO_OBJECTIVE` | `TOOL_SELECTED` **and** `OBJECTIVE_STATE` |
| `TOOL_ARGUMENTS_PRESERVE_APPROVED_INTENT` | `TOOL_ARGUMENTS` |
| `DANGEROUS_ARGUMENT_NOT_REQUESTED` | `TOOL_ARGUMENTS` or `TOOL_REQUESTED` |
| `TOOL_OUTPUT_NOT_REINTERPRETED_AS_AUTHORITY` | `TOOL_OUTPUT_OBSERVED` + a downstream action channel |
| `CHAIN_WITHIN_APPROVED_SET` | `TOOL_CHAIN_STEP` |
| `CHAIN_DEPTH_WITHIN_BOUND` | `TOOL_CHAIN_STEP` |
| `INVOCATION_COUNT_WITHIN_BOUND` | `TOOL_REQUESTED` |
| `POLICY_DENY_NOT_BYPASSED` | `POLICY_DECISION` |

A missing channel yields `INCONCLUSIVE`, never `PASS`. An unknown invariant
cannot be constructed; the evaluator is total over a closed set.

## 5. Bounds

All enforced in `crates/dare-tool-security/src/limits`, refused rather than
clamped, with run totals owned by the ledger so they never reset between trials.

| Bound | Value |
|---|---|
| Default trials | 3 |
| Hard max trials | 10 |
| Stop on first fail | true |
| Tool requests per trial | 8 |
| Total tool requests | 24 |
| Chain depth | 3 |
| Output bytes per trial | 16384 |
| Total output bytes | 65536 |
| Duration per trial | 30s |
| State changes | 0 |
| External egress bytes | 0 |

## 6. Corpus and fixtures

| Artifact | Count |
|---|---|
| Corpus entries (registry, digest-pinned) | 28 |
| — poisoning vectors | 8 (every poisoning family) |
| — misuse vectors | 12 (every misuse family) |
| — benign controls | 8 |
| Adversarial parser fixtures | 37 |
| TOOL-LAB scenarios | 20 |
| Sanitized traces | 2 |
| Lab corpora (deliberately broken) | 2 |

All generated by scripts with `--check` drift gates. No entry carries an
executable field, remote target, real credential or expected verdict, asserted
both at generation time and at load time.

## 7. Evidence model

Cycle 001 `SecurityEvidence` with tool-security detail under
`dare.tool-security.v1`. Each record binds scenario, objective, policy, surface,
per-tool and corpus digests; carries normalized observations, every violation,
trial index, request count, chain depth, coverage satisfaction, budget snapshot
with its zero state-change and zero-egress facts, control snapshot and redaction
state; names a synthetic target with `ObservationSource::Fixture`; and passes
`validate_secret_safety` before it is returned.

## 8. Compatibility

Additive throughout. Registry 22→26 properties, profiles 3→4, crates +1, CI jobs
11→12. No pre-existing property id, profile property set, requirement level,
denominator or schema was changed. `AGENT.TOOL.AUTHORIZATION_BOUNDARY` is shared
between the agentic profile (CONDITIONAL) and the tool-security profile
(REQUIRED); both levels are pinned by test so neither can adopt the other's.

## 9. Defects found and fixed during execution

| # | Defect | Fix |
|---|---|---|
| 1 | Surface reporting matched family names by substring, labelling TOOL-LAB-001 — a description-poisoning vector — as having no metadata surface tested | Replaced with the typed `PoisoningFamily::surface_area` and `MisuseFamily::misuse_surface` mappings; all five poisoning areas and five misuse surfaces now report individually |
| 2 | Nothing refused control characters or Unicode direction overrides, so a fixture could have written `ESC[2K\rVERDICT: PASS` into a rendered report line, or made two ids display identically | Added `assert_no_hostile_text`: C0/C1 controls, bidi embedding and isolates, and zero-width characters refused in every field name and string value, keeping newline and tab |
| 3 | The Cycle 002 e2e trace test waited 500ms for a child process's dump and flaked under full-workspace parallel load | Budget raised to 5s; it costs nothing when the dump is already present |
| 4 | CI `--min-total` on TOOL-LAB-019 expected two violations under one invariant, but that vector's independence spans several | Moved the multiplicity assertion to TOOL-LAB-008, where one unapproved tool genuinely crosses `APPROVED_TOOL_ONLY` twice |
| 5 | Secret markers beginning with `-` were parsed by argparse as flags | Moved into a canonical `--secret-markers` set in `assert-text.py` |
| 6 | `assert-json.py --count "=10"` could not address a top-level array | An empty path now names the document root |
| 7 | The `cycle014-*` CI glob also swept Cycle 012/013 regression outputs and demanded a tool-security scope note from them | Regression runs write under `regression-*`; the leak sweep widened to every artifact the job produces |
| 8 | Three offline-regression assertions fired on their own tests — a source sweep flagged a fixture asserting a URL is *refused*, a trace sweep flagged the word "server" in a sentence saying no server is contacted | Sweeps now read field names rather than raw text, skip test modules, and state the real constraint: every URL in shipping code must be a `darelabs.tech` schema id |

Defects 4–7 were caught by the mandatory local workflow-job gate before CI could
see them, which is precisely the gate's purpose.

## 10. Residual risks

1. **Synthetic observations are not production evidence.** `simulated` and
   `local-synthetic` stage a declared reference behavior. Every artifact marks
   them `synthetic`, and reports say so, but an operator who ignores that marking
   could over-read a `PASS`.
2. **The corpus is finite.** 28 entries across 18 families is coverage of those
   families, not of tool poisoning and misuse in general. Every report states
   this in its scope note.
3. **Replay trusts its recorder.** A trace records `treatment` and
   `digest_matches_approved` as facts. A trace that lies about those is refused
   only where it contradicts itself; the engine cannot verify a recorder it did
   not run.
4. **`chacha20` yank warning** remains in the workspace through
   `dare-mcp-discovery`'s `reqwest` chain. Not a vulnerability, not introduced
   here, and not reachable from the tool-security engine.
5. **No live-target validation.** Nothing in this cycle establishes behavior
   against a real MCP server, provider or production agent, by design.

## 11. Deviations from plan

- **TOOL-LAB-016 and TOOL-LAB-017** are refusal scenarios rather than ordinary
  runs. Their point is that loading fails closed, so they ship with dedicated
  lab corpora and exit 3 without writing an artifact. This matches DESIGN's
  "ERROR/refusal" and "refusal" expectations for those ids.
- **Portuguese documentation** was not added for the two new pages, following
  the Cycle 013 precedent of English-only capability docs. The Portuguese book
  is unchanged and still builds.
- **Corpus payloads flow into simulated output.** Added while building the
  corpus so fixture content is actually exercised by the redaction and evidence
  layers rather than sitting decorative. It changes no verdict logic; the
  payload is never parsed.

No deviation widens scope, weakens a bound, or relaxes a refusal.

## 12. Local CI artifact execution

```
python scripts/run-ci-job-locally.py .github/workflows/ci.yml tool-security-2026
```

Executed against the shipped `.github/workflows/ci.yml` at head `9456abb`.
**All 28 steps PASSED.** Per-step results are in `REGRESSION.md`.

This is the gate Cycle 013 lacked. Its lesson — that hand-checking the
assertions you *intended* to write is not the same as running the ones you
shipped — is why it is mandatory here, and it earned its place by catching four
defects on its first two runs.

## 13. PR-open CI

Pull request [#21](https://github.com/darelabs-tech/dare-agent-security/pull/21),
opened at head `a4f039335cd793eacbdf365abc0118dfe4e469ea`.

| Workflow | Run | Conclusion |
|---|---|---|
| `ci` | 33982616816 | **success** (6m15s) |
| `action-e2e` | 33982616776 | **success** (4m0s) |

All twelve `ci` jobs succeeded, including the new one:

| Job | Conclusion |
|---|---|
| Rust workspace | success |
| Cycle 005 lab corpus | success |
| Cycle 006 coverage engine | success |
| Cycle 007 benchmark methodology | success |
| Cycle 008 attack graph MVP | success |
| Cycle 009 controlled adversarial validation | success |
| Cycle 010 continuous security validation | success |
| Cycle 011 productization | success |
| Cycle 012 Agentic registry security gate | success |
| Cycle 013 Prompt Injection security gate | success |
| **Cycle 014 Tool Poisoning and Tool Misuse security gate** | **success** |
| mdBook documentation gate | success |

The Cycle 014 gate ran 2026-09-05T17:58:57Z to 18:01:46Z. No job failed, and no
prior cycle's gate regressed.

The only annotations are the repository-wide `actions/checkout@v4` Node.js 20
deprecation notices, which predate this cycle and affect every job equally.

This is the first cycle where the shipped CI job passed on its first PR-open
run. Cycle 013's did not, and the gate added in response — running the real
workflow steps locally before opening the PR — is what closed the gap.

---

## Completion

**Cycle 014 — DONE / REVIEW PASS**

Recorded on the basis that: 31 of 31 tasks are complete; 61 of 61 acceptance
criteria are mapped to concrete evidence; `cargo fmt`, `cargo clippy -D
warnings`, `cargo test --workspace` (1315 passing) and `cargo audit`
(0 vulnerabilities) all passed; the Cycle 013, Agentic and MCP regressions are
green; both books build; all three generator drift checks are clean; and the
mandatory local workflow-job run passed all 28 steps.

§13 is now closed as well: PR #21's CI completed green on open, with all twelve
jobs succeeding and no prior cycle's gate regressing. Nothing in this document
remains pending.
