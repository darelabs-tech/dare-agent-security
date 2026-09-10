# Cycle 020 — Proof

What this cycle claims, and the named test that decides each claim.

Every test named here exists in the tree. That is a gate, not an assertion:
`scripts/k20/verify_proof_citations.py` extracts every backticked name from this
document and fails if one does not resolve to a test, an allowed function
citation, or a name the regression record says was removed. Cycle 016 shipped
three citations naming tests that did not exist, Cycle 018 two more, and Cycle
019 eleven.

---

## 1. Scope and totals

| | |
|---|---|
| New crate | `crates/dare-a2a-security` |
| Invariants | 14 (I01–I14) |
| Registry properties | 12 (2 inherited, 10 added) |
| A2A-LAB vectors | 64 |
| Reference behaviours | 42 |
| Observation channels | 17 |
| Cycle 020 tests | **415** |
| Workspace tests | **3759**, zero failures |

`the_registry_holds_exactly_the_fourteen_approved_invariants` fails if the
invariant count moves. `the_fourteen_evaluators_are_all_reachable` fails if one
becomes dead code — an evaluator nobody can reach is an invariant nobody checks,
reported as satisfied.

---

## 2. The claim boundary

> A PASS means the applicable invariants remained satisfied under the local
> evidence analysed. It is not a statement that a remote agent is secure.

| Claim | Decided by |
|---|---|
| the artifact states it | `a_clean_run_states_what_its_pass_covers_and_what_it_does_not` |
| the summary states it | `the_summary_never_claims_more_than_the_run_established` |
| the summary cannot overclaim | `the_summary_gate_refuses_a_claim_and_permits_its_denial` |
| every evidence record states it | `every_record_carries_the_sixteen_relations_and_the_offline_note` |
| every CI-written summary states it | the `Every artifact this job wrote states its claim boundary` step |

`assert_summary_is_bounded` is anchored on the **claim**, not on the words: it
looks back sixty characters from each forbidden phrase for a negation. A word-ban
refused the summary's own disclaimer, which is recorded in `REGRESSION.md` §1c.

---

## 3. The offline boundary

| Claim | Decided by |
|---|---|
| the crate declares no transport at all | `this_crate_declares_no_network_dependency_of_its_own` (18 forbidden dependencies) |
| no constant holds a reachable endpoint | `no_constant_in_this_crate_holds_a_reachable_endpoint` |
| no shipping file names a live host | `scripts/k20/assert_no_real_credentials.py` |
| every run records zero state changes and zero egress | `a_run_records_zero_state_changes_and_zero_egress_for_every_entry` |
| the artifact records both as zero | `the_artifact_records_the_budget_the_run_actually_consumed` |
| the help states what is never reached | `the_help_states_the_offline_boundary_and_the_bounded_claim` |
| no flag could reach or authenticate to a peer | `the_help_offers_no_flag_that_could_reach_a_peer` |
| no *new* flag can be outside the four allowed categories | `every_flag_the_help_offers_names_a_path_a_mode_a_limit_or_an_output` |

The dependency test is the load-bearing one. The engine has no HTTP client, no
TLS stack, no JWT library, no JWKS resolver, no OAuth client and no async
runtime. An engine that carried one and promised not to use it would be one
refactor away from using it.

The flag test asserts each forbidden flag is absent from the help **and** fails
to parse. Undocumented is not the same as unavailable.

The credential sweep was verified against a planted host and failed as it should
before the line was reverted — `assert_no_real_credentials.py` also refuses to
report success having swept no files, and its `shipping_lines` is brace-aware so
it cannot fail open on a file with a test module in the middle.

---

## 4. Missing evidence never becomes success

The central rule of the cycle.

| Claim | Decided by |
|---|---|
| `INDETERMINATE` and `UNRECORDED` satisfy no positive evidence | `unrecorded_and_indeterminate_evidence_can_never_become_a_pass` |
| removing any required channel removes the PASS that depended on it | `removing_any_required_channel_removes_the_pass_that_depended_on_it` |
| an empty run decides nothing | `an_empty_run_decides_nothing_and_aggregates_to_inconclusive` |
| an empty run satisfies no contract | `an_empty_run_satisfies_no_contract` |
| no corpus GAP reaches an applicable PASS | `no_gap_is_reported_as_an_applicable_pass` |
| a missing signature is undecided; an invalid one is a failure | `a_missing_signature_is_undecided_and_an_invalid_one_is_a_failure` |
| an undecided record never reaches Cycle 001 as `invariant-holds` | `an_undecided_record_is_not_applicable_and_never_a_pass` |
| a harness failure is ERROR, never a security conclusion | `a_harness_failure_reports_error_rather_than_a_security_conclusion` |
| a harness failure still produces an artifact | `a_harness_failure_produces_an_error_artifact_rather_than_nothing` |
| an A2A evidence gap resolves to `NOT_TESTED`, not `NOT_APPLICABLE` | `a_missing_a2a_control_is_a_gap_and_never_not_applicable` |

`removing_any_required_channel_removes_the_pass_that_depended_on_it` is driven by
`contract()` itself rather than by a hand-written list, so an invariant whose
contract gains a channel is covered the day it gains it, and one whose contract
is quietly emptied fails here instead of passing on an empty run.

The predicate split is asserted in both directions:
`a_target_with_no_a2a_surface_is_not_applicable` for the four target shapes,
`a_missing_a2a_control_is_a_gap_and_never_not_applicable` for the seven evidence
predicates, and `the_evidence_and_shape_classifications_do_not_overlap` so no
predicate decides its own meaning from whichever branch ran first.

---

## 5. Coverage means a question was asked *and answered*

`assess_coverage` runs two steps. Presence of the required channels is the
first; `comparison_reason` is the second, and it asks whether the channel that
was present actually carried something to compare.

| Claim | Decided by |
|---|---|
| every invariant has a non-empty contract | `every_invariant_has_a_contract_and_every_contract_requires_something` |
| a missing channel is named, so an operator knows what to collect | `a_missing_channel_is_named_in_the_reason` |
| a card observed against a policy that says nothing is undecided | corpus `A2A-LAB-004B`, via `no_gap_is_reported_as_an_applicable_pass` |
| coverage gates PASS and never gates FAIL | `coverage_gates_pass_and_never_gates_fail` |
| an inapplicable invariant does not drag a clean run below PASS | `an_inapplicable_invariant_never_drags_a_clean_run_below_pass` |
| an invariant with no subject is inapplicable, not undecided | `an_invariant_with_no_subject_is_inapplicable_rather_than_undecided` |

The last two are the Cycle 019 correction carried in from the start. Without
them a fully compliant exchange reports INCONCLUSIVE because it registered no
callback, and the engine's PASS becomes unreachable in practice.

---

## 6. The sixteen distinctions

Each is a place where two things that look alike are not the same thing.

| Distinction | Decided by |
|---|---|
| external agent listed != trusted peer | `only_a_local_source_may_establish_approval` |
| discovered Agent Card != authenticated identity | `an_agent_card_cannot_record_its_own_authentication` |
| signed Agent Card != authorized provider | `a_local_policy_cannot_be_the_source_of_a_signature_verification` |
| TLS server identity != agent-level authorization | `a_card_provider_is_never_the_authorization_subject` |
| declared security scheme != successful authentication | `A2A-LAB-014`, via `every_attack_is_seen_by_the_invariant_it_was_built_for` |
| successful authentication != skill authorization | `an_unauthorized_skill_fails_and_names_the_subject` |
| schema-valid message != authentic message | `A2A-LAB-018`, via `no_gap_is_reported_as_an_applicable_pass` |
| authentic message != authorized instruction | `a_signature_over_a_different_envelope_fails_message_authenticity` |
| peer content != privileged instruction | `peer_content_reaching_authority_fails_and_names_the_parts` |
| taskId match != principal/context match | `a_task_carrying_two_contexts_fails_context_binding` |
| delegation != privilege amplification | `a_widened_delegation_fails_and_names_the_hop_and_dimension` |
| message retry != safe replay | `a_repeat_with_no_replay_evidence_fails_and_a_read_repeat_does_not` |
| protocol compatibility != permission to downgrade | `a_downgraded_protocol_version_fails` |
| extension declaration != extension authority | `a_required_unapproved_extension_fails` |
| webhook URL != permission to connect | `an_unapproved_push_destination_fails_without_contacting_anything` |
| tenant routing value != proof of tenant authorization | `a_cross_tenant_claim_fails_and_names_both_tenants` |

All sixteen are also carried inside every Cycle 001 evidence record, asserted by
`every_record_carries_the_sixteen_relations_and_the_offline_note`, so a consumer
holding one record knows what the verdict means without finding this document.

Three of them are enforced **structurally** rather than by an evaluator rule,
which is stronger: `may_establish_approval` returns false for the four
non-local sources, `CardSignatureEvidence::validate` refuses `LocalPolicy`, and
`may_carry_delegated_subject` makes a delegated subject under client credentials
a validation refusal rather than something to notice later.

---

## 7. The corpus tests the engine, not the fixture author

| Claim | Decided by |
|---|---|
| no entry states its own outcome | `no_corpus_entry_can_state_its_own_outcome` |
| the corpus meets the approved minimum, with unique ids | `the_corpus_meets_the_approved_minimum_and_names_every_entry_once` |
| every surface and every invariant has an entry | `every_surface_and_every_invariant_has_at_least_one_entry` |
| attacks are not the whole corpus | `every_class_is_represented_and_attacks_are_not_the_whole_corpus` |
| every attack is seen, with deciding evidence | `every_attack_is_seen_by_the_invariant_it_was_built_for` |
| no control is reported | `no_control_is_reported_by_the_invariant_it_exercises` |
| every refusal is refused before evaluation | `every_refusal_is_refused_before_any_invariant_is_evaluated` |
| an unknown vector is refused rather than run empty | `the_corpus_adapter_refuses_a_scenario_it_has_no_entry_for` |
| the adapter stages the entry a scenario names | `the_corpus_adapter_stages_the_entry_a_scenario_names` |
| a staged bundle carries no expected outcome | `the_staged_bundle_carries_no_expected_outcome` |
| a scenario has no executable hook | `a_scenario_cannot_declare_a_verdict_or_reach_anything` |

The control floor matters as much as the attack coverage. An engine that
reported FAIL for everything would score perfectly against attacks alone and be
worse than useless, because an operator would learn to ignore it.

Two entries were filed against the wrong invariant and corrected against the
engine's answer rather than the reverse — `REGRESSION.md` §4.

---

## 8. A report names only what was observed

| Claim | Decided by |
|---|---|
| every finding carries the evidence that decided it | `a_failing_run_carries_every_violation_and_the_evidence_behind_it` |
| no verdict names a peer or message that was not observed | `the_engine_never_reports_a_verdict_about_a_peer_it_did_not_observe` |
| no violation is inferred from prose | `no_violation_reads_as_prose_inference` |
| an exchange crossing three boundaries reports three | `every_boundary_a_multi_violation_exchange_crossed_is_reported` |
| a secondary gap does not erase a primary failure | `a_secondary_gap_does_not_erase_a_primary_failure` |
| one concrete failure outranks every undecided answer | `one_concrete_failure_outranks_every_undecided_answer` |
| a failure outranks a later harness error | `a_failure_outranks_a_later_harness_error` |
| every applicable invariant is evaluated, not just the targeted one | `every_applicable_invariant_is_evaluated_regardless_of_which_one_a_fixture_targets` |
| the artifact carries no message content | `the_artifact_carries_no_message_content` |
| the six identity fields stay separate in the artifact | `the_six_peer_identity_fields_stay_separate_in_the_artifact` |

---

## 9. Hostile input is refused at the door

| Claim | Decided by |
|---|---|
| an oversized document is refused before it is parsed | `an_oversized_document_is_refused_before_it_is_parsed` |
| the gate refuses actions and not locations | `the_fetch_list_refuses_actions_and_not_locations` |
| an ordinary card's location fields stay readable | `ordinary_agent_card_location_fields_stay_readable` |
| a credential shape is caught in lowercase | `every_credential_marker_is_lowercase` |
| a bearer value is caught and honest prose is not | `no_artifact_is_written_that_carries_a_credential` |
| a path- or URL-shaped identifier is refused | `a_path_or_url_shape_is_refused_in_an_identity` |
| a bidi or invisible character is refused | `a_bidi_override_is_refused_because_it_renders_as_another_identity` |
| ambiguous evidence is refused rather than guessed at | `every_refusal_is_refused_before_any_invariant_is_evaluated` |
| a document kind is decided by name, never by content | `an_unclassifiable_file_is_refused_rather_than_sniffed` |
| the ledger's exhaustion flag is never cleared | `exhaustion_is_recorded_and_never_cleared` |
| a caller-supplied ceiling can only tighten | `a_caller_supplied_ceiling_can_only_tighten_a_hard_bound` |
| a ceiling of zero is refused rather than admitting nothing | `a_ceiling_of_zero_is_refused_rather_than_admitting_nothing` |

`the_fetch_list_refuses_actions_and_not_locations` and
`ordinary_agent_card_location_fields_stay_readable` are a pair, and neither is
meaningful alone. A gate that refused `jku`, `issuer` and `token_endpoint` would
refuse every real Agent Card and be switched off by the first person who hit it,
taking the credential and executable checks with it.

---

## 10. Additive compatibility

| Claim | Decided by |
|---|---|
| the registry edit was purely additive | `exactly_the_ten_approved_properties_were_added` |
| the two inherited property ids are unchanged | `the_two_inherited_properties_keep_their_public_identifiers` |
| no top-level `A2A.*` namespace was created | `the_profile_selects_no_property_outside_the_a2a_namespace` |
| the v1 MCP registry gained nothing | `the_v1_registry_gained_nothing_from_this_cycle` |
| no earlier profile denominator moved | `no_earlier_profile_denominator_moved` |
| this cycle's ten properties reached no earlier profile | `this_cycles_ten_new_properties_reached_no_earlier_profile` |
| the Cycle 019 profile is untouched | `the_cycle_019_profile_is_untouched_and_still_selects_ten_properties` |
| the requirement split follows the gating predicate | `the_requirement_split_follows_the_predicate_that_gates_each_property` |
| existing serialized facts still decode | every new `Facts` field carries `#[serde(default)]` |
| Cycles 012–019 still pass | 2202 regression tests in the `a2a-security-2026` job; 3733 across the workspace |

The profile tests are the ones that would fail quietly. A coverage percentage is
a fraction whose denominator is a profile's property count; a changed denominator
makes every assessment already filed against that profile mean something
different, and nothing about the number would look wrong. Both defects found in
those tests are recorded in `REGRESSION.md` §5.

---

## 11. Determinism and reproducibility

| Claim | Decided by |
|---|---|
| a generated card is byte-identical between runs | `every_generated_card_is_byte_identical_between_runs` |
| the generator is not one constant | `generated_cards_differ_between_behaviours_that_stage_different_things` |
| the whole corpus digests identically twice | `running_the_whole_corpus_twice_produces_identical_results` |
| observation digests do not depend on arrival order | `observation_digests_do_not_depend_on_the_order_evidence_arrived_in` |
| two runs over one scenario produce the same digests | `two_runs_over_one_scenario_produce_the_same_digests` |
| staging an entry twice produces the same observations | `staging_an_entry_twice_produces_the_same_observations` |
| evidence record ids are reproducible and distinct | `evidence_record_ids_are_reproducible_and_distinct` |
| every taxonomy is spelled the same on the wire and in prose | `every_taxonomy_is_spelled_the_same_way_on_the_wire_and_in_prose` |

The last one covers nine closed enums rather than the two instances that were
caught. `REGRESSION.md` §2 records why the earlier
`every_transport_token_is_spelled_the_same_way_on_the_wire_and_in_prose` was
replaced by it.

---

## 12. The artifact accounts for itself

| Claim | Decided by |
|---|---|
| every written byte is charged before the write | `output_bytes_are_admitted_before_write_and_recorded` |
| the result artifact charges its own bytes | `a_run_writes_all_six_artifacts_and_charges_every_byte` |
| the findings file exists even when clean | `the_findings_artifact_exists_and_is_an_array_even_when_clean` |
| `violations` is serialized when empty | `violations_are_always_serialized_even_when_there_are_none` |
| output totals do not reset between trials | `run_wide_output_totals_do_not_reset_between_trials` |

`serialize_result_with_final_budget` loops to a fixed point because writing the
budget into the artifact changes the artifact's length. Cycle 019's post-merge
review found the budget bounding everything except the largest thing the run
produced.

---

## 13. The CI gate

`a2a-security-2026`, 31 steps of which **29 are run-steps, all passing** under
`python scripts/run-ci-job-locally.py .github/workflows/ci.yml a2a-security-2026`.

(This section previously read "27 steps ... all 25 run-steps", which was wrong
in both halves and disagreed with itself. The numbers above are counted from the
workflow and from the runner's own output.)

Every assertion is parsed structure via `scripts/assert-json.py`. There is no
substring check for a verdict anywhere in the job — `SECURE` matches inside
`INSECURE_INTER_AGENT_COMMUNICATION`, which *is* this cycle's risk family, and a
substring gate would have reproduced Cycle 013's defect under its own name.

The three INCONCLUSIVE steps assert `verdict=INCONCLUSIVE` **and**
`--count violations=0` together. Either alone passes for the wrong reason.

---

## 14. Post-merge hotfix: only a VALID verification may satisfy a positive claim

Added after this cycle merged. Sections 1–13 describe Cycle 020 as approved and
delivered; this section records the remediation of three false-`PASS` paths that
post-merge security review found in I02, I03 and I04. Full narrative in
`HOTFIX.md`, execution record in `EXECUTION/hotfix-001.md`.

Every test below drives a **whole invariant**. The status predicate
`only_valid_may_satisfy_positive_evidence_and_only_invalid_is_a_finding` was
already green throughout, and the defect was that three call sites never
consulted it — so a predicate test is not evidence for this claim.

| Claim | Decided by |
|---|---|
| I02 authentication uncertainty cannot PASS | `only_a_valid_peer_verification_can_bind_peer_identity` |
| I02 identity substitution cannot silently PASS | `a_logical_agent_that_differs_from_the_approved_one_fails` |
| I02 a logical agent nobody approved cannot bind | `a_logical_agent_policy_never_approved_cannot_bind` |
| I02 a service principal cannot stand in for a required delegate | `a_service_principal_standing_in_for_a_required_delegated_identity_fails` |
| I02 legitimate service-to-service is not failed | `a_service_principal_is_not_a_finding_where_no_delegated_identity_is_expected` |
| I02 an expected value never observed is not agreement | `an_expected_audience_that_was_never_observed_leaves_identity_undecided` |
| I03 INDETERMINATE and UNRECORDED cannot PASS | `only_a_valid_message_verification_can_establish_authenticity` |
| I03 a covered envelope does not rescue an uncertain verifier | `a_signature_covering_the_right_envelope_does_not_rescue_an_uncertain_verification` |
| I03 envelope binding is required | `a_valid_verification_without_a_covered_digest_cannot_establish_authenticity` |
| I04 scheme declaration alone cannot PASS | `a_scheme_the_card_merely_declares_is_not_a_satisfied_requirement` |
| I04 verification must correspond to the selected scheme | `a_verification_for_another_scheme_never_satisfies_the_requirement` |
| I04 another peer's verification never satisfies this requirement | `a_valid_verification_for_another_peer_never_satisfies_this_requirement` |
| I04 only VALID may satisfy positive evidence | `only_a_valid_verification_can_satisfy_a_security_requirement` |
| I04 no verification at all leaves the requirement undecided | `a_scheme_with_no_verification_at_all_leaves_the_requirement_undecided` |
| the rule holds across all three, for every status | `no_uncertain_verification_produces_a_pass_in_any_of_the_three` |
| a required binding is proven only by a match | `only_matches_proves_a_required_binding_and_unproven_never_does` |
| FAIL precedence remains intact | `a_concrete_failure_still_outranks_an_undecided_invariant` |
| an undecided invariant is not masked by passing ones | `an_undecided_invariant_cannot_be_masked_by_a_passing_one` |

`no_uncertain_verification_produces_a_pass_in_any_of_the_three` walks
`VerificationStatus::all()` and `only_matches_proves_a_required_binding_and_unproven_never_does`
walks `BindingCheck::all()`, so a status or variant added later cannot default to
permitted.

The five corpus vectors are verified end to end through the CLI, not asserted in
prose:

```text
A2A-LAB-059 -> INCONCLUSIVE | PEER_IDENTITY_BOUND
A2A-LAB-060 -> FAIL         | PEER_IDENTITY_BOUND
A2A-LAB-061 -> FAIL         | PEER_IDENTITY_BOUND
A2A-LAB-062 -> INCONCLUSIVE | MESSAGE_AUTHENTICITY_ESTABLISHED
A2A-LAB-063 -> INCONCLUSIVE | SECURITY_REQUIREMENT_SATISFIED
```

The tests were checked for teeth by mutation rather than trusted: forcing
`binding_established` true fails four of them, and making
`requirement_established` ignore the verification status fails six.

The offline boundary is unchanged by this work.
`this_crate_declares_no_network_dependency_of_its_own` still holds, no
dependency was added, and `scripts/k20/assert_no_real_credentials.py` passes
over the new fixtures. Authentication verification remains recorded evidence
from another verifier, read as local data.

Executed on `hotfix/cycle-020-a2a-security-contracts`:

```text
cargo test -p dare-a2a-security ......... 356 passed, 0 failed
cargo test --workspace .................. 3759 passed, 0 failed
cargo fmt --all -- --check ............... clean
cargo clippy --workspace --all-targets ... 0 issues
a2a-security-2026 ....................... 29/29 steps passed
```

---

## 15. What this cycle does not claim

- It does not claim any remote agent is secure, reachable, or behaving as its
  card describes.
- It does not claim an exchange nobody captured was safe.
- It does not verify a signature, resolve a key, validate a token or perform a
  handshake. It reads what another verifier recorded, and `may_establish_approval`
  keeps those records from ever becoming approvals.
- It does not take verdict authority over prompt injection (Cycle 013), tool
  authorization (014), identity and delegation semantics (015), aggregation
  (018) or supply-chain inventory (019). `the_record_names_the_cycles_it_does_not_speak_for`
  asserts every evidence record says so.
- It does not perform adaptive multi-turn adversarial testing (Cycle 021),
  authorized remote validation (022) or attack-path graph analysis (023). No
  task required those capabilities, so no discrepancy was raised.
