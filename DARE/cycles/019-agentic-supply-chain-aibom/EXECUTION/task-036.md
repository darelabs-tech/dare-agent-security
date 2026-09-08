# task-036 — Implement SIMULATED adapter

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-55, AC-56, AC-57

## Evidence

`src/simulated.rs`.

**A behaviour is a behaviour, never a verdict.** `ReferenceBehavior::DIGEST_SUBSTITUTED` says the recorded digest is not the approved one. It does not say the run should FAIL, and nothing in this file decides that — the evaluator reads the constructed bundle exactly as it reads an imported document.

`the_staged_bundle_carries_no_expected_outcome` asserts the serialized bundle contains no `expected`, `verdict`, `should_fail` or `is_secure`. If staging also declared the outcome, every paired fixture would test whether the fixture author and the evaluator agreed about a label rather than whether the evaluator can see a substitution.

**All 18 reference behaviours stage.** `every_reference_behaviour_stages_and_only_the_harness_failure_refuses`. A behaviour that could not be staged would silently drop a corpus entry while the count still looked right. `HARNESS_FAILURE` is the one that refuses, and it must: a staged harness failure that quietly produced a clean bundle would test the opposite of what it is for.

**Each vulnerable behaviour is seen by the invariant it targets.** `each_vulnerable_behaviour_is_seen_by_the_invariant_it_targets` checks fourteen behaviour/invariant pairs and asserts FAIL for every one, naming the reason in the failure message.

**The compliant control produces no violation at all.** `the_compliant_behaviour_produces_no_violation_at_all`. Without this, every vulnerable fixture would be agreeing with a broken baseline rather than demonstrating a difference.

## A correction the tests forced

`a_compliant_run_never_fails_and_a_substituted_one_does` originally asserted the compliant bundle aggregates to **PASS**. It does not — it aggregates to INCONCLUSIVE, and that is correct: the bundle carries no dependency edges, no model and no dataset, so four invariants have nothing to decide on. Aggregating those away as PASS would be the engine claiming to have checked boundaries it never saw evidence for.

The test now asserts no invariant FAILs and the aggregate is INCONCLUSIVE, which is the honest claim.

## A second correction

`NO_RELEVANT_OBSERVATION` originally staged a `FRAMEWORK` with no digest, on the assumption that a framework describes an arrangement rather than bytes. It does not: `expects_immutable_artifact()` includes `FRAMEWORK`, because a framework ships as a package. The behaviour now stages a `SERVICE_API` — a running endpoint, which genuinely owes no digest.

The same mistake was in `invariant.rs`. `a_model_with_no_digest_fails_completeness_and_a_framework_does_not` passed only because its framework fixture *had* a digest, so it never tested the claim in its name. It is now `..._and_a_service_api_does_not`, with both components lacking a digest so the test turns on the class rather than on the evidence.
