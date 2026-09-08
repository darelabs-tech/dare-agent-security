# task-023 — Define closed normalized observation model and adapter authority boundary

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-48

## Evidence

`src/observation.rs`.

**AC-48 — the model is closed and adapters cannot assert a verdict.** Twelve channels, exactly the ones DESIGN section 18 names, asserted by `the_twelve_design_channels_are_all_present`. An unknown channel fails to decode rather than becoming an unrecognized value every coverage contract would silently ignore.

`SupplyChainObservation` has no `Verdict` variant, no `Violation` variant, no `Finding` variant and no field shaped like one. `an_observation_cannot_carry_a_verdict` asserts four hostile shapes are refused, including a whole `"channel": "VERDICT"` observation. An adapter able to emit one would decide the outcome and reduce the evaluator to transcribing whatever a fixture author wrote.

## Why observations exist at all, given the evidence bundle already does

`SupplyChainEvidence` is what was **imported**. Observations are what a run **saw**, and the difference is the entire basis for INCONCLUSIVE.

`project()` emits **nothing** for a component with no digests, rather than a digest context saying `has_digest: false`. The second shape reads as an answer; the first is honestly the absence of one, and only the first lets an evaluator say the question was undecidable.

`a_component_with_no_digest_produces_no_digest_context` asserts it.

## Absent policy stays unanswered

`an_absent_policy_leaves_signer_and_builder_approval_unanswered` — `builder_approved` is `None`, not `false`. With no policy nobody asked the question, and answering it would make every component a finding.

## Unapproved signers are named, not counted

`an_unapproved_signer_is_named_rather_than_counted`. "An unapproved signer attested this" is only actionable if the operator learns which one, so the context carries `approved_signer_ids` and `unapproved_signer_ids` as sets rather than a count or a boolean.

## Determinism

`projection_is_deterministic` — two runs over the same evidence digest identically. Every collection in every context is a `BTreeSet` or a sorted `Vec`, so document order cannot change the output.

`every_observation_digests_and_the_digests_differ` — deciding-evidence citation is only useful if two different observations cite differently.
