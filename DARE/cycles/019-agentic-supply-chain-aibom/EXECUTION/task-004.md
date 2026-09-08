# task-004 — Add supply-chain applicability predicates and coverage compatibility tests

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-14, AC-70, AC-71, AC-72

## Evidence

Nine predicates added to the v2 schema enum (37 → 46), to the Rust `Predicate` enum, and to `AssessmentFacts`. `agent_present` and `external_components_present` are reused from Cycle 012 rather than restated.

## The AC-14 split, inherited from Cycle 018 rather than reinvented

Seven of the nine are **evidence or control** predicates. A target that ships external components but publishes no bill of materials, records no digest, declares no approved-source policy, carries no attestation, or exposes no dependency graph has a **gap** — `NOT_TESTED`. Reporting `NOT_APPLICABLE` there would let a target score better for supplying less evidence about itself.

Two are **target shape**: `model_component_present` and `dataset_component_present`. A system with no model genuinely has no model lineage to answer for.

`a_missing_supply_chain_control_is_a_gap_and_never_not_applicable` checks five evidence predicates end to end and asserts each yields `NOT_TESTED` with a non-empty rationale — a gap with no rationale is indistinguishable from one nobody looked at.

`a_target_with_no_model_or_dataset_is_not_applicable_for_that_property_only` checks the other direction, including that the absence does not spill onto the other nine properties.

`the_evidence_and_shape_classifications_do_not_overlap` asserts every new predicate is in exactly one class. A predicate in both would decide arbitrarily which branch ran, and the two branches produce opposite answers.

`a_complete_target_makes_every_supply_chain_property_applicable` is the control: tightening applicability is only correct if a target supplying everything is still assessed.

## Seven, not nine, gate the registry

`the_nine_new_predicates_exist_and_are_split_between_registry_and_engine` records why the split is 7/2 rather than an off-by-two.

`provenance_present` would naturally gate `AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE` — but that property is Cycle 012's and its predicates are frozen (AC-03). Adding a third would narrow when it applies. So provenance participates in **evaluation** rather than in applicability. `declared_observed_components_present` is the same shape: whether the declared/observed comparison can be made at all is the evaluator's question, not the registry's.

The test asserts the exact registry-gated set and that neither engine-only predicate has started gating a property, with a message saying what that would change.

## AC-72 — denominator maths untouched

No change to `math.rs`, `plan.rs` or `report.rs`. The additions are new enum variants, new fact fields and one new classification branch in `applicability.rs`, placed before the existing target-shape branch and after the existing auth-evidence branch.

## One refactor, and why it is not a semantic change

`AssessmentFacts` and `TransportKind` now derive `Default`, and the eight test helpers that construct facts literally end with `..Default::default()`.

Every cycle since 013 has added predicates, and a test that must list every field is a test that gets edited mechanically each time the struct grows — which is how an unrelated test acquires a change nobody read. Deriving `Default` does **not** affect deserialization: serde uses a field default only where `#[serde(default)]` says so, which is already true of every additive field and deliberately not true of the original required ones. `TransportKind` defaults to `Stdio`, the smaller surface, so a forgotten field understates what a target exposes rather than overstating it.

`cargo test -p dare-coverage` → **317 passed, 0 failed**; fmt and clippy clean.
