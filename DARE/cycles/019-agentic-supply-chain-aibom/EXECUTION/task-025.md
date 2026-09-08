# task-025 — Implement deterministic 12-invariant registry/property mapping

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-49

## Evidence

`src/model.rs`, and `SupplyChainMode` in `src/source.rs`.

**AC-49 — exactly twelve invariants.** `the_registry_holds_exactly_the_twelve_approved_invariants` asserts the count, the names and their uniqueness. A thirteenth added during execution would change what the cycle claims to have proved without anyone reviewing the claim; the test fails if the count moves, so such a change cannot be silent.

**The property mapping is exactly the one DESIGN section 19 fixed.** `the_property_mapping_is_exactly_the_one_design_fixed` checks all twelve individually, and `twelve_invariants_report_under_ten_properties` checks the arithmetic.

Two pairs share a property deliberately:

- invariants 1 and 7 both report under `COMPONENT_PROVENANCE`;
- invariants 3 and 5 both report under `COMPONENT_IDENTITY`.

They are separate invariants because they fail for separate reasons — a component with no provenance at all is a different finding from one whose provenance names the wrong builder — but they answer the same question a reader of the property asked. Splitting the property would have made the registry describe the engine's internals rather than the risk.

`every_property_is_in_the_frozen_namespace` asserts the `AGENT.SUPPLY_CHAIN.` prefix. Cycle 012 owns the namespace, and a parallel `AGENT.SUPPLY.*` would give a reader two places to look for one risk.

## The scenario authority boundary

`SupplyChainScenario` implements DESIGN section 22. `a_scenario_cannot_declare_a_verdict_or_run_anything` asserts that seven hostile fields all fail to decode: `expected_verdict`, `expected_findings`, `is_secure`, `should_fail`, `evaluator_override`, `command` and `hook`.

The last two matter as much as the first five. A scenario describes evidence; it does not run anything, and a fixture that could name a command would be an arbitrary execution hook wearing a corpus entry's clothes.

`primary_invariant` is a **coverage selector, never a verdict** — `the_primary_invariant_is_a_coverage_selector_and_not_a_verdict`. Naming an invariant says which question the fixture was built to exercise, not what the answer is.

`a_scenario_without_a_description_is_refused`: a fixture nobody can explain is a fixture nobody can review, and a corpus of them proves only that the engine agrees with itself.

## The four modes

`SupplyChainMode` is closed at `STATIC`, `REPLAY`, `SIMULATED`, `LOCAL_SYNTHETIC`. `there_are_exactly_four_modes_and_none_of_them_is_remote` asserts the count, the exact names and that `REMOTE`, `LIVE`, `REGISTRY` and `NETWORK` all fail to decode. A remote mode would need a transport this crate does not declare, and adding the variant would be the first half of adding the capability.
