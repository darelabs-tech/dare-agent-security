# task-026 — Implement provenance and capability-drift evaluators

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-31, AC-32, AC-33, AC-41, AC-49, AC-50, AC-51

## Evidence

`src/invariant.rs` — `provenance_sufficient`, `provenance_bound`, `capability_drift`.

**Invariant 1 applies per class, not universally.** `provenance_sufficient` reports a component with no provenance only when its class *is* bytes — a package, an image, a model, an embedding model, a dataset. A framework or a prompt asset describes an arrangement, and demanding provenance for it would produce a finding nobody can remediate, which is how a check gets suppressed.

**Invariants 1 and 7 do not double-count one gap.** `missing_provenance_is_reported_once_and_not_twice`: invariant 1 reports the absence, and invariant 7 stays silent about it. Both firing would report one gap as two failures and inflate every incomplete bundle.

**AC-31/AC-32/AC-33 — three independent bindings, reported separately.** `provenance_for_a_different_build_and_an_unapproved_builder_are_two_findings` asserts a single component produces two violations when both fail, and that the outcome reason says `2 independent violations`. They are remediated differently: one is a substitution, the other is a policy gap.

`builder_approved == Some(false)` is required for the builder finding. `None` — no builder named, or no policy — is a gap the coverage contract reports, not a violation.

**AC-41 — drift PASS/FAIL/INCONCLUSIVE.** `a_capability_a_component_gained_fails_drift_and_is_named` (FAIL, naming `write-file`), `a_capability_a_component_withdrew_is_not_drift` (not a FAIL), and the INCONCLUSIVE path through `drifted() == None` when only one side exists.

`capability_drift_is_observed_from_a_manifest_alone` is the important one: a component that dropped its own capability projection must not make drift unobservable, because the approved side is what the *deployment* recorded, not what the component says about itself.
