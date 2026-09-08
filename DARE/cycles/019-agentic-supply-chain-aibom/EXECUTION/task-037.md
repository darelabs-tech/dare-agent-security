# task-037 — Implement LOCAL_SYNTHETIC adapter under Cycle 009 safety concepts

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-55, AC-56, AC-57, AC-60

## Evidence

`src/local_synthetic.rs`.

**Why this adapter exists beside SIMULATED.** It generates a CycloneDX document and reads it back through the **real importer**. A bundle assembled directly in memory proves the evaluators work; only a generated document proves the importers do, and the parser path a hostile document would take is the path a synthetic document takes.

`a_generated_document_goes_through_the_real_importer` and `a_generated_substitution_is_seen_through_the_importer` assert both halves.

**AC-56/AC-57/AC-60 — the Cycle 009 budget.** `synthetic_budget` pins `max_state_changes` to 0, `max_external_egress_bytes` to 0 and `max_bytes_written` to 0. `the_budget_pins_state_changes_egress_and_writes_to_zero` asserts all three, and `the_snapshot_records_what_the_controls_allowed` asserts the report carries them.

Nothing is written to disk: what the adapter generates is bytes in a `Vec<u8>` that never leave the process. No artifact is executed, no archive is extracted, and no coordinate inside the generated document is resolved.

**The kill switch.** `pointing_an_approved_run_at_another_scenario_trips_the_kill_switch`. A run approved for one scenario that is pointed at another stops rather than collecting — without it, an approved allocation could be redirected at something nobody approved, and the allocation would still look correct in every record, because the record names the scenario the run was *approved* for.

**Generation is deterministic.** `generation_is_deterministic` over all 18 behaviours. A report's document digest is reproducible, so a changed digest means a changed generator rather than a changed run.

**The generator is held to the same standard as an imported document.** `no_generated_document_carries_a_hostile_field` runs the hostile sweep over every generated document. The generator is inside the trust boundary, and one that emitted a credential-shaped or fetch-shaped field would be teaching the corpus that such fields are normal.

**AC-58 restated where it is easiest to get wrong.** `a_generated_document_carries_a_coordinate_and_nothing_fetches_it` asserts the document contains `pkg:npm/react@1.0.0` and no `http`. Real documents carry purls, and refusing them would refuse every real document — the boundary is that nothing resolves one, not that none appears.

**A generated bundle carries no approval of its own.** `a_generated_bundle_carries_no_approval_of_its_own`. A generator that also produced the manifest would be approving the components it invented, and every synthetic run would agree with itself.
