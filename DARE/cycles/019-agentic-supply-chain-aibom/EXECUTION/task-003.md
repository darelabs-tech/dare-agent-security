# task-003 — Extend Agentic registry with exactly eight additive supply-chain properties

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-02, AC-03, AC-04, AC-05, AC-06, AC-07

## Evidence

`schemas/coverage/v2/registry.json` moves 40 → 48. `crates/dare-coverage/tests/supply_chain_properties.rs` — 15 tests, all passing. `cargo test -p dare-coverage` → 317 passed, 0 failed.

The eight added, all under the existing `AGENTIC_SUPPLY_CHAIN` family and the `SUPPLY_CHAIN` category:

`COMPONENT_IDENTITY`, `ARTIFACT_INTEGRITY`, `SOURCE_TRUST`, `ATTESTATION_BINDING`, `DEPENDENCY_INTEGRITY`, `MODEL_LINEAGE`, `DATASET_PROVENANCE`, `BOM_COMPLETENESS`.

`exactly_the_eight_approved_properties_were_added` compares the whole namespace against the approved set rather than counting it, so an extra property and a missing one fail the same test with different messages.

## What "additive" is asserted to mean

**AC-03, AC-04 — the two inherited properties are unchanged, not merely present.** `the_two_inherited_properties_are_unchanged` pins each one's risk family, category *and* its exact two predicates. A cycle that quietly added a third predicate would narrow when an inherited property applies — a change to what every assessment already filed against it means, with no requirement level edited and no denominator moved.

**AC-71 — the baseline profile's selection and level are pinned.** `the_agentic_baseline_profile_keeps_its_supply_chain_selection_and_level` asserts `AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE` is still selected at `CONDITIONAL`, and that none of the eight new properties joined the baseline profile without an approval.

**AC-02 — the family count still reads ten.** Asserted in both directions: the count is 10 and `AGENTIC_SUPPLY_CHAIN` is among them. A property that forgot its family and one that invented a family fail differently, and only one of those moves the number.

**AC-06 — no parallel namespace.** Checked across both registries, not just v2.

## One decision worth recording

The eight properties initially carried an interchange standard each — CycloneDX, SPDX, SLSA, in-toto, ECMA-424 — alongside ASI04. That failed `agentic::committed_agentic_assets_validate_offline`, because the registry's `standards` field is checked against the **Agentic provenance manifest**, whose sources are risk taxonomies.

The fix was to keep taxonomy provenance in the registry and leave interchange mapping to the Cycle 019 provenance record, where it already lives with constrained relations and non-NORMATIVE statuses. Adding CycloneDX to the Agentic manifest would have created two places recording the same mapping that must then agree.

`the_registry_records_taxonomy_provenance_rather_than_interchange_formats` asserts both halves: the registry cites only ASI04, and the cycle record maps the four interchange sources.
