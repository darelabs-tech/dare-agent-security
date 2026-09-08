# task-011 — Implement SPDX 3.0.1 bounded importer

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-09, AC-25, AC-58, AC-59

## Evidence

`src/spdx.rs`.

**AC-09/AC-25 — SPDX 3.0.1 normalizes into the *same* internal model.** Not a parallel model with a conversion step: `import()` returns the same `Component` and `Relationship` types the CycloneDX importer returns. A second internal representation would eventually disagree with the first, and the disagreement would surface as a finding.

`SUPPORTED_SPEC_VERSION = "3.0.1"`. `map_element_type` and `map_relationship` are closed; `an_unmappable_relationship_is_refused_rather_than_stored` asserts a relationship the model has no place for is an error rather than a dropped edge. A silently dropped edge is a dependency that stops being checked.

**AI packages become models and datasets become datasets.** `an_ai_package_becomes_a_model_and_a_dataset_becomes_a_dataset` — SPDX 3.0.1 has the AI and Dataset profiles, and mapping them to plain `PACKAGE` would remove exactly the components whose lineage and provenance this cycle exists to check.

**A document-level element is skipped, not refused.** `a_document_level_element_is_skipped_rather_than_refused`. An SPDX document describes itself as an element; treating that as an unmappable component would refuse every valid document.

**AC-58/AC-59 — `downloadLocation` is inert metadata.** Read, stored, never acted on. Nothing in this crate can fetch it.

**Relationships are recorded as observed.** `relationships_are_recorded_as_observed`. What a BOM records is what was *found*; what the manifest records is what was *expected*. Collapsing the two would make `declared dependency != observed dependency` unenforceable, and that distinction is what detects both an inserted dependency and a missing one.

**Hostile input is refused before any component is built.** `a_hostile_field_is_refused_before_any_component_is_built` — the sweep in `schema.rs` runs against the whole document first, so a credential smuggled into a field this importer never reads is still refused.
