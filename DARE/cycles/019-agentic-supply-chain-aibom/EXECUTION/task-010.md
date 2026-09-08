# task-010 — Implement CycloneDX 1.7 bounded importer

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-08, AC-24, AC-58, AC-59

## Evidence

`src/cyclonedx.rs`.

**AC-08/AC-24 — CycloneDX 1.7 normalizes into the internal model.** `SUPPORTED_SPEC_VERSION = "1.7"`; any other `specVersion` is refused rather than parsed on a best-effort basis. `map_component_type` and `map_hash_algorithm` are closed allowlists, and an unmappable value is an error, never a fallback bucket. There is no `OTHER` component type for exactly this reason: a catch-all turns every unrecognized class into something the evaluators silently skip.

**The importer never assigns trust.** `an_imported_component_never_carries_trust` asserts `source_trust` is `None` on every imported component regardless of what the document said about suppliers or publishers. A BOM records claims; approval arrives from the manifest.

**AC-58/AC-59 — coordinates are inert.** `purl` and `externalReferences` are read and stored as identifiers and metadata. Nothing in the import path can fetch, and `ordinary_bom_coordinate_fields_stay_readable` in `schema.rs` asserts these fields are not refused — refusing them would refuse every real document, which is how a safety check gets disabled.

**Admission runs before the model is built.** `the_ledger_admits_before_the_model_is_built` — the byte budget is charged against the raw document and the component budget against each entry *as it is admitted*, not after a full parse. This is the Cycle 018 lesson: a limit enforced after normalization is a limit on reporting, not on resource use.

## A design error the tests found

The first version mapped CycloneDX `application` to `ComponentType::Agent`. The cross-format equivalence test then failed against SPDX, where the same component normalized to `PACKAGE`.

The test was right and the mapping was wrong. Being an *agent* is a role a DARE manifest declares about a deployment; it is not something a build tool asserts, and a build tool has no way to know it. `application` now maps to `ComponentType::Package`. Had the equivalence test not existed, the two importers would have produced different component classes for the same system and every cross-format comparison would have reported a difference that was not there.
