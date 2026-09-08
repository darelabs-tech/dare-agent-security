# task-032 — Implement BOM-required-evidence completeness evaluator

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-49, AC-50, AC-51

## Evidence

`src/invariant.rs` — `bom_completeness`.

**The requirement is per component class, not global.** An artifact needs a digest; a model additionally needs lineage evidence; a dataset needs dataset provenance evidence. Demanding all of it from every component would report findings against components the requirement was never about, and those are the findings operators learn to skip.

`a_model_with_no_digest_fails_completeness_and_a_service_api_does_not` asserts both halves: the model with no digest is a violation, and the service API beside it is not. A service API is a running endpoint rather than bytes; a digest requirement against it is unremediable. Both components in the test lack a digest, so the test turns on the class rather than on the evidence.

The first version of this test used a `FRAMEWORK` as the negative case and was wrong: `expects_immutable_artifact()` includes `FRAMEWORK`, because a framework ships as a package. It passed only because the framework fixture happened to carry a digest, so it never tested the claim in its name.

**The missing evidence is named.** The reason reads `the bill of materials describes X as a MODEL without an artifact digest`, so an operator knows what to add rather than being told the document is incomplete.

**AC-50/AC-51 — completeness is the invariant most able to pass on nothing.** An empty run has no incomplete components, so the evaluator finds no violations, and without a contract it would report PASS. Its coverage contract therefore requires `BOM_DOCUMENT_CONTEXT`: deciding that required evidence is present means knowing a document was read at all.

`completeness_cannot_pass_without_a_document_having_been_read` in `coverage.rs` asserts it, and `an_empty_run_is_inconclusive_and_never_passes` in `invariant.rs` asserts it end to end across all twelve.
