# task-018 — Implement model lineage projection and binding

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-42, AC-43

## Evidence

`src/model_lineage.rs`. Seven tests.

**AC-43 — a model name alone cannot prove lineage.** A model called `llama-3-8b-finetuned` tells you what somebody named it; a substituted base model leaves that name unchanged. Lineage is therefore read from typed edges (`TRAINED_FROM`, `FINE_TUNED_FROM`, `BUILT_FROM`) between component identities, and the expectation in `ExpectedLineage` is a **component id**, never a name — `expected_lineage_is_expressed_as_an_id_and_not_a_name` asserts a `base_name` field fails to decode.

**AC-42 — PASS, FAIL and INCONCLUSIVE all have tests.**

- PASS: `an_approved_base_that_is_observed_matches`.
- FAIL: `a_substituted_base_model_does_not_match` — the finding the property exists for.
- INCONCLUSIVE, twice, for two different reasons: `missing_lineage_evidence_is_undecidable_rather_than_a_match` (nothing observed) and `a_missing_expectation_is_also_undecidable` (nothing approved). Both return `None` from `base_matches()`, never `Some(true)`.

**Digest binding is checked against the approved base, not the observed one.** This is the subtle part. Checking the observed base component own digests would let a substituted base that reused the approved id agree with itself — it would carry its own digest and match it. The comparison is against `ExpectedLineage::base_digests`, which the manifest supplied.

`the_right_base_with_the_wrong_digest_is_still_a_substitution` asserts `base_matches() == Some(true)` and `base_digest_bound == Some(false)` simultaneously: the right id and the wrong bytes is the same substitution one level down, and an engine reporting only the first would pass it.

**A model may derive from several bases.** `a_model_may_derive_from_several_bases`. Merged models are real, and requiring the approved base to be the *only* observed one would report a finding on a legitimate architecture.
