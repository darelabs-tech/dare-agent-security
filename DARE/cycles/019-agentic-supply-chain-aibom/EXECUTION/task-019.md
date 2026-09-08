# task-019 — Implement dataset provenance/lineage projection and scope boundary

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-44, AC-45

## Evidence

`src/dataset.rs`. Seven tests.

**AC-44 — dataset provenance has PASS and FAIL tests.** A dataset is a component: it has an identity, it has bytes, it came from somewhere, and a model was trained on it. Those four are supply-chain questions.

- PASS: `an_approved_dataset_with_a_matching_digest_binds`.
- FAIL: `a_substituted_dataset_does_not_bind`.
- INCONCLUSIVE: `a_dataset_nobody_approved_is_undecidable_rather_than_wrong`, and `an_approval_with_no_digest_leaves_integrity_undecided` — approving a dataset by name says which dataset was meant, not which bytes, and treating a name approval as a digest approval would let any content under the approved name pass.

**The assessment names the consuming models.** `the_assessment_names_the_models_that_consumed_the_dataset`. A substituted dataset matters in proportion to what trained on it; a finding that names the affected models is actionable in a way one naming only the dataset is not.

**AC-45 — the scope boundary is structural.** No privacy analysis, no PII detection, no copyright or licence assessment, no fairness or bias evaluation. These are real questions about datasets and none of them is a supply-chain question.

The engine sees a dataset **identity and digest and never its contents** — it could not evaluate bias if it wanted to, and a field inviting the attempt would be a promise the engine cannot keep.

`the_dataset_model_has_nowhere_to_record_a_privacy_finding` asserts both halves: that no `pii`, `privacy`, `copyright`, `licence`, `license`, `bias` or `fairness` field appears in the serialized assessment, and that `pii_detected`, `license_conflict` and `bias_score` all fail to decode.
