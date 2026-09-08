# task-031 — Implement model-lineage and dataset-provenance evaluators

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-42, AC-43, AC-44, AC-45, AC-49

## Evidence

`src/invariant.rs` — `model_lineage`, `dataset_provenance`.

**AC-43 — the wrong base and the wrong build of the right base are both findings.** The evaluator reports them as two distinct reasons:

- `base_matches() == Some(false)`: the model derives from something else entirely. `a_substituted_base_model_fails_lineage` asserts the reason names `base-attacker`, and adds that the model's own name is unchanged — which is why the invariant cannot be answered from a name.
- `base_digest_bound == Some(false)` with the base id agreeing: a rebuilt base under the approved id. The same substitution one level down, and an engine reporting only the id would pass it.

**AC-42 — INCONCLUSIVE has two causes.** No observed lineage, and no approved lineage. Both leave `base_matches()` at `None`, the evaluator silent, and the coverage contract reporting the gap.

**AC-44 — dataset substitution names the consuming models.** `a_substituted_dataset_fails_and_the_finding_names_the_models` asserts the reason names `planner-model`. A substituted dataset matters in proportion to what trained on it; a finding naming only the dataset makes the operator go and find that out.

Where nothing records training on it, the reason says so explicitly rather than omitting the clause — an empty list and an unasked question look identical otherwise.

**AC-45 — the scope boundary holds through the evaluator.** The dataset evaluator reads `digest_bound` and `consuming_model_ids`. There is no privacy, PII, copyright, licence, fairness or bias input available to it, because `DatasetAssessment` has no field carrying one — `the_dataset_model_has_nowhere_to_record_a_privacy_finding` asserts such fields fail to decode.
