# task-044 — Implement SupplyChainSecurityResult, artifacts, redaction and Cycle 001 evidence bridge

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-61, AC-75, AC-83

## Evidence

`src/result.rs` and `src/evidence_bridge.rs`.

**AC-75 — the artifact never claims a secure supply chain.** `complete AI-BOM != secure supply chain` is a rule of this cycle, and the report is where it is easiest to break: the sentence an operator actually reads.

- `a_clean_run_never_claims_the_supply_chain_is_secure` — a PASS reads *"this is a statement about the evidence supplied, not that the supply chain is secure"*.
- `an_inconclusive_run_says_it_established_nothing` — *"this run does not establish that the supply chain is intact"*.

**A harness failure is a result, not a lost run.** `a_harness_failure_becomes_an_error_result_rather_than_a_lost_run`. Returning `Err` would leave the scenario looking like it had never been attempted, and an operator scanning a report would see nothing where a broken input was.

**The artifact carries the route back to the evidence.** Document digests, per-violation deciding-observation digests, components and relationships evaluated, and the budget the run executed under. `a_substituted_artifact_produces_a_failing_artifact_with_its_evidence` asserts all of it is present.

**`violations` is always serialized.** An artifact where "no violations" is an absent field invites a reader — and a checker — to treat missing as unknown, and those are different answers. The local CI job's `--count violations=0` assertion is what surfaced this.

## The evidence bridge

**Twelve records per run, one per invariant.** An operator filtering by property must see the invariant that decided their question rather than a single record carrying an aggregate to unpack. `one_record_is_emitted_per_invariant` also asserts the twelve ids are distinct.

**Every record targets the synthetic lab.** `every_record_targets_the_synthetic_lab`. A Cycle 019 result is evidence about documents that were read; filing it against a real deployment would let a report present an inventory as a statement about a running system.

**Severity is never inferred.** `no_record_infers_a_severity_from_its_verdict`. Severity is a judgement a consumer makes, and baking one in would make this engine's opinion look like a fact.

**Every record carries the rules needed to read it.** `every_record_carries_the_rules_a_reader_needs_to_interpret_it` asserts the eleven trust relations and the execution note travel with the record. A record travels away from the run that produced it, and a reader holding one artifact must still know that an inventory is not trust.

**A standards attribution carries no URL.** `a_standards_attribution_carries_no_url`. A reference is not a retrieval target, and a URL there would be the first place somebody added one.

**AC-61/AC-83 — secret safety at the boundary.** `build_invariant_evidence` runs Cycle 001's `validate_secret_safety` and refuses rather than returning an unsafe record; `every_record_passes_cycle_001_secret_safety` exercises it over bundles carrying supplier, builder and signer identities.

## A test that was checking the wrong thing

`the_artifact_carries_no_credential_or_verdict_shaped_input` ran the *input* hostile-field sweep over the *output* artifact, and failed on the artifact's own `verdict` field.

The sweep is right and the test was wrong: an artifact carries a verdict because it **is** the evaluator's output, and running the document gate over it would refuse the field the artifact exists to publish. It is now `the_artifact_carries_no_credential_shaped_content`, which checks what actually must hold — that nothing credential-shaped or executable-shaped reached the artifact from the evidence.
