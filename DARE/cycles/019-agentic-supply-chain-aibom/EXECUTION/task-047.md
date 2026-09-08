# task-047 — Add reproducible fixture generators where justified and determinism checks

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-66, AC-82, AC-83

## Evidence

`crates/dare-supply-chain-security/tests/generators.rs` and `scripts/k19/assert_no_real_credentials.py`.

**AC-82 — one generator, and it is reproducible.** `generate_cyclonedx` is the only generator this cycle introduces. `every_generated_document_is_byte_identical_between_runs` covers all 18 reference behaviours.

A report cites the digest of the document a run read. If the generator produced different bytes each time, that digest would change without anything about the run changing, and no regression could be distinguished from noise.

`generated_documents_differ_between_behaviours_that_stage_different_things` is the other half: identical output for every behaviour would be reproducible and useless.

**AC-66 read as a regression rather than a count.** `running_the_whole_corpus_twice_produces_identical_results` runs all forty entries twice and compares result digests. A corpus that produced different verdicts between runs would make every future comparison meaningless, and the count would still look right.

`staging_is_deterministic_for_every_entry` requires an entry that refuses to refuse both times, so a flaky refusal cannot pass as determinism.

**AC-83 — swept over bytes, not over source.** Three tests cover what reaches disk: `no_generated_document_carries_a_credential_key_or_live_endpoint`, `no_corpus_bundle_carries_a_credential_key_or_live_endpoint` and `no_artifact_a_run_writes_carries_a_credential_key_or_live_endpoint`. A fixture that was clean and an artifact that was not would still be a leak.

`a_purl_stays_in_the_fixtures_and_a_registry_host_does_not` states the distinction the coordinate rule rests on: a purl names a component, a registry URL names a place to fetch from, and a fixture carrying the second would teach the corpus that a fetch target is normal content.

## The sweep script, and the rule that differs by file

`scripts/k19/assert_no_real_credentials.py` applies three rules, because one rule would have been wrong somewhere:

- **shipping code** may contain no credential shape and no live endpoint at all — a `const` holding an endpoint is where a fetch would start;
- **tests and guard lists** may name endpoints, because a test asserting a registry host never reaches an artifact has to write the host down to look for it. Banning the strings there would mean deleting the check;
- **JSON artifacts** may contain neither. They are the files that leave the repository.

The script was verified to bite: planting `https://registry.npmjs.org/react` in `canonical.rs` made it exit 1 naming the file and line.

**A correction during review.** The first version treated everything after the *first* `#[cfg(test)]` as test code. `lib.rs` has a nested test module inside `mod limits` well above the crate-level one, so any shipping code after it would have gone unswept — failing open on exactly the file that broke the convention. The skip is now brace-aware and resumes after each test module closes.
