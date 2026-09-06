# Cycle 017 — Regression record

Every gate below was executed on the Cycle 017 branch before any pull request
was opened. Commands and results are recorded as they ran, not as they were
expected to run.

- **Branch:** `agent/cycle-017-rag-retrieval-security`
- **Baseline:** `main @ c0cd5edbb5a157d285b20177b7bd20a23b1811cc`
- **Approved starting head:** `3346d3aa435492e38d03990b844e050ec4aa07c5`
- **Toolchain:** rustc/cargo 1.94.1, Windows 11 msvc; Git Bash for the local
  workflow runner; mdBook 0.5.4
- **Files changed vs baseline:** 252

## 1. Executed gates

| Gate | Command | Result |
|---|---|---|
| Format | `cargo fmt --all --check` | clean |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | 0 warnings, 0 errors |
| Tests | `cargo test --workspace` | **2436 passing, 0 failing** |
| Audit | `cargo audit` | exit 0 — 0 vulnerabilities, 1 pre-existing allowed warning (see §4) |
| Cycle 017 gate | `python scripts/run-ci-job-locally.py .github/workflows/ci.yml rag-security-2026` | **all 41 steps PASSED** |
| Cycle 016 gate | `… memory-security-2026` | all 39 steps PASSED |
| Cycle 015 gate | `… identity-security-2026` | all 36 steps PASSED |
| Cycle 014 gate | `… tool-security-2026` | all 28 steps PASSED |
| Cycle 013 gate | `… prompt-injection-2026` | all 22 steps PASSED |
| Cycle 012 gate | `… agentic-registry-2026` | all 5 steps PASSED |
| Corpus generator | `python scripts/gen-rag-security-corpus.py --check` | current (24 entries) |
| Scenario generator | `python scripts/gen-rag-security-scenarios.py --check` | current (24 labs) |
| Hostile generator | `python scripts/gen-rag-security-hostile-fixtures.py --check` | current (80 cases, 81 files with the manifest) |
| Docs EN | `mdbook build book/en` | built |
| Docs PT | `mdbook build book/pt` | built |

The `rag-security-2026` step was run with the real workflow file rather than a
hand-written equivalent, which is the point of the requirement: a gate that is
only ever approximated locally is a gate nobody has actually run.

## 2. Cycle 017 test counts

| Suite | Passing |
|---|---|
| `dare-rag-security` unit (`--lib`) | 239 |
| `dare-rag-security` `lab_scenarios` | 9 |
| `dare-rag-security` `hostile_fixtures` | 9 |
| `dare-rag-security` `violations_and_hygiene` | 10 |
| `dare-rag-security` `offline_confidential` | 10 |
| `dare-coverage` `rag_security_properties` | 15 |
| `dare-coverage` `rag_security_profile` | 11 |
| `dare-coverage` `rag_security_standards` (lib) | 21 |
| `dare-product` `rag_security_metadata` (lib) | 11 |
| `dare-agent-security` `rag_security` (lib) | 10 |
| `dare-agent-security` `rag_security_cli` | 17 |
| `dare-agent-security` `rag_security_product` | 7 |
| **Cycle 017 total** | **369** |

Workspace total moved from **2067** (frozen in `BASELINE.md`) to **2436**.

## 3. Inventory after the cycle

| Item | Before | After |
|---|---|---|
| v2 registry properties | 34 | 40 |
| Agentic risk families | 10 | **10** (unchanged) |
| Property categories | 22 | 15 distinct in use, `RETRIEVAL` added |
| Profile files | 6 | 7 |
| RAG schemas | 0 | 8 |
| RAG corpus vectors | 0 | 24 |
| RAG lab scenarios | 0 | 24 |
| RAG hostile fixtures | 0 | 80 |

## 4. Defects found and fixed during execution

Four were found by writing the tests and gates, not by review. Each is recorded
with what would have gone wrong had it shipped.

### 4.1 `METADATA_FILTER_ENFORCED` could be evaded by not reporting

**Found by:** writing `violations_and_hygiene.rs` and probing every invariant on
RAG-LAB-022.

The evaluator read only the retriever's own `FilterDecision` observations. A
retriever that recorded honest decisions for the documents it really filtered,
and none at all for the one it smuggled in, satisfied the coverage contract
through the honest decisions and left the smuggled document unchecked.
RAG-LAB-022 does exactly that: `doc-salary` reaches a result carrying no
`department` field while the policy makes `department` mandatory, and the
invariant reported **PASS**.

That is a `PASS` produced by a missing observation — the outcome this cycle
exists to prevent — and it was inconsistent with how the same crate already
treated protected documents, which are checked against the corpus rather than
the observation.

**Fix:** the evaluator now checks a second, independent channel. Every document
that actually appears in a result is compared against the policy's mandatory
clauses using the corpus declaration, whatever decisions were or were not
recorded. Findings are deduplicated by document so the two channels cannot
double-report. Regression: `a_document_smuggled_past_the_filter_is_caught_from_the_corpus`.

### 4.2 A scenario could name a corpus vector that did not exist and still run

**Found by:** writing the CI job and noticing `corpus_id` was `null` in every
artifact.

The CLI resolved a scenario's declared corpus vector with `RagCorpus::get`,
which answers `None` both to "the scenario names the corpus as a whole" and to
"the scenario names a vector this corpus does not have". A scenario whose vector
had been renamed, removed or substituted therefore ran exactly as though it had
named nothing: the reference silently ignored, `bind_corpus` never reached, the
pinned digest never checked, and a clean artifact produced against a corpus
entry that was not there.

**Fix:** `RagCorpus::resolve` separates the three cases and refuses the third.
The corpus-wide reference stays legitimate — loading the corpus already verifies
every pinned entry digest, so there is no single vector to bind — and naming one
entry still binds and pins it. Regressions:
`a_scenario_naming_a_vector_the_corpus_does_not_have_is_refused` and
`naming_one_vector_binds_it_and_naming_the_corpus_binds_nothing`.

### 4.3 A provenance-absence branch was unreachable through any valid document

**Found by:** tracing which fixture could reach the `RETRIEVAL_PROVENANCE_PRESERVED`
detachment branch.

`Provenance.source_id` was required by the schema, so
`is_machine_readable()` could never be false for a schema-valid document. The
evaluator branch existed and nothing could reach it — a check that looked like
coverage and was not.

**Fix:** `source_id` became `Option<String>` in Rust and non-required in
`document.schema.json` and `document-store.schema.json`;
`ProvenanceContext.source_id` followed. RAG-LAB-008 now reaches the branch and
fails on it.

### 4.4 A hostile-registry refusal named no entry an operator could fix

**Found by:** the corpus registry hostile fixtures.

The general hostile sweep caught a URL-shaped path before the specific path
check ran, so the refusal was correct but named nothing actionable. Both orders
refuse and neither echoes the hostile value; only one tells an operator which
entry to fix.

**Fix:** the specific path check runs first.

## 5. Defects in my own tests, corrected before commit

Recorded because a test that passes for the wrong reason is worse than no test.

- **An inverted assertion.** `an_identifier_that_could_forge_a_log_line_is_refused`
  used `.unwrap_or_else(|_| panic!("was allowed"))`, which panics on exactly the
  `Err` that proves the check works. Changed to `.expect_err(...)` plus an
  assertion that the refusal does not echo the forged text.
- **Three over-broad "no endpoint" checks.** Banning the literal strings
  `https://`, `pinecone`, `qdrant` and so on flagged the engine's own schema
  `$id` values, and the honest note in the evidence and the summary that names
  the stores this cycle never contacts. Banning the word bans the sentence
  documenting the boundary. All three now check **reachability** instead: every
  `://` occurrence must belong to `https://darelabs.tech/schemas/`, which names
  a contract and is never resolved. A bare scheme with no host — how `schema.rs`
  spells the prefixes it *refuses* — is also allowed, and a companion assertion
  checks that refusal list still exists so the exemption cannot protect nothing.
- **A wrongly chosen independence probe.** The first version of
  `a_failing_run_of_one_invariant_leaves_the_others_independently_judged`
  asserted `TOP_K_BOUND_PRESERVED` holds on RAG-LAB-022. It does not, and the
  failure is genuine: a retriever that leaks two extra documents on top of its
  legitimate results really does exceed the ceiling. Suppressing that by
  trimming the fixture would have made it less faithful in order to make a test
  easier to write. The test now probes an invariant the lab genuinely leaves
  untouched.

## 6. Deviations from the plan

**One, and it is a scoping decision rather than a change of design.**

`DESIGN.md` states the six `AGENT.RAG.*` properties carry no Agentic risk
family, while `crates/dare-coverage/src/property.rs` required `risk_family` for
every `AGENT.*` property. `BASELINE.md` §3 records the three options that were
weighed. The chosen one relaxes the rule by namespace: `AGENT.RAG.*` is excluded
from the requirement *and forbidden from declaring one*, in all three places
that enforce it (the schema `allOf`, `property.rs` and `agentic.rs`).

Tests pin both halves: a non-RAG `AGENT.*` property without a family is still
refused, and a RAG property that claims a family is refused too.
`derive_risk_family_coverage` already skipped `None`, so the Agentic family
count stays exactly 10 without anything being hidden — asserted from both the
registry side and the profile side.

No other deviation. No property, profile, predicate or denominator that predates
this cycle was changed.

## 7. Residual risks

1. **`corpus_id` is `null` in the shipped lab artifacts.** Every RAG-LAB names
   the corpus as a whole rather than a single entry, so no single vector is
   bound and the field is accurately empty. The corpus is still fully verified —
   `load_corpus` checks every pinned entry digest — but an operator reading one
   artifact cannot tell from that field alone that verification happened.
   Binding each lab to its matching corpus vector would exercise `bind_corpus`
   end to end and is a reasonable follow-up; it was not done here because it
   would change all 24 fixtures and their digests late in the cycle for a
   reporting improvement, not a security one.
2. **One yanked transitive dependency.** `chacha20 0.10.1`, reached through
   `rand 0.10.2` via `rmcp` and `reqwest` in `dare-mcp-discovery`. It predates
   this cycle, is a yank rather than a CVE, `cargo audit` exits 0, and
   `dare-rag-security` does not depend on it — the crate declares no HTTP
   client, database driver, vector-store SDK or embedding runtime, and a test
   asserts that.
3. **The Portuguese book does not carry the Cycle 017 pages.** It carries none
   of the per-cycle concept pages (013 through 016 are all English-only). Adding
   Portuguese for 017 alone would make that book internally inconsistent. Both
   books build.
4. **Simulated and replayed observations describe a reference retriever.** They
   are marked `synthetic` in every artifact and every summary says so, but a
   reader who ignores that marking could still over-read a `PASS`. The bounded
   wording is enforced at write time rather than left to review.
5. **Coverage is the 24 approved vectors.** A retrieval failure mode outside
   them is untested, and the report says "not tested" rather than passing it.

## 8. What did not change

- No property that predates Cycle 017 was renamed, re-scoped or given a
  different applicability predicate.
- No earlier profile's property count moved, so no denominator behind an
  already-filed assessment moved. Asserted directly in
  `rag_security_profile.rs::no_earlier_profile_changed`.
- Cycle 006 denominator semantics are untouched.
- The Agentic risk family count is 10.
- The CI trigger is still `pull_request` / `branches: [main]` / `types: [opened]`.
  No push trigger was added.
- Cycle 013 remains the final judge for prompt-injection and
  instruction-boundary properties. Cycle 017 runs no second prompt-injection
  evaluator.
- Cycle 015 principal semantics are re-exported, not redefined.
- Cycle 016 memory semantics are untouched, and its gate is green. Retrieved
  content is not memory.
