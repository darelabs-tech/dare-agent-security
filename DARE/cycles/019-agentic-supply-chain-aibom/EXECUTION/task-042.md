# task-042 — Build hostile/refusal/admission-boundary corpus

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-29, AC-30, AC-61, AC-62, AC-63, AC-64, AC-65, AC-69

## Evidence

`src/corpus.rs` (the forty entries) and `crates/dare-supply-chain-security/tests/supply_lab.rs` (the harness contract).

## The split that makes the corpus worth having

An entry records a **class** — `CONTROL`, `ATTACK`, `REFUSAL`, `GAP` — and never a verdict. There is no `expected_verdict`, no `expected_findings`, no `is_secure`. `no_entry_declares_an_outcome_anywhere_in_its_evidence` asserts none of those strings reaches the evaluator from any of the forty bundles.

The expectation lives in the harness contract instead, asserted once per class rather than per fixture:

- **ATTACK** — the declared invariant must report `FAIL`, and every violation must cite deciding evidence.
- **CONTROL** — nothing may `FAIL`, and the declared invariant must reach `PASS`.
- **REFUSAL** — the bundle must be refused before evaluation, and the refusal must not echo what it refused.
- **GAP** — the declared invariant must be `INCONCLUSIVE`: never `PASS`, and never `FAIL` either, because thin evidence is not a finding.

## Entries 019, 033, 034, 035 and 039

| Entry | What it stages |
| --- | --- |
| 019 | an edge naming a component nothing inventoried |
| 033 | an unsupported specification version |
| 034 | a document carrying a credential-shaped field |
| 035 | a document with more components than the hard maximum |
| 039 | a digest whose length does not match its algorithm |

**AC-69 — a refusal never echoes what it refused.** `every_refusal_is_refused_before_anything_is_evaluated` asserts the error message contains neither the planted credential value nor the malformed digest value. An error log is a persistence surface like any other: a message quoting a smuggled token back would store the credential it declined to store.

**AC-29/AC-30/AC-64/AC-65 — the budget is an admission boundary, not a reporting one.** Entry 035 carries `HARD_MAX_COMPONENTS + 1` components and is refused **during import**, before any of them is persisted. A limit enforced after normalization is a limit on reporting rather than on resource use — the Cycle 018 lesson.

**AC-61/AC-62/AC-63 — the hostile sweep runs over the whole document.** Entry 034 plants `api_key` on a component object. The sweep in `schema.rs` visits every value at every depth, including inside fields no model has a place for, which is the point: a hostile field placed where nothing will decode it is still a field in a document the engine is about to accept.

**No product state changes and no egress.** Every refusal entry reads bytes already in memory. Nothing is written, nothing is fetched, and the refusal happens before any parser reaches a model.
