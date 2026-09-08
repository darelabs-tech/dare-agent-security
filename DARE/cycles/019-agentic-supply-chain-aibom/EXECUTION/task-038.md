# task-038 — Build identity/integrity/source SUPPLY-LAB paired corpus

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-66, AC-67

## Evidence

`src/corpus.rs` (the forty entries) and `crates/dare-supply-chain-security/tests/supply_lab.rs` (the harness contract).

## The split that makes the corpus worth having

An entry records a **class** — `CONTROL`, `ATTACK`, `REFUSAL`, `GAP` — and never a verdict. There is no `expected_verdict`, no `expected_findings`, no `is_secure`. `no_entry_declares_an_outcome_anywhere_in_its_evidence` asserts none of those strings reaches the evaluator from any of the forty bundles.

The expectation lives in the harness contract instead, asserted once per class rather than per fixture:

- **ATTACK** — the declared invariant must report `FAIL`, and every violation must cite deciding evidence.
- **CONTROL** — nothing may `FAIL`, and the declared invariant must reach `PASS`.
- **REFUSAL** — the bundle must be refused before evaluation, and the refusal must not echo what it refused.
- **GAP** — the declared invariant must be `INCONCLUSIVE`: never `PASS`, and never `FAIL` either, because thin evidence is not a finding.

## Entries 001–008 and 037–039

| Entry | Class | What it stages |
| --- | --- | --- |
| 001 | control | every component resolves to one canonical identity |
| 002 | attack | one artifact under two canonical ids |
| 003 | control | the observed digest is the approved digest |
| 004 | attack | the artifact substituted under an approved identity |
| 005 | control | a floating tag **beside an immutable digest** |
| 006 | attack | a floating tag as the only identity |
| 007 | control | a supplier local policy approved |
| 008 | attack | a supplier nobody approved |
| 037 | control | a document omitting optional metadata |
| 038 | attack | two documents that each look consistent and collide once merged |
| 039 | refusal | a digest whose length does not match its algorithm |

**005 is the entry that stops the check being useless.** A container image tagged `latest` with a digest beside it is pinned by the digest. An engine that reported it would be reporting a naming convention, and an operator who sees that finding learns to skip the one that matters.

**037 is the same idea for completeness.** No supplier, no purl, no version — none of which is needed to decide whether identities are unambiguous. An engine that reported it would be reporting incompleteness as insecurity.

**038 is the cross-document case.** Each document is internally consistent; the collision exists only once they are merged, which is why validation runs on the assembled bundle rather than per import.
