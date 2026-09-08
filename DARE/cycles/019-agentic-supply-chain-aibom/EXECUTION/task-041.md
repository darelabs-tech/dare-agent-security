# task-041 — Build CycloneDX/SPDX import/equivalence corpus

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-24, AC-25, AC-26, AC-66

## Evidence

`src/corpus.rs` (the forty entries) and `crates/dare-supply-chain-security/tests/supply_lab.rs` (the harness contract).

## The split that makes the corpus worth having

An entry records a **class** — `CONTROL`, `ATTACK`, `REFUSAL`, `GAP` — and never a verdict. There is no `expected_verdict`, no `expected_findings`, no `is_secure`. `no_entry_declares_an_outcome_anywhere_in_its_evidence` asserts none of those strings reaches the evaluator from any of the forty bundles.

The expectation lives in the harness contract instead, asserted once per class rather than per fixture:

- **ATTACK** — the declared invariant must report `FAIL`, and every violation must cite deciding evidence.
- **CONTROL** — nothing may `FAIL`, and the declared invariant must reach `PASS`.
- **REFUSAL** — the bundle must be refused before evaluation, and the refusal must not echo what it refused.
- **GAP** — the declared invariant must be `INCONCLUSIVE`: never `PASS`, and never `FAIL` either, because thin evidence is not a finding.

## Entries 030–033

| Entry | Class | What it stages |
| --- | --- | --- |
| 030 | control | a CycloneDX 1.7 document normalizing into the internal model |
| 031 | control | an SPDX 3.0.1 document normalizing into the **same** internal model |
| 032 | control | the SPDX half of the cross-format equivalence pair |
| 033 | refusal | a bill of materials declaring an unsupported specification version |

These entries go through the **real importers** rather than staging a bundle in memory. Everything else in the corpus proves the evaluators work; these prove the parsers do.

**AC-26 — the equivalence test asserts both halves.** `cyclonedx_and_spdx_halves_describe_the_same_system` first asserts the two bundles came from **different formats**, then asserts they describe the same system. Without the first assertion the test could pass by comparing a bundle with itself, which is the failure mode a same-system assertion invites.

The comparison is over `semantic_keys()`, which excludes the evidence source. Including it would mean the test asserted that CycloneDX is not SPDX — true, and useless.

**033 refuses rather than guessing.** A document declaring CycloneDX 1.4 is refused; reading it under 1.7 semantics would mean guessing which specification's field meanings apply, and the fields that moved between versions are exactly the ones a security decision reads.

## A fixture that had to be corrected

The SPDX entry was first written with `spdxVersion: "3.0.1"`, `elements` and `packageVersion`. The importer reads `specVersion`, `@graph` and `software_packageVersion`, so the fixture was refused for declaring no specification version — the importer was right and the fixture was wrong. Had the importer been lenient about the shape, the fixture would have imported as an empty document and the equivalence test would have compared two empty bundles and passed.
