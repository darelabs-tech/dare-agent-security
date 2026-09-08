# task-002 — Record verified standards/status snapshot and provenance assets

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-07, AC-08, AC-09, AC-10, AC-11, AC-12, AC-13

Record the standards this cycle reads, each with the status the approval assigned it, in a form a later edit cannot quietly change.

## Evidence

`standards/supply-chain-security/2026/provenance.json` — 8 sources, 10 surface classes, 10 property mappings, 11 trust distinctions, 10 explicit exclusions, 5 inherited lessons.

`crates/dare-coverage/src/supply_chain_standards.rs` — the validator, **22 tests, all passing**. `cargo test -p dare-coverage --lib` → 145 passed, 0 failed.

## Statuses, pinned rather than written down

A status recorded in prose decays in one direction: a `DRAFT` becomes a requirement and nobody notices, because nothing failed. `PINNED_SOURCE_STATUS` makes each one a test.

| Source | Status | AC |
|---|---|---|
| OWASP Agentic Top 10 2026 — ASI04 | NORMATIVE | AC-07 |
| CycloneDX 1.7 | NORMATIVE | AC-08 |
| ECMA-424 2nd Edition | NORMATIVE | AC-08 |
| SPDX 3.0.1 | NORMATIVE | AC-09 |
| SLSA 1.2 | NORMATIVE | AC-10 |
| in-toto Attestation Framework v1.2 | NORMATIVE | AC-11 |
| Sigstore/Cosign | **INFORMATIVE** | AC-12 |
| CycloneDX v2.0 / TEL | **FUTURE** | AC-13 |

`promoting_an_informative_source_to_normative_is_refused` and `promoting_the_future_source_is_refused` each edit the record in memory and assert the validator rejects it. Sigstore is the one most likely to be promoted by accident — it is a real verification system and easy to write as though this cycle used it. It does not: it models a status field a document already carried.

## The distinction the file exists for

**No property mapping may be `NORMATIVE`.** A mapping says where a property borrowed its vocabulary; it never says the specification requires the property. `ALLOWED_MAPPING_STATUS` omits `NORMATIVE` even though `ALLOWED_SOURCE_STATUS` includes it, so the type system holds the distinction rather than the reader's memory.

`ALLOWED_RELATIONS` is two — `SPECIALIZES` and `COMPOSES_WITH`. `IMPLEMENTS` and `CONFORMS_TO` are absent because neither is true of anything this cycle does.

## No conformance claim, and an honest denial that still works

`assert_no_conformance_claim` refuses twelve phrasings across every free-text surface, including the disclaimer itself — a disclaimer that claimed conformance would be the exact failure it exists to prevent.

The detector is **sentence-scoped**, which matters: a record must be able to say what it is *not*, and the natural phrasing contains the phrase being denied. `an_honest_denial_stays_writable` checks that "nothing here is CycloneDX compliant" passes, and `a_denial_in_one_sentence_does_not_license_a_claim_in_the_next` checks that the denial does not extend past its sentence.

`assert_no_status_promotion` separately refuses "SLSA level achieved", "TEL is required" and six more. This cycle assigns no SLSA level to anything, because a level is a statement about a build system that no local document can establish on its own.

## What the record says plainly rather than leaving to inference

Two tests assert the record denies things a reader would otherwise assume from the presence of version numbers:

- `the_record_says_plainly_that_nothing_was_reverified` — no upstream re-verification was performed; these are the statuses the approval froze on 2026-09-08 and they should be re-checked before being relied on.
- `the_record_says_plainly_that_nothing_is_fetched` — a URL or registry coordinate inside imported evidence is inert metadata, and "naming something is not authorization to go and get it".

`the_record_carries_no_credential_or_reachable_target` checks the committed JSON contains no `http://`, `https://` or credential marker at all. Provenance files usually cite specification URLs; this one records title and version instead, so there is nothing in it a reader's tooling could follow.

## The eleven trust distinctions

`DESIGN.md` §2 lists eleven places where two things that look alike are not the same thing. All eleven are in the record and pinned by `REQUIRED_TRUST_RULE_MARKERS`; `removing_a_trust_distinction_is_refused` deletes "component URL != authorization to fetch" and asserts the validator catches it.
