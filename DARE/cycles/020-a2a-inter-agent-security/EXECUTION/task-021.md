# task-021 — Implement canonical peer/card/message/task normalization

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Assemble one evidence bundle whose digests do not depend on the order anything arrived in.

## Files changed

- `crates/dare-a2a-security/src/normalize.rs` (new — `A2aEvidence`, `DocumentRef`, `EvidenceBuilder`, `assessment_facts`)

## Decisions

`BTreeSet` and `BTreeMap` throughout, so a canonical digest depends on content and not on insertion order. Two runs over the same evidence delivered in different orders must produce the same digest, or every reproducibility claim in this cycle is unfalsifiable.

`EvidenceBuilder::build` charges peers, exchanges and delegation depth to the ledger **before** validating, so an oversized bundle is refused rather than validated and then rejected.

`A2aEvidence::validate` refuses an exchange naming a peer nobody described, two authentication records for one peer, two authentication records for one message, and two delegation chains under one id. Each is a case where the answer would otherwise depend on which record an evaluator read first.

## What is retained rather than refused

`provider_disagreements()` returns the peers whose card and trace name different providers. This is deliberately **not** a refusal. A card and a capture disagreeing about a provider is the substitution I01 exists to report, and refusing the bundle would hand an operator a run that could not observe instead of the disagreement it observed perfectly well.

That distinction — refuse what makes the question unanswerable, retain what *is* the answer — is the line this module draws.

`assessment_facts()` derives the fourteen Cycle 006 applicability facts from what was observed rather than declared, so a target cannot claim a surface it never showed.

## Commands executed

```
cargo test -p dare-a2a-security normalize
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

10 tests passing.

## Evidence

```
cargo test -p dare-a2a-security --lib normalize::
test result: ok. 10 passed; 0 failed
```

## Review result

**REVIEW PASS**
