# task-022 — Implement discovery/Agent Card binding invariant

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

I01 — decide whether the card in hand is the card policy approved.

## Files changed

- `crates/dare-a2a-security/src/invariant.rs` (the evaluator, its violations and its `applies_to` arm)
- `crates/dare-a2a-security/src/observation.rs` (the context this evaluator reads)
- `crates/dare-a2a-security/src/simulated.rs` (the reference behaviours that stage it)

## What it reports

Five distinct crossings, each with its own message: a digest that does not match the one policy pinned, a provider policy did not approve, a card and an observed exchange naming different providers, a signature verified and found **invalid**, a signer policy does not approve, and interfaces the card advertises that policy did not approve.

## The line between a finding and a gap

A signature that was checked and failed is a finding. One nobody checked is a gap, and coverage reports it — `an_invalid_card_signature_fails_and_an_unrecorded_one_does_not` asserts both halves in one test, because the two are one line apart in the code and one word apart in a report.

*discovered Agent Card != authenticated identity* and *signed Agent Card != authorized provider* are the two distinctions here, and the second does not run backwards: an unsigned card whose binding the pinned provider already settles is not a failure. Corpus entry `A2A-LAB-004` holds that line, and `004B` — a card policy says nothing about — carries the real gap.

`a_substituted_card_fails_discovery_and_cites_its_evidence` asserts the violation carries the observation digests that decided it. A finding with no deciding evidence is an assertion, not a finding.

## Commands executed

```
cargo test -p dare-a2a-security --lib invariant::
cargo test -p dare-a2a-security --lib simulated::
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

24 invariant tests and 14 simulated-adapter tests passing; whole crate green.

## Evidence

```
cargo test -p dare-a2a-security --lib invariant::
test result: ok. 24 passed; 0 failed
```

## Review result

**REVIEW PASS**
