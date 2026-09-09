# task-042 — Build A2A-LAB discovery/Agent Card corpus

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Open the A2A-LAB corpus with the discovery surface: card substitution, signature status, provider disagreement, and the controls that keep the discovery evaluator from being merely strict.

## Files changed

- `crates/dare-a2a-security/src/corpus.rs` (new — the corpus, its classes, and `CorpusAdapter`)
- `crates/dare-a2a-security/src/lib.rs` (`pub mod corpus;`)
- `crates/dare-a2a-security/tests/a2a_lab.rs` (new — the harness contract)

## What an entry may say, and what it may not

An entry carries an id, a surface, a **class**, the invariant it is built to be judged against, a description and a builder. There is no `expected_verdict`, no `expected_findings`, no `is_secure`. `no_corpus_entry_can_state_its_own_outcome` renders each scenario and asserts none of those names appear.

The expectation lives in `tests/a2a_lab.rs`, asserted once per class rather than once per entry. A fixture able to declare its outcome would turn every pair into a test of whether the fixture author and the evaluator agreed on a label.

The `invariant` field is a *coverage selector*: it says which invariant this vector was built to exercise. Every other invariant is still evaluated, and a concrete failure of one of them is still retained — `the_engine_never_reports_a_verdict_about_a_peer_it_did_not_observe` walks all fourteen outcomes for every entry.

## Discovery entries

`A2A-LAB-001` control, `002` substituted card (pinned digest does not match), `003` signature verified and found invalid, `004` unsigned card, `004B` a card policy says nothing about, `005` card and trace naming different providers, `006` a card larger than the engine will read, plus the six hostile-card refusals (`053`–`057`) and the location-rich control (`058`).

## Two corrections the harness contract forced

**`A2A-LAB-004` was written as a GAP and is a CONTROL.** An unsigned Agent Card looked like missing evidence, so the entry was filed as one. The run reported I01 PASS, and the reason was right: policy pins `expected_provider`, the provider comparison ran, and the binding to what policy approved was decided without a signature. The frozen distinction is *signed Agent Card != authorized provider*; it does not run backwards into *unsigned card == unbound card*. The entry now says exactly that, and `004B` — a card with no policy entry at all, where nothing was compared to anything — carries the real I01 gap.

**`A2A-LAB-011` was written as an I02 attack and is an I05 attack.** `PeerIdentityMismatch` stages a peer authenticating as `svc-somebody-else` with no delegated subject, and sets the authentication record to agree. Nothing mismatches: I02 asks about audience, provider and authentication status, and all three hold. What the staged bundle actually crosses is I05 — a service principal with no delegated subject invoking a skill granted only to `user-alice`. The entry was moved to the invariant that sees it. This is the distinction *successful authentication != skill authorization*, staged from the direction where there is no delegated subject at all.

Neither correction changes an invariant's semantics; both correct a fixture that named the wrong one.

## Commands executed

```
cargo build -p dare-a2a-security
cargo test -p dare-a2a-security --test a2a_lab
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

13 harness-contract tests passing.

## Evidence

```
cargo test -p dare-a2a-security --test a2a_lab
test result: ok. 13 passed; 0 failed; 0 ignored
```

## Review result

**REVIEW PASS** — discovery corpus in place; two misfiled entries corrected against the engine's actual answer rather than the engine bent to the fixture.
