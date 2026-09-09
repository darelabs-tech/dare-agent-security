# task-024 — Implement message authenticity invariant

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

I03 — decide whether authentication evidence binds the exact message received.

## Files changed

- `crates/dare-a2a-security/src/invariant.rs` (the evaluator, its violations and its `applies_to` arm)
- `crates/dare-a2a-security/src/observation.rs` (the context this evaluator reads)
- `crates/dare-a2a-security/src/simulated.rs` (the reference behaviours that stage it)

## The two crossings

A signature verified and found invalid, and — separately — a **valid** signature covering a different envelope than the one observed.

The second is what this invariant exists for. *schema-valid message != authentic message* is the easy half; the hard half is that a signature over a message is not a signature over *this* message. Without `covered_envelope_digest`, a genuine signature lifted from another exchange is indistinguishable from one over the message in hand.

`a_signature_over_a_different_envelope_fails_message_authenticity` stages exactly that: status `VALID`, signer approved, covering something else.

A missing signature is neither of these. It is a gap, and `a_missing_signature_is_undecided_and_an_invalid_one_is_a_failure` (in the missing-evidence regressions) holds the separation — one needs evidence collected, the other needs a peer stopped.

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
