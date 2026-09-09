# task-032 — Implement replay/idempotency invariant

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

I11 — decide whether a repeated action was proven safe to repeat.

## Files changed

- `crates/dare-a2a-security/src/invariant.rs` (the evaluator, its violations and its `applies_to` arm)
- `crates/dare-a2a-security/src/observation.rs` (the context this evaluator reads)
- `crates/dare-a2a-security/src/simulated.rs` (the reference behaviours that stage it)

## The three-way split

Only repeats of **non-idempotent state changes** are in question. A repeated read is not a replay finding, and treating every repeat as suspicious would make the surface unusable.

A repeat is proven safe by either of two independent facts: the skill is one policy declares idempotent, or the exchange carried an idempotency key. Requiring both would report safe traffic; requiring neither would report nothing.

*message retry != safe replay* cuts in both directions, which is why the corpus pairs `A2A-LAB-037` (a repeat with a key — a CONTROL) against `A2A-LAB-039` (a repeat of a skill nobody declared idempotent). During execution `DuplicateNonIdempotentAction` initially staged `summarize`, which the base policy *does* declare idempotent, so the repeat was genuinely proven safe and the behaviour staged nothing. It now stages `send-invoice`, with a matching grant and card skill.

`a_repeat_with_no_replay_evidence_fails_and_a_read_repeat_does_not` holds both ends.

A run with no repeats is **inapplicable** rather than undecided: replay safety was never in question, and reporting INCONCLUSIVE would make every clean run unreadable.

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
