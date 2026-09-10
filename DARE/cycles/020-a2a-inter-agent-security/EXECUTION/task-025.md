# task-025 — Implement security requirement satisfaction invariant

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

I04 — decide whether the mechanism actually used satisfies a requirement the card declares and policy approves.

## Files changed

- `crates/dare-a2a-security/src/invariant.rs` (the evaluator, its violations and its `applies_to` arm)
- `crates/dare-a2a-security/src/observation.rs` (the context this evaluator reads)
- `crates/dare-a2a-security/src/simulated.rs` (the reference behaviours that stage it)

## Two comparisons, not one

`satisfies_card_requirement` asks whether the scheme used is one the card requires for the skill invoked. `kind_approved_by_policy` asks whether that kind of scheme is one the local deployment accepts at all. Both are needed: a card can require a scheme the deployment has decided is no longer good enough, and satisfying the card is not the same as satisfying policy.

*declared security scheme != successful authentication* is the distinction, and I04 sits deliberately between I02 (did authentication succeed) and I05 (may this subject do this). A card declaring OAuth means the peer says OAuth is available; it says nothing about what happened.

`SecuritySchemeUnsatisfied` stages a card that additionally declares a legacy API-key scheme and an exchange that used it, which is the realistic shape of this failure: the weak option is usually declared, not smuggled.

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
