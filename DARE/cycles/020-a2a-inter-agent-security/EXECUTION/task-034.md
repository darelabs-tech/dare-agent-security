# task-034 — Implement extension trust-boundary invariant

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

I13 — decide whether extensions in use were declared, approved and non-authoritative.

## Files changed

- `crates/dare-a2a-security/src/invariant.rs` (the evaluator, its violations and its `applies_to` arm)
- `crates/dare-a2a-security/src/observation.rs` (the context this evaluator reads)
- `crates/dare-a2a-security/src/simulated.rs` (the reference behaviours that stage it)

## Three questions, asked separately

An extension in use the card never declared. A declared extension local policy does not approve. A required extension claiming authority nobody granted it.

*extension declaration != extension authority* is the gap between the first and the third. A card declaring an extension is describing a capability; an extension claiming authority is asserting a right, and a card is not a thing that grants rights.

The base policy's `authority_bearing_extensions` set is empty, so an extension claiming authority is unapproved by default. Failing closed matters more here than almost anywhere else: an extension is precisely the mechanism by which a peer extends what the protocol lets it say.

`a_required_unapproved_extension_fails` covers the compound case — required *and* authority-claiming *and* unknown to policy — which is the shape an attacker would actually choose.

This invariant decides from what was observed alone: an extension either was declared and approved or was not, so `comparison_reason` exempts it from the second coverage step.

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
