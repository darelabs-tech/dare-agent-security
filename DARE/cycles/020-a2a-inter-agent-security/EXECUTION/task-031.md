# task-031 — Implement data-scope boundary invariant

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

I10 — decide whether disclosure stayed inside what policy allowed.

## Files changed

- `crates/dare-a2a-security/src/invariant.rs` (the evaluator, its violations and its `applies_to` arm)
- `crates/dare-a2a-security/src/observation.rs` (the context this evaluator reads)
- `crates/dare-a2a-security/src/simulated.rs` (the reference behaviours that stage it)

## What it compares

The peak sensitivity a message's parts carry against the ceiling policy sets for the peer receiving it, and the destination against the approved set.

Peak rather than average: a message is as sensitive as its most sensitive part, and averaging would let one restricted field ride along inside an otherwise public payload.

`DataSensitivity` is ordered, so "more sensitive than" is a comparison the type supports rather than a table an evaluator maintains and can get wrong.

A peer with no recorded ceiling is undecidable, not unlimited. That default matters: the opposite would mean a peer nobody has written a policy for is the one peer allowed to receive anything.

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
