# task-033 — Implement protocol negotiation/downgrade invariant

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

I12 — decide whether the version and interface used were ones policy permits.

## Files changed

- `crates/dare-a2a-security/src/invariant.rs` (the evaluator, its violations and its `applies_to` arm)
- `crates/dare-a2a-security/src/observation.rs` (the context this evaluator reads)
- `crates/dare-a2a-security/src/simulated.rs` (the reference behaviours that stage it)

## Three separate checks

A version below the policy floor, a version outside the approved set, and a transport policy does not approve. The floor and the set are separate because a version can be inside the set and still below a floor a deployment has since raised, and the two findings have different fixes.

*protocol compatibility != permission to downgrade* is the distinction. Both sides being able to speak 0.9.0 is a capability; whether they may is policy, and only the second is what this invariant answers.

The transport check reads the observed `TransportKind` rather than the card's advertised interfaces. A card can advertise a gRPC endpoint the exchange never used, and judging the advertisement would report a peer for something that did not happen.

`a_downgraded_protocol_version_fails` stages a card that also declares the older interface, which is the realistic shape: the downgrade path is usually advertised.

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
