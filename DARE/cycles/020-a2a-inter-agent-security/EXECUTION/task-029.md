# task-029 — Implement authority propagation/non-amplification invariant

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

I08 — decide whether authority held or narrowed across every hop.

## Files changed

- `crates/dare-a2a-security/src/invariant.rs` (the evaluator, its violations and its `applies_to` arm)
- `crates/dare-a2a-security/src/observation.rs` (the context this evaluator reads)
- `crates/dare-a2a-security/src/simulated.rs` (the reference behaviours that stage it)

## Two independent defects

**Amplification.** A hop granting a skill, a scope, a tenant or a sensitivity the upstream hop never held. `DelegationChain::amplifications()` returns every one, across all six `AmplificationKind` dimensions — reporting only the first would let a chain that widened twice read as a chain that widened once.

**Disconnection.** A chain whose links do not join grantee to grantor. This is not amplification and does not get amplification's message: an unconnected chain is not a chain, and accepting it would let an unrelated grant be presented as the authority for a hop.

*delegation != privilege amplification* is the distinction. Delegation is normal and expected; the whole point of A2A is that agents act for one another. What is not normal is a hop that ends holding more than it was given.

`a_widened_delegation_fails_and_names_the_hop_and_dimension` asserts the violation names both, because "the chain widened" is unactionable and "hop 2 gained transfer-funds" is not.

Cycle 015 owns delegation semantics; this invariant applies them to inter-agent hops and takes no verdict authority over Cycle 015's own findings.

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
