# task-030 — Implement tenant boundary invariant

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

I09 — decide whether the exchange stayed inside the approved tenant.

## Files changed

- `crates/dare-a2a-security/src/invariant.rs` (the evaluator, its violations and its `applies_to` arm)
- `crates/dare-a2a-security/src/observation.rs` (the context this evaluator reads)
- `crates/dare-a2a-security/src/simulated.rs` (the reference behaviours that stage it)

## Three answers, not two

**Crossed** — the claimed tenant is not the one policy records for the subject, or the peer is not one that tenant approved.

**Held** — both comparisons succeeded.

**Undecidable** — policy records nothing about this subject, so the claim can be neither confirmed nor contradicted.

The third is the answer this invariant most needs to be able to give. *tenant routing value != proof of tenant authorization*: the claim in the message is a value the sender chose, and when there is nothing to compare it against, reporting a pass would treat the sender's choice as its own proof.

Corpus entry `A2A-LAB-033` is that case and is classified GAP rather than ATTACK, so the harness never demands a FAIL the evidence cannot support.

`a_cross_tenant_claim_fails_and_names_both_tenants` asserts the violation names the claimed tenant and the recorded one — one without the other is half a finding.

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
