# task-044 — Build A2A-LAB task/context/delegation/tenant/data corpus

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Cover the surfaces where a correlation identifier is mistaken for a principal, a hop is mistaken for a grant, and a routing value is mistaken for proof.

## Files changed

- `crates/dare-a2a-security/src/corpus.rs`
- `crates/dare-a2a-security/tests/a2a_lab.rs`

## Entries

**Task and context (I07).** `023` control; `024` one task carrying messages from two initiating principals; `025` one task carrying two context ids; `026` the initiating principal changing under a matching task id. `026` is the distinction *taskId match != principal/context match* stated as directly as a fixture can state it: everything correlates and the principal has changed underneath.

**Authority propagation (I08).** `027` control — each hop narrows what it received; `028` a hop granting a skill the upstream hop never held; `029` a chain whose links do not connect grantee to grantor; `030` two chains recorded under one id, refused.

`028` is *delegation != privilege amplification*. `029` matters separately: a chain that does not connect is not a chain, and accepting it would let an unrelated grant be presented as the authority for a hop.

**Tenant (I09).** `031` control; `032` a message claiming a tenant the subject does not belong to; `033` a claim for a subject policy does not know — undecidable rather than a crossing, which is a different answer and a different fix; `034` a tenant identifier carrying a bidirectional override, refused.

`034` is worth its own entry: two tenant ids that render identically and compare differently are two tenants an operator believes are one, and the refusal happens in `assert_safe_identifier` rather than in an evaluator that would have to be right about it later.

**Data scope (I10).** `035` control — data within the peer's ceiling; `036` a message carrying data more sensitive than the peer may receive.

## The gap that had to stay a gap

`033` is the entry that carries *tenant routing value != proof of tenant authorization*. It would have been easy to report it as a crossing, and it is not one: nobody knows which tenant `user-unknown` belongs to, so the run cannot say the boundary was crossed **or** that it held. `no_gap_is_reported_as_an_applicable_pass` holds the second half of that; the first half is that its class is GAP and not ATTACK, so the harness never demands a FAIL the evidence cannot support.

## Commands executed

```
cargo test -p dare-a2a-security --test a2a_lab
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

All entries behave as their class requires. `024`, `025`, `026`, `028`, `029`, `032` and `036` report concrete failures; `033` stays undecided; `030` and `034` are refused before evaluation.

## Evidence

```
cargo test -p dare-a2a-security --test a2a_lab
test result: ok. 13 passed; 0 failed; 0 ignored
```

## Review result

**REVIEW PASS**
