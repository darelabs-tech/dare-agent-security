# task-028 — Implement task/context/principal binding invariant

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

I07 — decide whether task, context and initiating principal stayed the same across an exchange.

## Files changed

- `crates/dare-a2a-security/src/invariant.rs` (the evaluator, its violations and its `applies_to` arm)
- `crates/dare-a2a-security/src/observation.rs` (the context this evaluator reads)
- `crates/dare-a2a-security/src/simulated.rs` (the reference behaviours that stage it)

## Three ways one task can be two

Messages sharing a `task_id` but carrying different `context_id` values; messages sharing a `task_id` but naming different initiating principals; and the combination.

*taskId match != principal/context match* is the distinction, and it is the one that most resembles a working system while being broken. Everything correlates. The identifiers line up. Only the third field disagrees, and it is the one that says on whose behalf the work is being done.

`a_task_carrying_two_contexts_fails_context_binding` stages the context case; `TaskSubstituted` and `PrincipalMismatch` stage the principal case from two directions — a second principal injected under the same task, and the principal changing between two otherwise identical messages.

This invariant decides from what was observed alone. There is no approved side that could be missing: a task carrying two contexts is a substitution whatever policy says, which is why `comparison_reason` exempts it from the second coverage step.

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
