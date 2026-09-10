# task-026 — Implement skill authorization invariant

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

I05 — decide whether the effective subject may invoke the skill that was invoked.

## Files changed

- `crates/dare-a2a-security/src/invariant.rs` (the evaluator, its violations and its `applies_to` arm)
- `crates/dare-a2a-security/src/observation.rs` (the context this evaluator reads)
- `crates/dare-a2a-security/src/simulated.rs` (the reference behaviours that stage it)

## The subject is not the peer

The subject compared against `SkillGrant::allowed_subjects` comes from `PeerIdentity::authorization_subject()` — the delegated subject when there is one, otherwise the authenticated principal, and never the peer id, the provider or the endpoint.

That indirection is the whole invariant. *successful authentication != skill authorization*: a peer that authenticated perfectly is a peer whose identity is established, and the question of what it may do on whose behalf has not yet been asked.

`an_unauthorized_skill_fails_and_names_the_subject` asserts the violation names the subject rather than the peer, because "planner is not authorized" and "user-mallory is not authorized" send an operator to two different places.

The corpus stages this from both directions: `A2A-LAB-016` with a delegated subject holding no grant, and `A2A-LAB-011` with no delegated subject at all, where the service principal itself becomes the subject and holds no grant either.

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
