# task-023 — Implement peer identity binding invariant

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

I02 — decide whether the authenticated party is the intended agent, audience and tenant.

## Files changed

- `crates/dare-a2a-security/src/invariant.rs` (the evaluator, its violations and its `applies_to` arm)
- `crates/dare-a2a-security/src/observation.rs` (the context this evaluator reads)
- `crates/dare-a2a-security/src/simulated.rs` (the reference behaviours that stage it)

## What it reports

A credential issued for another audience, an observed provider that is not the one policy expected, and an authentication verified and found invalid.

## What it deliberately does not report

It does not report on *which principal* authenticated. That is not evasion: the question "may this subject invoke this skill" belongs to I05, and answering it here would give the same crossing two owners and two messages. Corpus entry `A2A-LAB-011` was originally filed against I02 for exactly that reason and moved to I05, which is the invariant that sees it.

Audience is the check most often skipped in practice and the reason *TLS server identity != agent-level authorization* is on the frozen list: a credential can be entirely valid, correctly signed, and issued for somebody else.

An `UNRECORDED` authentication produces no violation and no pass — the question was never asked, and coverage says so.

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
