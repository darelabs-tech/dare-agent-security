# task-010 — Reuse Cycle 015 delegation/authority semantics for inter-agent propagation

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Project Cycle 015's delegation semantics onto A2A hops without re-deciding them here.

## Files changed

- `crates/dare-a2a-security/src/delegation.rs` (new — `DelegationHop`, `DelegationChain`, `AmplificationKind`)

## What is reused and what is added

Cycle 015 owns identity, principal, delegation, privilege and tenant semantics. This cycle does not restate them and does not take verdict authority over them. What it adds is the A2A-specific projection: a chain of hops between *agents*, where each hop names a grantor, a grantee and the skills it carries.

`AmplificationKind` enumerates the six ways authority can widen across a hop rather than hold or narrow. `DelegationChain::amplifications()` returns every one it finds — reporting only the first would let a chain that widened twice read as a chain that widened once.

`is_connected()` is separate and checked separately. A chain whose links do not join grantee to grantor is not a chain at all, and accepting it would let an unrelated grant be presented as the authority for a hop. That is a different defect from amplification and gets a different message.

*delegation != privilege amplification* is the distinction, and it is asserted from both ends: a narrowing chain produces no amplification, and each of the six kinds is produced by a mutation built to produce exactly it.

## Commands executed

```
cargo test -p dare-a2a-security delegation
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

10 tests passing, including a table-driven case covering all six amplification kinds.

## Evidence

```
cargo test -p dare-a2a-security delegation::
test result: ok. 10 passed; 0 failed
```

## Review result

**REVIEW PASS**
