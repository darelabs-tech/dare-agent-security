# task-006 — Define closed peer identity, principal and endpoint binding model

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Keep the six things an A2A peer can be called separate, so no evaluator can substitute one for another.

## Files changed

- `crates/dare-a2a-security/src/peer.rs` (new — `PeerIdentity`, `PeerSet`)

## The six fields, kept apart on purpose

`peer_id`, `logical_agent_id`, `card_provider`, `authenticated_principal`, `delegated_subject` and `audience` are separate fields rather than one identity. Each is a different claim with a different basis, and collapsing any two is one of the frozen distinctions:

- a discovered card names a `logical_agent_id` and a `card_provider` — *discovered Agent Card != authenticated identity*
- transport names a server — *TLS server identity != agent-level authorization*
- authentication names an `authenticated_principal` — *successful authentication != skill authorization*
- delegation names a `delegated_subject` — *delegation != privilege amplification*

`authorization_subject()` returns the delegated subject when present, otherwise the authenticated principal, and never the provider, the endpoint or the logical agent. That method is the only way an evaluator obtains a subject, so no evaluator can quietly authorize a URL.

## Commands executed

```
cargo test -p dare-a2a-security peer
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

12 tests passing, including one asserting `authorization_subject()` never returns a provider or endpoint value.

## Evidence

```
cargo test -p dare-a2a-security peer::
test result: ok. 12 passed; 0 failed
```

## Review result

**REVIEW PASS**
