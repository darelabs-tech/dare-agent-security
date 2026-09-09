# task-012 — Define data-scope/disclosure boundary projection

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Compare what an exchange carried with what the peer receiving it may be told.

## Files changed

- `crates/dare-a2a-security/src/data_scope.rs` (new — the disclosure assessment)

## Decisions

`DataSensitivity` is an ordered closed enum, so "more sensitive than" is a comparison the type supports rather than a lookup table an evaluator maintains. `MessagePart::peak_sensitivity()` takes the highest label a part carries: a message is as sensitive as its most sensitive part, and averaging would let one restricted field ride along inside an otherwise public payload.

`DataScopePolicy` carries a per-peer ceiling and a set of approved destinations. Both are needed for the same reason the tenant policy needs two maps — the ceiling governs what the peer may be told, and the destination set governs where it may be sent onward.

The assessment returns `Option<bool>`: a peer with no ceiling recorded is undecidable, not unlimited.

## Commands executed

```
cargo test -p dare-a2a-security data_scope
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

6 tests passing.

## Evidence

```
cargo test -p dare-a2a-security data_scope::
test result: ok. 6 passed; 0 failed
```

## Review result

**REVIEW PASS**
