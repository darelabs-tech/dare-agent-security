# task-013 — Define replay/idempotency evidence and operation-safety model

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Separate a repeat that is safe from a repeat that is not, using evidence rather than assumption.

## Files changed

- `crates/dare-a2a-security/src/replay.rs` (new — the replay assessment)

## Decisions

`OperationEffect` is a closed three-value enum: read-only, idempotent state change, non-idempotent state change. A repeat only matters against the third, and treating every repeat as suspicious would make the surface unusable.

`ReplayPolicy` carries the set of skills declared idempotent and whether an idempotency key is required. Two independent ways a repeat can be proven safe, and the assessment accepts either: the skill is declared idempotent, or the exchange carried a key.

*message retry != safe replay* cuts both ways, which is why the corpus pairs `IdempotencyProven` with `DuplicateNonIdempotentAction`. An engine that reported the first would train an operator to ignore it, and an engine that missed the second would report nothing worth having.

`is_applicable()` is separate from `is_decidable()`. A run with no repeats has no replay question — reporting it as INCONCLUSIVE would make every clean run unreadable.

## Commands executed

```
cargo test -p dare-a2a-security replay
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

6 tests passing.

## Evidence

```
cargo test -p dare-a2a-security --lib replay::
test result: ok. 6 passed; 0 failed
```

## Review result

**REVIEW PASS**
