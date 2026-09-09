# task-017 — Implement raw-byte/object/run-wide/output admission ledger

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Bound every dimension a hostile input could grow along, and bound the run's own output alongside them.

## Files changed

- `crates/dare-a2a-security/src/budget.rs` (new — `AdmissionLedger`)
- `crates/dare-a2a-security/src/lib.rs` (the `limits` module)

## What is bounded

Bytes per document, peers, exchanges, parts per message, skills and interfaces and security schemes per card, extensions, delegation depth, data labels, metadata bytes, evidence text, JSON depth, trials, output bytes per trial, and output bytes for the whole run.

## The Cycle 019 correction, carried in from the start

`admit_output` is charged **before** the write, and the final result artifact charges itself through it. The Cycle 019 post-merge review found that exempting the output artifact left the budget bounding everything except the largest thing the run produced. Here that is not a fix applied late; it is what `admit_output` is documented to do.

## Exhaustion is one-way

Once the ledger is exhausted the flag is never cleared. A run that hit a ceiling and then continued would produce a partial result indistinguishable from a complete one, and an operator reading it would believe the engine looked at everything.

`snapshot()` exposes the counters so an artifact can record what the run actually consumed rather than what it was permitted.

## Commands executed

```
cargo test -p dare-a2a-security budget
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

10 tests passing, including one asserting the exhaustion flag survives further successful admissions.

## Evidence

```
cargo test -p dare-a2a-security --lib budget::
test result: ok. 10 passed; 0 failed
```

## Review result

**REVIEW PASS**
