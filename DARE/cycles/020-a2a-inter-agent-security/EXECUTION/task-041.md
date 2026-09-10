# task-041 — Implement LOCAL_SYNTHETIC adapter under bounded local safety rules

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Generate local synthetic A2A evidence under the Cycle 009 control envelope, with a kill switch that cannot be talked out of.

## Files changed

- `crates/dare-a2a-security/src/local_synthetic.rs` (`LocalSyntheticAdapter`, `A2aControlSnapshot`, `synthetic_budget`, `generate_agent_card`)

## The controls are recorded, not assumed

`control_snapshot()` returns what the run was actually permitted: trial count, output ceilings, `MAX_STATE_CHANGES = 0` and `EXTERNAL_EGRESS_BYTES = 0`. A report that claimed a bounded run without recording the bounds would be asking the reader to take the boundary on trust.

`synthetic_budget()` derives the ledger from those constants rather than from a separate set of numbers, so the two cannot drift apart.

## The kill switch

The adapter holds a `Cell<bool>` that, once tripped, refuses every subsequent generation for the life of the adapter. It is never cleared. A generator that could resume after tripping would produce a partial corpus indistinguishable from a complete one.

## Synthetic evidence is labelled synthetic

`evidence_is_synthetic()` returns `true`, inherited from the trait's safe default. `generate_agent_card` marks every document it produces with `EvidenceSource::SyntheticFixture`, and `EvidenceSource::may_establish_approval()` returns false for it — a generated card cannot approve anything, no matter how plausible it looks.

## A defect found while removing a probe

Removing a throwaway decode probe left unbalanced braces in the test module. Repaired, and the module compiles and passes.

## Commands executed

```
cargo test -p dare-a2a-security --lib local_synthetic::
cargo test -p dare-a2a-security
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
cargo fmt --all
```

## Result

11 tests passing. Whole crate green at this point: 275 unit tests.

## Evidence

```
cargo test -p dare-a2a-security --lib local_synthetic::
test result: ok. 11 passed; 0 failed
```

## Review result

**REVIEW PASS**
