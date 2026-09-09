# task-047 — Build explicit missing-evidence INCONCLUSIVE and multi-violation regressions

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Pin the two ways a run can overstate what it saw: missing evidence read as success, and a partial report of an exchange that crossed several boundaries.

## Files changed

- `crates/dare-a2a-security/tests/a2a_missing_evidence.rs` (new, 8 tests)

## The strongest of the eight

`removing_any_required_channel_removes_the_pass_that_depended_on_it` takes the compliant run — which passes everything it can decide — and, for every invariant and every channel that invariant's contract requires, re-evaluates with that channel's observations removed. The answer must stop being PASS, the coverage must stop being satisfied, and the missing channel must be named.

This is stronger than asserting one hand-built undecidable case, because it is driven by `contract()` itself: an invariant whose contract gains a channel is covered the day it gains it, and an invariant whose contract is quietly emptied fails here rather than passing on an empty run.

## The rest

- `an_empty_run_decides_nothing_and_aggregates_to_inconclusive` — the cheapest false PASS available, handed to the engine directly.
- `unrecorded_and_indeterminate_evidence_can_never_become_a_pass` — the frozen status semantics asserted on `VerificationStatus` itself, so a fifth status added later cannot default into satisfying positive evidence.
- `a_missing_signature_is_undecided_and_an_invalid_one_is_a_failure` — the same surface, two answers. Conflating them sends an operator to the wrong fix: one needs evidence collected, the other needs a peer stopped.
- `a_harness_failure_reports_error_rather_than_a_security_conclusion` — a run that could not execute has not observed a secure exchange, and reading it as one is the worst available answer because nobody looks again.
- `every_boundary_a_multi_violation_exchange_crossed_is_reported` — I06, I08 and I09 all reported for one exchange, and every violation in the flat list carries the observation digests that decided it. A report naming one crossing leaves an operator who fixes it believing the exchange is clean.
- `one_concrete_failure_outranks_every_undecided_answer` — Cycle 018 precedence, asserted on a run that genuinely mixes FAIL and INCONCLUSIVE.
- `an_inapplicable_invariant_never_drags_a_clean_run_below_pass` — the Cycle 019 correction carried forward. A compliant exchange that registers no push notification has not failed to prove anything about push notifications; the question does not arise. Without this, every clean run reports INCONCLUSIVE and the engine's PASS becomes unreachable in practice.

## Commands executed

```
cargo test -p dare-a2a-security --test a2a_missing_evidence
cargo test -p dare-a2a-security
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
cargo fmt --all
```

## Result

8 regressions passing. Whole crate green: 275 unit + 13 A2A-LAB + 8 missing-evidence = 296 tests. Clippy clean under `-D warnings`.

## Evidence

```
cargo test -p dare-a2a-security
running 275 tests ... test result: ok. 275 passed; 0 failed
running 13 tests  ... test result: ok. 13 passed; 0 failed
running 8 tests   ... test result: ok. 8 passed; 0 failed
```

## Review result

**REVIEW PASS**
