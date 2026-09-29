# task-031 — Write REGRESSION.md and PROOF.md, run the completion gate and create the archive branch

**Status:** DONE. Two items are open for Review: R-9 and R-10.  
**Complexity:** MED

## Records

- **`REGRESSION.md`** is complete with R-1..R-11. The items added in this task:
  - **R-10:** RF-15 is refined. The projector declares the policy's relationships
    (`STATICALLY_PROVEN`) and the trace verdicts guard them, because RS-02 keeps
    observed names inside the engine.
  - **R-11:** the one gate failure is a frozen, load-sensitive Cycle 022 timing test.
- **`PROOF.md`** maps every item to an executed test:
  - O-01..O-08;
  - RF-01..RF-17 (RF-17 is out of scope by Q7 (b));
  - RNF-01..RNF-06 and RS-01..RS-09;
  - the approval decisions and the boundaries.

  `python scripts/k25/verify_proof_citations.py`: **143 cited names verified** against
  1 030 tests.

## A gap found by the proof and fixed (RNF-05)

Mapping RNF-05 showed that a PASS did not cite the spans that proved it: the evidence
listed only violation spans. Each deciding trace in `listed_traces` now carries
`observed_span_ids`.

- New test: `every_pass_cites_the_spans_that_prove_it`.
- The result document is unchanged, so the Cycle 023 `rt` bundle's result is
  byte-identical. Only its evidence file was regenerated with the CLI, and
  `projection_tables` and `binding` pass.

## Gate (Cycle 025 head, rustc 1.98.1)

| Step | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean |
| `cargo test --workspace --no-fail-fast` | 363 suites, **4 585 passed, 1 failed, 12 ignored** (baseline: 347 / 4 433 / 0 / 9) |
| the one failure | `dare-remote-validation` `at_two_per_second_consecutive_requests_are_at_least_500_ms_apart`: 494.3 ms against a 495 ms floor under full-workspace load. The crate is frozen and unchanged this cycle, and the test passes 5 of 5 isolated runs (R-11) |
| Release scale | runtime telemetry 2.57 s (bound 10 s); blast radius layered 11.8 s (reported over the 10 s target, under the 20 s ceiling, per the R-6 decision); attack paths 0.85 s |
| `cargo audit` | clean |
| k25 credential sweep and proof citations | clean and verified |
| mdBook EN/PT, canvas `--check` | clean and current |

## Archive branch

`agent/cycle-025-runtime-opentelemetry-security` is pushed at the head of
`claude/loving-newton-113zme`.

## Follow-up (2026-09-29): R-11 fixed

CI on PR #50 failed the same Cycle 022 test (494.2 ms). With the Product Owner's
authorization, the test was fixed:

- `rate_and_budget.rs` now allows 25 ms of arrival jitter per gap and checks the span
  of the whole run.
- **Results:** under CPU load it fails 0/30, against 3/12 before, on `main` and on this
  PR alike. A 480 ms mutant limiter is caught by the span check.
- The `dare-remote-validation` digest in `ENGINE_TREES` is re-pinned to `21099e0b…`.
- `dare-remote-validation` (all suites) and `attack_path_compatibility` pass.
- No `src/` file changed.

