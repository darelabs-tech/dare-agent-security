# task-026 — Add the scale test (O-08)

**Status:** DONE  
**Complexity:** LOW

## `tests/scale.rs`

The test is release-only: `#[cfg_attr(debug_assertions, ignore)]`, as in Cycle 024.

- **Input:** 2 000 traces of 50 spans each, written by the SIMULATED writer: 1 agent,
  45 tool calls, 3 HTTP calls and 1 retrieval per trace. Each trace is spread across
  all **64** files, so every trace must be rebuilt across files. That makes
  **100 000 spans**, analysed with the lab policy.
- **`a_hundred_thousand_spans_in_64_files_are_analysed_in_under_ten_seconds`** times
  `analyze` plus `artifacts`, that is, analysis and rendering of all four artifacts,
  including the schema check of each file and of the result. It asserts:
  - exactly 100 000 spans and 2 000 traces;
  - no `stop_reason` and no incomplete trace;
  - `spans ≤ MAX_SPANS`;
  - four artifacts;
  - a time under 10 s.
- **`the_span_bound_cuts_exactly_at_its_value`**: with `max_spans` 12 345, exactly
  12 345 spans are analysed and `stop_reason` is `max_spans` (no overshoot).

**Measured here (release):** 3.84 s, a verdict of PASS, and 12.1 s for the whole file
including input generation. The margin is 2.6×, unlike the thin Cycle 024 margin
(R-6), so the hard 10 s bound of O-08 is kept as approved.

## Ralph Loop

| Step | Result |
|---|---|
| Build | release ok |
| Test | `cargo test -p dare-runtime-telemetry --release --test scale`: 2/2 |
| Lint | fmt; clippy `-D warnings --all-targets`: clean |
| Audit | No dependency change |
