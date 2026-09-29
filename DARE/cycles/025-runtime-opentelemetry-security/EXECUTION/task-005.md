# task-005 — Implement `limits.rs` and `error.rs`

**Status:** DONE  
**Complexity:** LOW

- **`limits.rs`** holds the Design §4.3 maxima: 64 files, 16 MiB per file, 256 MiB in
  total, JSON depth 64, 1 000 000 spans, 256 attributes per span, 64 KiB scanned per
  value, tree depth 256. It adds a 1 MiB policy bound.
  - `Bounds{max_spans}` is lower-only.
  - `check` refuses 0 (`BoundZero`) and anything above the maximum
    (`BoundAboveMaximum`); it never clamps.
- **`error.rs`** defines `TelemetryError{Refused, Internal}` and `Refusal`, with 13
  variants.
  - An `Input` position (`trace file N` / `the policy file`) names the file.
  - `InvalidTrace` and `InvalidPolicy` carry a fixed `&'static str` rule name, never
    input content.

## Tests

- `the_maxima_are_the_design_values`
- `every_bound_refuses_zero_and_values_above_its_maximum`
- `lowering_takes_the_smaller_value`
- `no_error_message_echoes_input`: every variant renders only ASCII names and positions.

Ralph Loop green.
