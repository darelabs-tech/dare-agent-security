# task-007 — Implement the OTLP/JSON model and the trace-subset schema

**Status:** DONE  
**Complexity:** MED

## `src/otlp.rs`

The reader walks `serde_json::Value` by hand, not with derive, so every refusal carries a
fixed rule name and unknown fields can be counted.

- **Types:** `AnyValue` (Empty, Str, Bool, Int, Double, Bytes kept as base64 text, Array,
  KvList), `KeyValue`, `Event`, `Kind` (the 6 OTLP span kinds) and `Span`. Each span
  carries its resource attributes and scope name. `TraceFile{spans, unknown_fields}`
  holds the result.
- **OTLP JSON rules:**
  - trace and span ids are case-insensitive hex of 16 and 8 bytes, lowercased; all-zero
    ids are refused (R-2);
  - times and `intValue` are accepted as a decimal string or a number;
  - enums are integers;
  - `AnyValue` must be a one-of: two members refuse with `any_value_one_of`, and none
    reads as `Empty`;
  - an empty `parentSpanId` means a root span;
  - more than 256 attributes on a span refuse with `attributes`.
- **Unknown fields:** the top level must be exactly `{resourceSpans}`, or the reader
  refuses with `top_level`. Below the top level, unknown fields are ignored, as OTLP
  requires, and counted in `unknown_fields`.

## Schema and `src/schema.rs`

- `schemas/runtime-telemetry/v1/otlp-trace-subset.schema.json` is draft 2020-12. It
  closes the top level, requires the span's ids, name and times, and patterns the ids and
  `uint64` values.
- `src/schema.rs` embeds it with `include_str!` and provides `conforms`.

## Tests

- `a_span_reads_with_both_time_encodings_and_lowercased_ids`
- `any_value_is_a_one_of_with_nested_arrays_and_kvlists`
- `events_links_status_and_dropped_counts_are_read`
- `unknown_fields_below_the_top_level_are_counted_and_the_top_level_is_closed`
- `every_malformed_field_is_refused_with_its_rule`: 13 cases plus the attribute bound
- `the_trace_schema_and_the_reader_agree`: a good export is accepted by both, and an
  extra top-level key or a bad id is refused by both

Ralph Loop: fmt and clippy clean; 22 crate tests pass.
