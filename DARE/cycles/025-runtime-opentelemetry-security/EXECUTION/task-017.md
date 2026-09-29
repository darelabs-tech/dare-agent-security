# task-017 — Implement aggregation, the result type and the result schema

**Status:** DONE  
**Complexity:** MED

## `src/result.rs`

- **`read_trace_paths`** admits 1–64 files: size, the 256 MiB total and depth.
- **`analyze(files, policy, mapping, bounds, mode) -> Run`** runs these steps:
  1. schema-check each file against the trace subset (refuse `InvalidTrace{schema}`,
     by position), read it, and normalize its spans;
  2. apply the span bound: a deterministic cut plus `stop_reason: max_spans`, and every
     trace gets the `SpanBound` gap;
  3. count unrecognized keys;
  4. reconstruct the traces;
  5. evaluate every rule on every trace, the behaviour rules only when there is a policy;
  6. aggregate per property (AD-05).
- **Aggregation:** FAIL > INCONCLUSIVE > PASS. With no PASS it is NOT_TESTED
  (`not_exercised`, no verdict). Without a policy, behaviour rules are NOT_APPLICABLE
  (`no_runtime_policy`, no verdict). A required operation unseen in every trace makes T-2
  INCONCLUSIVE (`required_operation_unobserved`).
- **Run verdict:** in the same order, and a run that judged nothing is INCONCLUSIVE
  (`nothing_judged`).
- **`RuntimeTelemetryResult`** holds:
  - the schema id, engine, mode and `synthetic`;
  - the semconv pins and mapping digest;
  - input file digests and counts, and the policy id and digest;
  - `max_spans` and `stop_reason`;
  - the trace summary: counts, spans by kind, unrecognized keys, incomplete traces with
    their gaps;
  - 9 property results: rule, property id, verdict, coverage, reason, per-trace counts,
    gaps, evidence ids (filled by task-018);
  - the verdict, `REDACTED` and the bounded claim.

  It has no time field (R-6).
- `schemas/runtime-telemetry/v1/result.schema.json` is closed and defines every
  enumeration.
- The temporary `#[allow(dead_code)]` from task-008 is removed; the accessors are now
  used.

## Tests (`tests/result.rs`, 9)

- conformant run passes and validates;
- one failing trace fails the property;
- an incomplete trace is never PASS;
- no policy: behaviour NOT_APPLICABLE, telemetry judged;
- a required operation unobserved;
- a span-bound stop leaves no PASS (this caught T-1, now INCONCLUSIVE under the stop);
- an empty export judges nothing;
- a schema refusal by position;
- the full verdict-combination order.

Ralph Loop: clippy `-D warnings` and fmt clean; 82 crate tests pass.
