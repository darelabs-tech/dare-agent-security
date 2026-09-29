# task-012 — Implement completeness

**Status:** DONE  
**Complexity:** MED

`src/complete.rs`:
- **`View`** is a trace plus each span's classified kind. It offers `of(kind)`,
  `kind_of`, and `nearest(span, kind)` for the nearest ancestor of a kind.
- **`Requirement`** is what one property reads:
  - `kinds`: the kinds whose defects can hide a violation;
  - `observed`: the kinds that must appear for a positive observation;
  - `keys`: per-kind `KeyNeed::Key` or `AnyOf`.
- **`gaps(view, requirement, stopped)`** returns the closed `Gap` set. It holds the §6.3
  reasons plus the R-3 additions. An empty set is the only path to PASS.

## Tests

- `a_complete_trace_has_no_gap`
- `every_gap_reason_is_found`: orphan, missing root, dropped attributes (span and
  resource), dropped events, dropped links, not sampled, missing key, no observation,
  time inversion, span bound, conflict, malformed.
- `a_one_of_key_need_is_met_by_any_member`
- `defects_on_spans_the_property_does_not_read_do_not_count`

Ralph Loop green: 41 crate tests.
