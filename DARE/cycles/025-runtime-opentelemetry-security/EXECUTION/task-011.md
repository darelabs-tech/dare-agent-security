# task-011 — Implement trace reconstruction

**Status:** DONE  
**Complexity:** MED

`src/trace.rs`, following BLUEPRINT §6.2:
- **Order.** Input is sorted by `(trace id, span id, file)` before anything else, so file
  and span order cannot change the result.
- **Duplicates.** A span repeated with identical content, ignoring the file it came from,
  is dropped and counted in `duplicates_removed`; the lowest file index is kept. The same
  span id with different content marks the trace `Conflict`, and the span is not refused.
- **Trees.** Each `Trace` keeps its spans sorted by `(start, span id)`, an id index,
  `roots`, `orphans` (parent not in the trace), `markers` (Conflict, Malformed for a
  parent cycle, TooDeep beyond 256) and `time_inversions`.
- **Helpers.**
  - `ancestors()` walks the parent chain, bounded by the trace size, so it terminates on
    a cycle.
  - `structurally_sound()` means a root exists and there are no marker and no orphan.

## Tests

- `a_tree_links_children_and_orders_by_start_then_id`
- `orphans_are_found_and_the_trace_is_not_sound`
- `identical_duplicates_across_files_are_removed_and_conflicts_are_marked`
- `cycles_depth_and_time_inversions_are_detected`: a 258-deep chain is marked TooDeep.
- `file_and_span_order_do_not_change_the_forest`

Ralph Loop green.
