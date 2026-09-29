# task-015 — Implement the remediation delta (RF-10, SHOULD)

**Status:** DONE  
**Complexity:** MED

- **Candidates:** `Decided(FAIL)` edges on the `uncontained_route` of an `Exposed`
  target. They are ordered by (smallest position on such a route, edge id) and capped at
  `MAX_DELTA_EDGES` (64).
- **Recount:** for each seed that has the edge on an exposed route, the uncontained
  search runs again with `excluded = edge`. The count is the number of that seed's
  exposed targets no longer reached.
- **Partial:** a truncated recount, or an exhausted shared budget, marks the entry
  `partial: true` and contributes 0. A target the recount did not settle is never
  counted.
- **Output order:** (-count, edge id). These are counts only, never a risk ranking.

## Tests (`tests/impact_delta.rs`)

- `the_delta_counts_targets_each_failed_edge_would_contain`: two FAIL edges, each
  containing one target.
- `the_delta_recounts_through_alternatives_and_orders_by_count`: a shared FAIL
  delegation contains 2 targets. A FAIL edge with an unguarded parallel edge contains 0.
- `an_exhausted_budget_marks_the_delta_partial`: this covers both a budget of 0 and a
  truncated recount.
- `the_delta_keeps_at_most_the_bound`: 70 failed edges give 64 entries in edge-id order.

Ralph Loop green.
