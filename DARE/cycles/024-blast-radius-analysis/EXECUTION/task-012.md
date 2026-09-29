# task-012 — Add the uncontained view, the excluded edge and the total budget

**Status:** DONE  
**Complexity:** MED

- **`View::Uncontained`** skips an edge exactly when `is_held(edge)`, meaning
  `edge_control(edge) == Decided(PASS)` (the Cycle 023 rule). It counts
  `held_edges_skipped`. Structural edges are `Exempt` in that rule, so they are never
  held.
- **`excluded`** skips one edge id in any view. The remediation delta uses it.
- **`budget`** is shared across searches. At 0, the search stops with `MaxStatesTotal`.

## Tests (`tests/reach.rs`)

- `the_uncontained_view_skips_only_held_edges`: one graph per guard state. PASS is
  skipped and counted. FAIL, INCONCLUSIVE, ERROR and no guard are crossed. The structural
  view skips nothing. A `BELONGS_TO_TENANT` edge stays traversable in the uncontained
  view.
- `an_excluded_edge_is_treated_as_held`.
- `depth_cut_and_state_bounds_are_reported` covers the shared budget.

Ralph Loop green.
