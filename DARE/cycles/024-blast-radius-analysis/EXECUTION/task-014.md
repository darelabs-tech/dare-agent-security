# task-014 — Implement `impact.rs`, the top-level frontier and totals

**Status:** DONE  
**Complexity:** MED

- **`impact`** computes one view's facts over the targets that view reaches:
  - `targets_by_class`;
  - `tenants_reached`: the tenants of every reached node, not only targets, other than
    the seed's tenant;
  - `trust_boundaries_crossed`: over the witness-walk edges;
  - `privileged_credentials_acquired`: the privileged CREDENTIAL nodes that are the
    principal at some state of a witness walk. This uses `Walk::authorities`, so
    nothing is replayed.
- **`view_impact`**: the structural view counts every reached target; the uncontained
  view counts only `Exposed` targets (§6.6).
- **`totals`** counts `(seed, target)` pairs per exposure, with `exposed_by_class`.
- **`frontier`** lists every held edge in any frontier, with:
  - its sorted guard properties;
  - its evidence ids;
  - `contained_targets`, the number of pairs that list it.

## Tests (`tests/impact_delta.rs`)

- `impact_counts_follow_each_view`: a hand-built graph with a privileged key, a
  cross-tenant DATA node behind a boundary-crossing edge, and a held edge. Each of
  `tenants_reached`, `trust_boundaries_crossed` and `privileged_credentials_acquired`
  is asserted in both views.
- `totals_and_frontier_count_seed_target_pairs`: two seeds (with and without a tenant).
  - Totals are `(5, 2, 0)`, one `CROSS_TENANT_RESOURCE`.
  - The frontier edge has `contained_targets = 2`.
  - Both match the manual count.

Ralph Loop green.
