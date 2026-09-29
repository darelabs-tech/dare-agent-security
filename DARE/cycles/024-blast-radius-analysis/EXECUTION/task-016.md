# task-016 — Implement `validate_blast_radius` (invariants 1–9)

**Status:** DONE  
**Complexity:** MED

`src/validate.rs` implements `validate_blast_radius(graph, doc)`. Every failure is
`BlastError::Internal("invariant N: …")`, which names no input content.

| Inv. | Checked |
|---|---|
| 1 | `graph_id`, schema id and version, and the recorded bounds are within their maxima |
| 2 | Each seed node exists, and its kind fits and its tenant matches. Every route is a walk over known ids, of length 1..=`max_depth`, from the seed to its target. Delta edges exist |
| 3 | Each route replays `Authority::step` from the seed's initial authority with no refused step |
| 4 | `control_state`, `failed_guards` and `undecided_edges` equal `path_control` |
| 5 | No uncontained route crosses a `Decided(PASS)` edge |
| 6 | The exposure/route/truncation table, and `Contained` has a non-empty frontier |
| 7 | The frontier is exactly the held edges of the structural route for `Contained`, and empty otherwise |
| 8 | Totals and the top-level frontier are recomputed. Per view, `targets_by_class`, `trust_boundaries_crossed` and `privileged_credentials_acquired` are recomputed, and `tenants_reached` is checked as a superset (R-4). `truncated`/`stopped_by` are checked (R-4). Every delta edge `Decided(FAIL)` and carries its FAIL properties. The structural view skips no held edge |
| 9 | Seeds, targets, frontiers, impact lists, delta order (-count, id) and `stopped_by` are sorted and unique |

## Tests (`tests/validate.rs`, 10)

- `a_document_the_engine_produces_passes`, over the shared `support::lab` graph. That
  graph has exposed, contained and cross-tenant targets, a privileged key, a boundary,
  FAIL and PASS edges, and a foreign-principal access.
- One test per invariant, `invariant_1_…` to `invariant_9_…`. Each doctors the document
  and asserts that invariant's refusal by name. There are 26 doctored documents in all.

Ralph Loop green.
