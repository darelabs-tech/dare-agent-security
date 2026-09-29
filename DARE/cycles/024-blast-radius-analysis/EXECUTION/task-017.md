# task-017 — Implement `analyze` end to end, with the determinism test

**Status:** DONE  
**Complexity:** MED

`src/analyze.rs`:

- **`analyze(graph, Seeding::{Scenario(path), EntryPoints}, &Options)`** checks the
  options (0 or above the maximum is refused), then loads the graph and resolves the
  seeds.
- **`load_graph`/`graph_from_value`** admit the graph at 16 MiB and 64 levels, then
  check the v2 graph schema, serde and `validate_graph_v2`. Any failure is
  `InvalidGraph`.
- **`analyze_graph`** does the rest:
  - bounds are the default lowered by the options, then by the scenario;
  - seeds are sorted and deduplicated;
  - it runs both views per seed from a shared 5M budget, then classification, impact,
    totals, frontier and the delta;
  - `truncated`/`stopped_by` follow R-4;
  - the document is checked with `validate_blast_radius` before it is returned.
- The library writes no file. `lib.rs` re-exports `analyze`, `Analysis`, `Options`,
  `Seeding` and `validate_blast_radius`.

## Tests (`tests/analyze.rs`, 5)

- A scenario file seeds a credential leak, giving vault `EXPOSED` and ledger
  `CONTAINED`. It carries a `scenario_digest`, and the directory is unchanged.
- Entry-point mode gives the injection and takeover seeds, with no digest.
- Options lower the bounds. 13 / 1 000 001 are refused `BoundAboveMaximum`, and 0 is
  refused `BoundZero`.
- `InvalidGraph` for unsorted edges, a non-graph and an unsealing graph id.
- `ten_shuffles_give_identical_documents` (O-06, R-5).

Ralph Loop: fmt, clippy `-D warnings` and 51 crate tests green.
