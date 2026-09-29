# task-020 — Implement `summary.md`

**Status:** DONE  
**Complexity:** LOW

`summary::summary(graph, doc)` writes these sections:
- the title, graph id, scenario id, seeds (with skipped and omitted counts), the bounds
  and the totals line;
- a seeds table, with counts per exposure and truncation;
- exposed targets by class;
- per seed, up to `TARGETS_PER_SEED` (50) targets, then "N more in blast-radius.json";
- the frontier table and the remediation-delta table ("a count, not a ranking");
- the search record: states, refused steps, depth cut, truncation and `stopped_by`;
- **"What this does not claim"**, with the four statements of BLUEPRINT §5.4 as
  `NOT_CLAIMED`.

Every display name and the scenario id are escaped for table cells (`|`, `<`, `>`,
backticks, line breaks) and capped at 80 characters. There is no time stamp.

## Tests (`tests/views.rs`)

- `the_summary_counts_routes_and_ends_with_what_it_does_not_claim`: the last four lines
  are the statements, a pipe cannot break a cell, and there is no time stamp.
- `the_summary_lists_at_most_fifty_targets_per_seed`: 57 targets give 50 rows and
  "7 more".
- `every_summary_ends_with_the_four_statements_even_with_no_reach`.

Ralph Loop green (fmt, clippy `-D warnings`, 68 crate tests).
