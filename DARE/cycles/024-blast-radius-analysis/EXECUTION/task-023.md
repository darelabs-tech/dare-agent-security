# task-023 — Build the BLAST-RADIUS-LAB harness and BRL-001..BRL-010

**Status:** DONE  
**Complexity:** HIGH

## Harness (`crates/dare-agent-security-cli/tests/blast_radius_lab.rs`)

Each BRL scenario runs these steps:
1. **Build the graph.** The APL scenario named in `graph_from` is built through the real
   binary, using `common::lab_runner::build_apl` and `attack_paths`. Each APL graph is
   built once per test run.
2. **Render the scenario.** `compromise.json` is rendered with `${graph_id}` and
   `${run:N}` substituted, or `--seed-entry-points` is used when `lab.json` says so.
3. **Run twice.** `validate blast-radius` runs twice. The four files must be
   byte-identical, and all four must exist.
4. **Validate.** The document is parsed and passed through `validate_blast_radius`
   against the graph.
5. **Compare with `expected.json`.** The comparison covers:
   - the exit code and `truncated`;
   - per seed, `kind`, `refused_steps_min` and `absent` targets;
   - per target, class, exposure, route nodes (the uncontained route when exposed),
     control state, failed properties and frontier properties;
   - delta entries, matched by properties and count.

   Every mismatch is reported together with a readable description of the document.

The ignored test `dump` writes every APL graph, with its entry-point reach, to
`$DARE_BRL_DUMP`. It was used to read the graphs before the expectations were written.

## Scenarios

`tests/fixtures/blast-radius-lab/generate.py` writes all 20 scenarios. The expectations
were derived by hand from the graphs, following the continuity rule. They were written
before the first BRL run, and all 20 matched on that first run.

To show that the harness catches errors, two expectations were deliberately broken
(BRL-005 exposure and BRL-017 `refused_steps_min`). Both were reported, and both were
then restored.

The mapping to APL graphs follows BLUEPRINT §7.1, with the adaptations recorded in R-7.

Ralph Loop: fmt, clippy `-D warnings` and the lab (2 tests) are green.
