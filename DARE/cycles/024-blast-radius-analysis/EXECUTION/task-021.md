# task-021 — Add the `validate blast-radius` CLI subcommand

**Status:** DONE  
**Complexity:** MED

`crates/dare-agent-security-cli/src/blast_radius.rs` is registered in `args.rs`
(`ValidateSubcommand::BlastRadius`, with `after_help`), `main.rs` and `lib.rs`. The CLI
`Cargo.toml` gains `dare-blast-radius` (path).

- **Flags (§5.1):**
  - `--graph`;
  - `--compromise` or `--seed-entry-points`: a clap `ArgGroup`, required and exclusive;
  - `--output-dir`, checked by `ci_output::validate_output_dir`;
  - `--max-depth` (default 8) and `--max-states` (default 1 000 000), which lower the
    scenario's values;
  - `--json`.
- **Before any write:**
  - `analyze` (the document already passed `validate_blast_radius`);
  - `validate::check_schema`, new in the library: the document against its embedded
    JSON schema;
  - all four files rendered (`blast-radius.json`, `summary.md`, `graph.mmd`,
    `graph.dot`);
  - each file swept with `dare_attack_graph::v2::sweep::is_sensitive`, where a hit is
    `Refusal::UnsafeArtifact` (exit 3).
- **Exit codes:**
  - 0: nothing `EXPOSED` and nothing truncated;
  - 2: `EXPOSED` or truncated (BQ-5);
  - 3: refusal;
  - 1: internal error.
- **Stdout line:** `<n> seeds: <e> EXPOSED, <c> CONTAINED, <u> CONTAINMENT_UNKNOWN
  targets[, truncated]`.

## Tests (`tests/blast_radius_cli.rs`)

The graphs come from `validate attack-paths` over Cycle 023 bundles.

| Test | Proves |
|---|---|
| `help_names_every_flag_and_offers_nothing_else` | exactly the §5.1 flags, the exit codes and the not-claimed wording; no widening flag is accepted |
| `seeding_is_one_of_a_scenario_or_the_entry_points` | neither, or both, exits 3 and writes nothing |
| `exit_0_writes_four_files_when_nothing_is_exposed` | A2A: four files; `--json` prints the document; the stdout line |
| `exit_2_when_a_target_is_exposed_or_a_search_is_truncated` | identity: `PRIVILEGED_CREDENTIAL` `EXPOSED`; `--max-states 1` gives `, truncated` |
| `exit_1_on_an_internal_write_failure` | a directory in place of `blast-radius.json` |
| `a_scenario_names_its_seeds_and_lowers_the_bounds` | the scenario's `max_depth: 4` lowers the default 8; `scenario_digest` |

Ralph Loop: see task-022.
