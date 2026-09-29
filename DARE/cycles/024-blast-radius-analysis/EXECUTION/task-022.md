# task-022 — Add the CLI refusal corpus, hostile labels and double-run test

**Status:** DONE  
**Complexity:** MED

Every refusal below exits 3, writes nothing (the output directory is never created) and
starts with `refused:`. The planted `CANARY-*` values never appear in stderr.

| Refusal | Case |
|---|---|
| `Unreadable` | missing graph file |
| `Symlink` | the graph is a symbolic link |
| `TooLarge` | 16 MiB + 1 byte |
| `TooDeep` | 70 nested arrays |
| `InvalidGraph` | a non-graph with a canary field; a sealed graph with an edited display name (canary) |
| `NoSeeds` | the MCP bundle's graph (no entry point) |
| `UnsafeOutputDir` | `a/../../escape` |
| `InvalidDocument` | a scenario with an unknown key (canary); no seed; `max_depth: 13` |
| `GraphMismatch` | another graph id |
| `UnknownSeed` | an unknown `node_id` (canary); an unknown `entity_id` (canary) |
| `SeedKindMismatch` | `CONTENT_INJECTION` on a HUMAN |
| `DuplicateSeed` | the same seed twice |
| `AmbiguousSeed` | a resealed graph where `shared` names an AGENT and a HUMAN |
| `BoundAboveMaximum` | `--max-depth 13`, `--max-states 1000001` |
| `BoundZero` | `--max-depth 0` |
| `UnsafeArtifact` | a resealed graph whose reachable target id carries `ghp_…`. Nothing is written, the message says "credential-shaped value", and `ghp_` is not echoed |

- `hostile_display_names_are_escaped_in_the_views`: the display name `"]; click n0 call
  x() <script>` renders escaped in both views.
- `two_runs_give_byte_identical_files`: all four files.
- `--help` offers exactly the §5.1 flags (task-021's test).

Ralph Loop:
- fmt clean;
- clippy `--workspace --all-targets -D warnings` clean;
- `cargo test --workspace` green (counts in task-028);
- no dependency was added beyond the in-workspace path, so there is nothing to audit.
