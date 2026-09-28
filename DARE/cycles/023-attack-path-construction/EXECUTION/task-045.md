# task-045 — Write the EN/PT attack-path pages and the system-model reference

**Status:** DONE  
**Complexity:** LOW

## Pages

| Page | Content |
|---|---|
| `book/en/src/concepts/attack-paths.md` | Covers the following: <ul><li>the question the command answers;</li><li>inputs, with the `inputs/` each engine needs, the binding and refusals, and the bounds table;</li><li>how the graph is built (projection, guards and ENTITY narrowing, alias-only identity, designation);</li><li>feasible versus `DISCONTINUOUS`;</li><li>the three control states, the BQ-1 structural exemption and the declared-edge rule;</li><li>chokepoints, outputs and exit codes;</li><li>**what a result does not claim**;</li><li>product integration (`attack_graph_v2`).</li></ul> |
| `book/pt/src/concepts/attack-paths.md` | the same page in Portuguese |
| `book/en/src/reference/attack-path-system-model.md` | Covers the following: <ul><li>why identity needs a model;</li><li>the run-scoped and entity id forms;</li><li>every field, with its pattern and limit;</li><li>entities, aliases (with or without `run`), designations with `exclude`;</li><li>trust boundaries and declared edges (unguarded, so at best `CONTROL_UNDECIDED`, and still checked for continuity);</li><li>every refusal with its cause;</li><li>`aliases_unused`;</li><li>a worked example (APL-001).</li></ul> |

Also changed:
- EN `commands/validate.md` has a `validate attack-paths` section.
- EN `reference/exit-codes.md` has its table.
- EN `concepts/attack-graph.md` points from the Cycle 008 graph to the new page.
- Both `SUMMARY.md` files link the concept page, and the EN one also links the reference.

Both statements the DONE criterion requires are made in EN and PT:
- `CONTROLS_HELD` does not mean "secure" / não significa "seguro";
- paths longer than `--max-path-edges` are not covered / não são cobertos.

## Ralph Loop

`mdbook build book/en` and `mdbook build book/pt` are green (mdBook 0.4, as in the
`docs-build` job). No code changed.
