# task-042 — Read a v2 graph in `dare-product` (RF-16, BQ-3 (a))

**Status:** DONE  
**Complexity:** MED

## Change (`crates/dare-product/src/assess.rs`)

- `ProductFixture` gains the optional field `attack_graph_v2: <path>`. It is skipped when
  it serializes and is absent, so a fixture without it reads and writes as before.
- `read_attack_graph_v2` refuses, with a configuration error that never echoes content:
  - an empty or absolute path, or one with `..`: the path must be relative and inside the
    target;
  - a link, a directory or a missing file;
  - a file over 16 MiB;
  - a file that is not an `AttackGraphV2` (`deny_unknown_fields`);
  - a graph that fails `dare_attack_graph::v2::validate_graph_v2`;
  - a fixture that also carries `attack_graph_facts`.
- A valid graph is written unchanged as the run's `attack-graph.json`.
- `summarize_graph` recognises the v2 schema id. It reports node, edge, entry-point and
  target counts, says that paths and control states are in `attack-paths.json`, and ends
  "analysis only (not executed)".
- `dare-product` does not depend on `dare-attack-path` and gains no dependency.

## Tests (`crates/dare-product/tests/attack_graph_v2.rs`)

| Test | Proves |
|---|---|
| `without_the_field_the_attack_graph_artifact_is_unchanged` | SHA-256 of `attack-graph.json` for a fixture without a graph and for a v1 facts fixture equals the digests recorded on `a3d6c06` (before this change, taken with the change stashed) |
| `a_v2_graph_is_validated_and_written_as_the_run_graph` | the run's graph equals the file (a graph produced by `validate attack-paths` over the identity and RAG bundles); the summary names it as v2 |
| `a_doctored_v2_graph_is_refused_without_echoing_it` | an edge to an unknown node and an unknown field are refused, and the planted text is not echoed |
| `the_path_is_confined_to_the_target_and_exclusive_with_v1_facts` | `..`, absolute, empty, a link, a missing file, and both fields at once are refused |
| `the_product_does_not_depend_on_the_attack_path_engine` | `Cargo.toml` names no `dare-attack-path` (also covered by `dare-attack-path/tests/manifest.rs`) |

## Ralph Loop

Green: fmt, clippy `-D warnings --all-targets`, `cargo test -p dare-product` (85 tests).
No dependency changed: `sha2` is already a normal dependency of `dare-product`.
