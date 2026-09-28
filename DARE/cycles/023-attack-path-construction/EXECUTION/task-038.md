# task-038 — Add the refusal corpus (§8.3)

**Status:** DONE  
**Complexity:** MED

## Change and tests (`crates/dare-agent-security-cli/tests/attack_paths_cli.rs`)

Every case goes through the real binary, through the helper `refused`. The helper asserts
four things: exit 3, no output directory created, stderr starting `refused:`, and, where a
value was planted, that the value is absent from stderr.

| §8.3 item | Test |
|---|---|
| Bundle and binding: unknown bundle, duplicate run, edited scenario (planted title), a 020 trace changed by one byte, a changed 019 manifest (planted id) | `refusal_corpus_bundles_and_binding` |
| Evidence: a record with a planted invalid verdict, a result citing a planted absent id | `refusal_corpus_evidence_and_files` |
| Files: a symlinked scenario, an `inputs/` directory linked outside the bundle, 16 MiB + 1 byte, JSON nested 65 deep (planted string) | `refusal_corpus_evidence_and_files` |
| System model: conflicting alias (planted local id), type clash, INFERRED declared edge without a rationale, an entity id containing `:` (planted) | `refusal_corpus_system_model_and_bounds` |
| Bounds: `--max-path-edges 13`, `--max-paths 10001`, `--max-paths-per-pair 65`, `--max-paths 0`, and an `--output-dir` containing `..` | `refusal_corpus_system_model_and_bounds` |
| Labels: `"]; click` and `-->` are escaped in `graph.mmd` and `graph.dot` | `hostile_labels_are_escaped_in_the_views_and_credential_shaped_ids_are_hashed` |

The library-level refusals (one test per `Refusal` and `ModelRefusal` variant path) are in
`crates/dare-attack-path/tests/{binding,model,graph}.rs` (tasks 012–017 and 029).

## Ralph Loop

Green: fmt, clippy `-D warnings`, tests (9 CLI tests).
