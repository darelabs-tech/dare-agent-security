# task-007 — Implement `source.rs`/`schema.rs` byte, depth, schema and hostile admission

**Status:** DONE  
**Complexity:** MED

## Files changed

- `crates/dare-multi-turn-security/src/source.rs` (new)
- `crates/dare-multi-turn-security/src/error.rs`: `ForbiddenField { name, category }` added; `name` is the matched constant, never the input
- `crates/dare-multi-turn-security/Cargo.toml`: `jsonschema` (workspace)

## Result

`admit(raw, kind)` enforces the frozen order: size ≤ 4 MiB, JSON, depth ≤ 32
(iterative, so it cannot overflow the stack), `schema_version == "1"`, the hostile
sweep, then the JSON Schema. `read_bounded` never reads past the ceiling and refuses
non-regular files.

The hostile sweep refuses five field-name groups:
- executable;
- credential;
- remote/model/provider (Cycle 022);
- **generation** (`generate`, `mutate`, `template`, `paraphrase`, `seed`, `temperature`, … — DESIGN RS-06);
- self-declared outcome.

It also refuses control, bidi and zero-width characters (newline and tab are allowed
in values) and credential-shaped values. The shape rules are the same as Cycle 016,
including the ≥ 16-char bearer rule, so prose about credentials stays writable. URLs
in content are admitted as inert text.

## Tests (`source::tests`)

- `a_well_formed_graph_is_admitted`
- `an_oversized_document_is_refused_before_parsing`
- `deep_nesting_is_refused` (32 refused, 31 admitted)
- `every_forbidden_field_group_is_refused_by_name` (includes case-insensitive `TEMPERATURE`)
- `bidi_and_control_text_is_refused_but_newlines_in_content_are_not`
- `credential_shaped_values_are_refused_but_prose_about_them_is_not`
- `urls_inside_content_are_inert_and_admitted`
- `a_wrong_version_is_refused_before_the_sweep`
- `read_bounded_refuses_directories_and_reads_files`

The per-bullet hostile corpus test file (`tests/hostile_refusal.rs`) is task-028.

## Ralph Loop

- Build/Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 266 suites, 3 796 passed, 0 failed (+15 over task-005)
- Audit: `cargo audit` exit 0 (305 crates). The first attempt hit a transient crates.io `503` on yank checks; the retry was clean. `jsonschema` was added from the workspace (already audited, no new crate in the lockfile).
