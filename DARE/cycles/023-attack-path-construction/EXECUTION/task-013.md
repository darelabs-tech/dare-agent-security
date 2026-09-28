# task-013 — Implement `load.rs` scenario loaders over the engines' public validators

**Status:** DONE  
**Complexity:** MED

## Change

`crates/dare-attack-path/src/load.rs` repeats the private `load_scenario` of each engine
CLI, using only `pub` engine items.

- **tool, identity, memory, rag, mcp-auth** (`schema_loader!`), in this order:
  1. `enforce_document_size`;
  2. `validate_scenario_document`;
  3. the typed decode;
  4. `validate()`, for identity, memory, rag and mcp-auth only. The tool CLI does not
     call it.
- **supply-chain and a2a** (`hostile_loader!`), in this order:
  1. `enforce_document_size`;
  2. `assert_no_hostile_fields`;
  3. the typed decode;
  4. `validate()`.
- **Errors.** Engine errors become positional refusals. The engine's own message is
  dropped, because it can quote the input.
- **File access.** The file is read through `AdmittedDir`, so the symlink, escape, size
  and depth rules apply before the engine sees the bytes.

## Tests

- `the_loaders_match_the_engines_on_every_shipped_scenario` (`tests/binding.rs`) runs over
  every scenario file under the five engines' shipped scenario directories: 127 files (20 tool, 24 identity, 24 memory, 24 rag, 35 mcp-auth, counted by directory listing; the commit message of `55b93fd` gives a wrong breakdown with the right total).
  For each file:
  - it recomputes the engine CLI's own acceptance sequence independently;
  - it asserts that this crate accepts exactly the same files;
  - for an accepted file, it asserts that the digest this crate computes equals the
    engine's `bind(&scenario).scenario_digest`.

  Engine-invalid fixtures, such as `identity-lab-018`, are refused by both sides.

## Ralph Loop

Green: fmt, clippy `-D warnings`, `cargo test -p dare-attack-path`.
