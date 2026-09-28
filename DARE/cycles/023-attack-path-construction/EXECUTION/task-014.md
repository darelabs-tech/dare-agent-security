# task-014 — Implement bundle detection and input binding for tool, identity, memory, rag and mcp-auth

**Status:** DONE  
**Complexity:** MED

## Change

`crates/dare-attack-path/src/bundle.rs`:
- **Detection.** `BUNDLES` lists the ten result files. `detect` requires exactly one
  (`UnknownBundle`).
- **`load_bundle`:**
  - admits the directory;
  - reads the result and evidence files;
  - builds the evidence index;
  - records `RunTag`, the result and evidence SHA-256, the mode and the synthetic flag;
  - dispatches to the engine's binder.
- **Binders** recompute each pinned digest with the engine's public function:
  - **tool:** `scenario_digest` and `tool_surface_digest`;
  - **identity:** `digest`, `principal_set_digest`, and also `delegation_chain_digest` and
    `resource_context_digest` when present. Presence must agree with the result;
  - **memory and rag:** `digest` and `store_digest`;
  - **mcp-auth:** `canonical::digest`.

  Each binder also checks that every `result.evidence_ids` entry is in the evidence file.
- **Not done here.** `DuplicateRun` (the same result given twice) needs every bundle, so it
  is checked in `run.rs` (task-031).

## Tests (`tests/binding.rs`)

- Fixture bundles were produced by the real CLI in simulated mode for `TOOL-LAB-001`,
  `IDENTITY-LAB-001`, `MEMORY-LAB-001`, `RAG-LAB-001` and `MCP-AUTH-LAB-001`, with each
  shipped scenario copied to `inputs/scenario.json`.
- `every_fixture_bundle_binds`: every fixture bundle binds.
- `detection_needs_exactly_one_known_result`: an empty directory is refused, and so is a
  directory with two result files.
- `a_missing_scenario_is_refused_for_every_scenario_engine` (`MissingInput`).
- `an_edited_scenario_no_longer_binds`: each of the five engines, after a `title` edit,
  gives `DigestMismatch("scenario")`.
- `an_edited_pinned_sub_document_names_itself`: a false surface digest gives
  `"tool surface"`, and a false store digest gives `"memory store"`.

## Ralph Loop

Green: fmt, clippy `-D warnings`, tests.
