# task-021 — Implement the memory projector (§6.3)

**Status:** DONE  
**Complexity:** MED

## Change

`project/memory.rs`. Items become DATA nodes with their tenant, plus owner `WRITES` item (declared). `MemoryWriteObserved` gives writer `WRITES` item (OBSERVED). A recall gives requester `READS` item (access guards) and item `TRANSFERS_TO` requester (`CONTEXT_INTEGRITY`). An `ActionIntentObserved` with a tool gives SUT `CALLS` tool (R-4). Item `TRANSFERS_TO` tool is emitted only when a changed influence on tool selection or tool argument is in the **same** trial. Untrusted items, or items from user input, external content or tool output, are `MEMORY_WRITE` entries. A principal the context does not declare becomes IDENTITY.

## Tests (`crates/dare-attack-path/tests/projection_tables.rs`)

`memory_rows`. Every projected edge is also checked by `all_have_evidence`:
- it carries evidence ids;
- an OBSERVED edge cites evidence records;
- a STATICALLY_PROVEN edge cites `input:<engine>:` ids only;
- it has a locator and an original kind.

The inputs are real engine output (the fixture bundles of tasks 014–016).

## Ralph Loop

Green: fmt, clippy `-D warnings`, `cargo test -p dare-attack-path` (60 tests).
