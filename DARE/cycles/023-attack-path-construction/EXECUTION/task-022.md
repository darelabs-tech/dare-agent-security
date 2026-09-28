# task-022 — Implement the RAG projector (§6.4)

**Status:** DONE  
**Complexity:** MED

## Change

`project/rag.rs`. Documents become DATA nodes (sensitive for CONFIDENTIAL and RESTRICTED) with `BELONGS_TO_TENANT`. The collection is recorded in `original_kind` only. `DocumentContext` and `RetrievedChunk` give acting principal `READS` document (access guards) and document `TRANSFERS_TO` principal (content-trust guards). Untrusted documents, or documents from external ingestion or agent generation, are `RETRIEVED_DOCUMENT` entries, and sensitive documents are targets. `RagViolation.document_id` narrows a FAIL.

## Tests (`crates/dare-attack-path/tests/projection_tables.rs`)

`rag_rows`. Every projected edge is also checked by `all_have_evidence`:
- it carries evidence ids;
- an OBSERVED edge cites evidence records;
- a STATICALLY_PROVEN edge cites `input:<engine>:` ids only;
- it has a locator and an original kind.

The inputs are real engine output (the fixture bundles of tasks 014–016).

## Ralph Loop

Green: fmt, clippy `-D warnings`, `cargo test -p dare-attack-path` (60 tests).
