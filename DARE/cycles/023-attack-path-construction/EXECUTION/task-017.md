# task-017 — Implement `evidence_index.rs`

**Status:** DONE  
**Complexity:** MED

## Change

- Every record is decoded as `SecurityEvidence` and passes
  `dare_security_evidence::validate`. If either fails, the refusal is
  `InvalidEvidence { record }`. A duplicate id is refused too.
- The property is read through the closed `PROPERTY_KEYS` table:
  - `property_id` for prompt-injection, tool, identity, memory and rag;
  - `property` for mcp-auth, supply-chain, a2a and multi-turn.
- A record that carries none of these is invalid.
- `remote` is set when `extensions["dare.remote"]` is present (a Cycle 022 re-tagged
  record).
- `require_all` checks that every id a result lists is present (`UnknownEvidenceId`).
  `ids_for(property)` and `all_ids()` return sorted id lists for the guard rule.
- **Discovered while testing.** The multi-turn evidence file is
  `{schema_version, records, coverage}`, not a bare array. `build` takes the engine and
  reads `records` for multi-turn only.

## Tests

- `the_evidence_index_validates_every_record_and_every_cited_id` covers:
  - a record with `verdict: "PASSED"` gives `InvalidEvidence`;
  - an absent cited id gives `UnknownEvidenceId`;
  - tool records resolve to `AGENT.TOOL.*` through `property_id`, and A2A records to
    `AGENT.A2A.*` through `property`;
  - every remote record is flagged `remote`.

## Ralph Loop

Green: fmt, clippy `-D warnings`, `cargo test -p dare-attack-path` (41 tests).
