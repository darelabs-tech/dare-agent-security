# task-027 — Implement the multi-turn projector (§6.8)

**Status:** DONE  
**Complexity:** MED

## Change

`project/multi_turn.rs`. There is one channel per role in {USER, TOOL, RETRIEVED, MEMORY}. APPROVAL is counted, not an entry. The seven 021 invariants guard every channel edge. Each `DelegatedFinding` whose property is in `MULTI_TURN_DELEGATED` adds an ENTITY-scope FAIL on its turn's channel, resolved through the transcript. Executed actions give `CALLS` (guarded by `CROSS_TURN_CONTINUITY`), and requested ones give `CAN_INVOKE`.

## Tests (`crates/dare-attack-path/tests/projection_tables.rs`)

`multi_turn_rows`. Every projected edge is also checked by `all_have_evidence`:
- it carries evidence ids;
- an OBSERVED edge cites evidence records;
- a STATICALLY_PROVEN edge cites `input:<engine>:` ids only;
- it has a locator and an original kind.

The inputs are real engine output (the fixture bundles of tasks 014–016).

## Ralph Loop

Green: fmt, clippy `-D warnings`, `cargo test -p dare-attack-path` (60 tests).
