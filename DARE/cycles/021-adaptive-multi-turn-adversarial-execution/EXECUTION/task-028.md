# task-028 — Implement hostile/refusal corpus tests

**Status:** DONE  
**Complexity:** MED

## Files changed

- `crates/dare-multi-turn-security/tests/hostile_refusal.rs` (new)
- `crates/dare-multi-turn-security/src/replay.rs`: static index check (below)

## Result

There is one test per DESIGN §4.5 bullet, and every case is refused before any turn runs:
- limits: depth 33, more than 256 nodes, a 128-path fan-out;
- any cycle, including a self-loop;
- 7 generator directives (`generate`, `mutate`, `template`, `paraphrase`, `seed`, `temperature`, `model`);
- oversized turns and documents;
- nesting at depth 40 (caught by our check) and at depth 1 000 (caught by serde_json's own recursion limit, with no stack overflow);
- duplicate node ids;
- reordered, duplicated or gapped transcripts, and a transcript carrying `verdict`;
- bidi and control characters in ids, not echoed back;
- URLs admitted as inert text, while credential-shaped values are refused;
- observation classes outside the enum, and the `UNCLASSIFIABLE` edge.

## Correction: DESIGN RF-10 honoured statically (task-015)

The Blueprint treated reordered, inserted and dropped replay turns as runtime strategy
faults (ERROR). DESIGN RF-10 says they are **refused**. Where this is detectable without
running anything, `ReplayAdapter::new` now refuses the transcript as
`TranscriptTampered` when its indices are not exactly 0, 1, 2, … (duplicate, gap or
reorder).

A wrong node at the right index, or a transcript truncated at the end, can only be seen
during the run. Those remain `STRATEGY_FAULT` → ERROR, which is never PASS. Test:
`replay::tests::reordered_duplicated_and_gapped_indices_are_refused_at_binding`.

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 3939 passed, 0 failed
- Audit: no dependency change
