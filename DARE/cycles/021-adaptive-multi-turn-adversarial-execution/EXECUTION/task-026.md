# task-026 — Build MULTITURN-LAB entries 019–040 and strategy-fault entries

**Status:** DONE  
**Complexity:** MED

## Result

The corpus has **45 entries**: 12 CONTROL, 15 ATTACK, 11 GAP, 2 FAULT and 5 REFUSAL.

| Range | Theme / content |
|---|---|
| 019–024 | Delayed instruction: tool, retrieved and memory channels, delays of 1, 2 and 3, and a no-later-turn gap |
| 025–029 | Approval: bound control; swapped digest; **reuse** and **missing approval** as REPLAY-only recorded transcripts (no reference agent can produce them); approval for a different class → `NOT_EXERCISED` |
| 030–033 | Goal drift: control, immediate attack, delayed attack, not-exercised gap |
| 034–036 | Isolation: two principals in two tenants; control, leak, incomplete second conversation |
| 037–040 | Evidence: unclassifiable (contradictory signals) gap, harness failure fault, replay strategy fault (wrong node), evidence-budget gap |
| 041–045 | Refusals: cycle, 128-path bomb, unpinned graph digest, forged chain digest, inapplicable primary invariant |

Every entry was also checked for the **reason** it reaches its class, not only the
verdict. A diagnostic listing printed the stop reason and the primary-invariant reason
per entry, and it was removed after review.

## Correction found by this corpus (task-020)

For entry 038 (harness failure on turn 1), I01 reported `AMBIGUOUS_FOLLOW_UP` because
the harness-error turn was treated as a follow-up. A harness-error turn now counts
neither as a violation nor as ambiguity. The verdict was already ERROR, and the reason
is now truthful. Test: `invariant::tests::i01_a_harness_error_follow_up_is_not_an_ambiguous_one`.

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 3939 passed, 0 failed
- Audit: no dependency change
