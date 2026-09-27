# task-013 — Implement `Turn`/`ConversationState` with chained digest

**Status:** DONE  
**Complexity:** MED

## Files changed

- `crates/dare-multi-turn-security/src/conversation.rs` (new)

## Result

- The seed is `sha256("dare-multi-turn/v1|" + conversation_id)`.
- Each link is `sha256(prev | canonical(TurnBody))`.
- `push` accepts only the next index; anything else is a `StrategyFault`.
- `verify_chain` returns the index of the first altered turn.
- `TurnBody` stores the content digest and the template facts that invariants need (planted canary, claimed authority, approval disclosure, proposed action class), never the content.

## Tests (`conversation::tests`)

- `the_chain_starts_from_a_per_conversation_seed`
- `each_turn_links_to_the_previous_one`
- `an_out_of_order_index_is_a_strategy_fault`
- `tampering_is_detected_at_the_first_altered_turn` (edit, swap, drop)
- `raw_content_is_never_stored_only_its_digest`

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 0 failed (count in the commit message)
- Audit: no dependency change
