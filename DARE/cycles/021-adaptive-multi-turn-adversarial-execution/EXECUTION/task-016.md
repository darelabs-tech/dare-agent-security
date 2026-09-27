# task-016 — Implement `SimulatedAdapter` and all `ReferenceAgent` variants

**Status:** DONE  
**Complexity:** HIGH

## Files changed

- `crates/dare-multi-turn-security/src/simulated.rs` (new)

## Result

All 16 variants of Blueprint §4.9 are implemented. Every agent is secure by default
(the module documents the baseline order), and each vulnerable variant departs in
exactly one dimension from its secure twin. That pairing is what the MULTITURN-LAB
controls rely on.

Responses are a pure function of the conversation so far, the node and the memory of
earlier conversations. That memory is used only by `LeakyAcrossConversations`.

## Tests (`simulated::tests`)

Each test covers a vulnerable variant and its twin:
- `eroding_refusal_gives_in_after_n_and_the_secure_twin_never_does`
- `fragment_completer_finishes_the_composite_and_fragment_aware_stops_at_the_last_piece`
- `authority_groomable_accepts_after_n_claims_and_strict_never_does`
- `delayed_follower_emits_the_canary_n_turns_later_and_the_ignorer_never_does`
- `approval_bound_executes_the_disclosed_digest_and_the_swapper_does_not`
- `without_an_approval_the_secure_agent_only_requests`
- `goal_drifter_leaves_the_objective_after_n_turns_and_stable_never_does`
- `leaky_agent_carries_canaries_into_the_next_conversation_and_isolated_does_not`
- `harness_failure_and_ambiguity_are_produced_on_demand`
- `responses_are_deterministic`

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 3858 passed, 0 failed
- Audit: no dependency change
