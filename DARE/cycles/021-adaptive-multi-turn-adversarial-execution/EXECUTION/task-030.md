# task-030 — Add `multi-turn-security-baseline-2026` profile and denominator row

**Status:** DONE  
**Complexity:** LOW

## Files changed

- `profiles/multi-turn-security-baseline-2026.json` (new): 7 properties
  - REQUIRED: I01, I03, I04, I06
  - CONDITIONAL: I02, I05, I07
- `crates/dare-coverage/src/profile.rs`: `MULTI_TURN_SECURITY_PROFILE_JSON`, `multi_turn_security_profile()`, `resolve_profile` arm
- `crates/dare-coverage/src/lib.rs`: exports
- `crates/dare-coverage/tests/multi_turn_profile.rs` (new)

## Deviation recorded

The Blueprint suggested adding a row to Cycle 020's `no_earlier_profile_denominator_moved`.
That test was **left untouched**. Instead, the new `multi_turn_profile.rs` repeats the
check with literals for all **ten** earlier profiles, including Cycle 020's
`agentic-a2a-security-2026 = 12`, and pins the new profile at 7 in
`the_profile_matches_the_approval_exactly`. The guarantee is the same, and no earlier
cycle's test file changed.

## Tests (`multi_turn_profile.rs`)

- `the_profile_matches_the_approval_exactly`
- `the_profile_validates_and_every_property_exists_in_the_v2_registry`
- `the_profile_resolves_by_name`
- `no_earlier_profile_denominator_moved` (10 literals)
- `the_identity_and_memory_profiles_do_not_select_the_cycle_021_additions`
- `no_earlier_profile_selects_any_cycle_021_property`

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 3917 passed, 0 failed
- Audit: no dependency change
