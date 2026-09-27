# task-029 — Add the seven registry entries and property tests

**Status:** DONE  
**Complexity:** MED

## Files changed

- `schemas/coverage/v2/registry.json`: 7 entries appended (58 → 65); the diff is additions only
- `crates/dare-coverage/tests/multi_turn_properties.rs` (new)
- Cycle 015/016 tests adjusted, per the Product Owner decision (below):
  - `crates/dare-coverage/tests/identity_security_properties.rs`
  - `crates/dare-coverage/tests/identity_security_profile.rs`
  - `crates/dare-coverage/tests/memory_security_properties.rs`
  - `crates/dare-coverage/tests/memory_security_profile.rs`
- `DARE/cycles/021-.../APPROVAL.md`: the decision is recorded

## Review stop and decision

Adding `AGENT.IDENTITY.CLAIMED_AUTHORITY_BOUNDARY` and
`AGENT.MEMORY.CONVERSATION_ISOLATION` broke **7 test functions in 4 files**. The
estimate given to the Product Owner was 5 tests. Those tests froze family size at six,
and required that the family's profile select every family member.

The approval forbids changing earlier denominators, so execution stopped and the
Product Owner was asked. The decision was to **adjust the tests**:
- Each file declares `CYCLE_021_ADDITIONS` with the named ID.
- Every family-size and "every family member is selected" check now excludes exactly
  those names, and still pins the cycle's own six.
- A new test per family, `the_only_later_{identity,memory}_family_members_are_the_named_cycle_021_additions`,
  proves that the family equals the cycle's six plus the named additions, so no
  anonymous property can enter.

No profile denominator changed.

## Result

Every entry uses the existing shape and the `agent_present` + `stateful_agent_present`
predicates (the latter existed with no user until now). The `reference` strings are
byte-identical to existing registry entries.

## Tests (`multi_turn_properties.rs`)

- `exactly_the_seven_approved_properties_were_added` (count 58 + 7, appended in order)
- `each_property_carries_its_family_category_and_reference`
- `no_multi_turn_namespace_was_introduced`
- `every_new_property_is_gated_by_the_existing_stateful_agent_predicate`
- `a_stateful_agent_makes_them_applicable_and_a_stateless_one_does_not`
- `the_v1_registry_gained_nothing`
- `every_new_property_is_mapped_in_the_cycle_021_standards_record`

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 3917 passed, 0 failed
- Audit: no dependency change
