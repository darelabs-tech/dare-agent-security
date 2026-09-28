# task-008 — Implement `limits.rs` hard maxima and lower-only `Limits`

**Status:** DONE  
**Complexity:** LOW

## Result

The constants equal BLUEPRINT §4.2. `Limits::resolve` and `resolve_within` (a plan
against its authorization) return the ceiling for `None`, `BoundZero` for 0 and
`BoundRaised` above the ceiling.

## Tests

- `the_hard_maxima_match_the_approved_design`
- `absent_limits_resolve_to_the_hard_maxima`
- `every_limit_can_be_lowered_to_one`
- `raising_any_limit_is_refused_by_name` (all 5 fields)
- `a_zero_limit_is_refused_rather_than_disabling_the_bound` (all 5)
- `a_plan_may_only_lower_its_authorization`

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets -- -D warnings` green
- `cargo test -p dare-remote-validation`: 21 passed
- `cargo audit`: exit 0. `Cargo.lock` gained only the `dare-remote-validation` package entry. `zeroize` and `reqwest` were already locked, so no new external crate was added.
