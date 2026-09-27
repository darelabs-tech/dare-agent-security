# task-004 — Implement `limits.rs` hard maxima and lower-only `Bounds`

**Status:** DONE  
**Complexity:** LOW

## Files changed

- `crates/dare-multi-turn-security/src/limits.rs`

## Result

Every constant of Blueprint §4.1 exists. A few are split into finer constants:
`MIN_COMPOSITE_FRAGMENTS`, `MAX_ACTION_ARGUMENT_BYTES` and `MAX_EXCERPT_CHARS`.
`Bounds::resolve` returns `EffectiveBounds`. A requested value is handled as follows:
- `None`: the hard maximum;
- `1..=max`: accepted;
- `0`: `BoundZero`;
- `> max`: `BoundRaised`.

## Tests

- `absent_bounds_resolve_to_the_hard_maxima`
- `a_bound_may_be_lowered_down_to_one`
- `raising_any_bound_is_refused` (all three bounds)
- `a_zero_bound_is_refused_rather_than_silently_disabling_the_run`
- `the_hard_maxima_match_the_approved_design` (literals 32 / 256 / 64 / 16 384 / 8 388 608, DESIGN §13 Q2)

## Ralph Loop

- Build: `cargo build --workspace` green
- Test: `cargo test --workspace`: 266 suites, 3 781 passed, 0 failed (baseline 3 767 + 14 new)
- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Audit: `cargo audit` clean. No external dependency was added; `Cargo.lock` gains only the new workspace member.
