# task-005 — Implement `ids.rs` validated identifier newtypes

**Status:** DONE  
**Complexity:** LOW

## Files changed

- `crates/dare-multi-turn-security/src/ids.rs`

## Result

Seven newtypes are defined: `NodeId`, `ClassId`, `ConversationId`, `CanaryId`,
`ApprovalId`, `ActionId` and `ScenarioId`. Each is built by one macro and validated
by `validate_identifier` against `^[a-z0-9][a-z0-9._-]{0,63}$`. Serde goes through
`try_from = "String"`, so an invalid id cannot be deserialized.

Forbidden characters are reported by codepoint and field only, never by value:
- C0 and C1 controls;
- zero-width characters U+200B–U+200F;
- bidi controls U+202A–U+202E and U+2066–U+2069;
- BOM U+FEFF.

## Tests

- `the_grammar_accepts_ordinary_identifiers` (includes a 64-char id)
- `the_grammar_rejects_everything_else_without_echoing_it` (empty, uppercase, leading `-`/`.`, space, `/`, non-ASCII, 65 chars)
- `bidi_zero_width_and_control_characters_are_named_by_codepoint`
- `deserialization_cannot_construct_an_invalid_identifier`

## Ralph Loop

- Build: `cargo build --workspace` green
- Test: `cargo test --workspace`: 266 suites, 3 781 passed, 0 failed (baseline 3 767 + 14 new)
- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Audit: `cargo audit` clean. No external dependency was added; `Cargo.lock` gains only the new workspace member.
