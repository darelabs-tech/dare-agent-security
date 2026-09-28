# task-009 — Implement `error.rs`, `ids.rs` and `canonical.rs`

**Status:** DONE  
**Complexity:** LOW

## Result

**Errors.** `RemoteError::is_refusal` is true for exactly 7 variants:
- the 6 pre-egress refusals of BLUEPRINT §4.1;
- `ForbiddenCharacter`/`InvalidIdentifier`, which the Blueprint folds into `Refused`.

**`CredentialMissing`.** It is an `AuthorizationRefusal` variant (rule 16), not a top-level
variant, so every authorization refusal has one path.

**Identifiers.** There are two grammars (§ `ids.rs` docs): document ids, and scenario
references in each engine's own spelling.

**Canonical form.** Canonical JSON and SHA-256 use the same construction as Cycle 021.

**Vocabulary.** `outcome.rs` defines `TransportOutcome` and `StopReason`, so every
module shares one vocabulary. The overlay itself is task-021.

## Tests

- `refusals_are_exactly_the_pre_egress_variants`
- `no_error_message_carries_input_values`
- `every_authorization_refusal_has_its_own_message`
- `io_errors_keep_only_their_kind`
- 5 identifier tests, including code-point reporting and serde `try_from`
- 2 canonical tests

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets -- -D warnings` green
- `cargo test -p dare-remote-validation`: 21 passed
- `cargo audit`: exit 0. `Cargo.lock` gained only the `dare-remote-validation` package entry. `zeroize` and `reqwest` were already locked, so no new external crate was added.
