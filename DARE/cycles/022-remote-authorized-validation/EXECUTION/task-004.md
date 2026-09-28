# task-004 — Correct the supply-chain evidence bridge for INCONCLUSIVE/ERROR

**Status:** DONE (with one recorded extension; see below)  
**Complexity:** LOW

## Files changed

- `crates/dare-supply-chain-security/src/evidence_bridge.rs`

## Result

For INCONCLUSIVE and ERROR records, `observed.decision` and `observed.result` are now
`None` (DESIGN §4.8, APPROVAL decision 5). `observed.description` still says the
evidence was not observed, so no human-readable information is lost. The existing test
that pinned `Some(NotApplicable)` was updated: it now asserts `None` and that
`dare_security_evidence::validate` accepts the record.

## Extension found by the validator (recorded in REGRESSION.md)

Running `validate` on the corrected record found a **second** latent defect:
`hashes[].value` carried the engine's `sha256:` prefix, which the Cycle 001 validator
rejects ("hash digest must be lowercase hexadecimal"). The same fix already exists in
the identity, memory, rag and tool bridges (`strip`) and in the Cycle 021 bridge
(`bare_hash`). It was applied here as `bare_hex`.

Consequence: PASS and FAIL records now differ from before in `hashes[].value` only
(the prefix is removed). Without this change every record from this bridge, of any
verdict, fails the validation that DESIGN §4.8 step 2 requires, so the bridge would
return no record at all. No verdict, result artifact or coverage number changed.

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- `cargo test --workspace`: 281 suites, 3 957 passed, 0 failed (baseline 3 955 + 2 new tests)
- No dependency change, so no audit was required
