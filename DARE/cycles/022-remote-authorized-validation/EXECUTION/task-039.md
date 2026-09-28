# task-039 — Add compatibility tests

**Status:** DONE  
**Complexity:** MED

## Result (`crates/dare-remote-validation/tests/compatibility.rs`)

Every digest was computed from `main @ b6f14b9` and verified equal to the current tree
(`git diff --quiet b6f14b9 -- profiles schemas/coverage/v2/registry.json crates/dare-adversarial crates/dare-continuous`).

- `every_engine_no_network_test_is_unchanged`: the no-network test region of 7 engine crates, pinned by digest. For prompt-injection, rag and tool that is the whole `tests/offline_confidential.rs`; for a2a, multi-turn, mcp-auth and supply-chain it is the last `#[cfg(test)]` module of `lib.rs`. Each region must still name `"reqwest"`. Identity and memory have no manifest-level network test to pin.
- `the_registry_and_every_profile_are_byte_for_byte_unchanged`: the coverage registry plus 11 profiles, and no profile added.
- `dare_adversarial_still_refuses_non_local_execution`: `roe.rs` is pinned by digest, and the `local_only` refusal is present.
- `nothing_continuous_or_adversarial_depends_on_this_crate`: continuous, adversarial, coverage and evidence.
- `no_engine_crate_depends_on_this_crate`: all 9 engines.
- `the_cli_never_enables_the_lab_feature`: one normal dependency line, with no `features` and no dev-dependency, and `lab` is not a default.
- `embedded_assets_live_in_docker_copied_dirs`: every `include_str!` in the remote crate, the 018 crate and the CLI.
- `the_ci_trigger_is_still_pull_request_opened_only`: the trigger is unchanged, both `remote-validation-2026` and `multi-turn-security-2026` exist.

## Ralph Loop

- `cargo clippy -p dare-remote-validation --all-targets --features lab -- -D warnings` green
- `cargo test -p dare-remote-validation --test compatibility`: 8 passed
