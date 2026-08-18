# task-001 — Bootstrap discovery and CLI crates

## Goal
Create the Rust package boundaries required by Cycle 002 without changing the Cycle 001 evidence contract.

## Required implementation
- Add `crates/dare-mcp-discovery` as a library workspace member.
- Add `crates/dare-agent-security-cli` as a binary workspace member with binary name `dare-agent-security`.
- Discovery may depend on `dare-security-evidence`; CLI may depend on discovery.
- Evidence MUST NOT depend on either new crate.
- Add async/runtime/CLI dependencies only where justified by the Blueprint.
- Preserve Apache-2.0 metadata.

## Files expected
`Cargo.toml`, `Cargo.lock`, both new crate `Cargo.toml` files and minimal `src/lib.rs` / `src/main.rs`.

## Tests / gates
```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo tree -p dare-security-evidence
```

## DONE
Workspace builds, the binary starts/help-renders, and dependency inspection proves the evidence crate has no MCP/CLI dependency.