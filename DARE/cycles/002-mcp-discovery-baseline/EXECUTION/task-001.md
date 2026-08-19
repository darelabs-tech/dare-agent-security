# task-001 — Bootstrap discovery and CLI crates

> Status: DONE
> Depends on: Cycle 001
> Complexity: MEDIUM

## Objective
Create the Rust workspace members that will host passive MCP discovery and the CLI.

## Required implementation
- add `crates/dare-mcp-discovery` library;
- add `crates/dare-agent-security-cli` binary;
- discovery may depend on `dare-security-evidence`;
- CLI depends on discovery;
- evidence must not depend on discovery/CLI;
- add only dependencies justified by the Blueprint.

## Invariants
- no protocol logic in the evidence crate;
- no database/SaaS dependencies;
- no proprietary code imports;
- no stub production behavior.

## Expected files
`Cargo.toml`, `Cargo.lock`, new crate manifests and minimal `src/lib.rs` / `src/main.rs`.

## Gates
`cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.

## DONE when
Workspace builds, dependency direction is correct, and all gates pass.

---

## Execution result

- **Status:** DONE
- **Date:** 2026-08-18
- **Files:** `Cargo.toml`, `Cargo.lock`, `crates/dare-mcp-discovery/{Cargo.toml,src/lib.rs}`, `crates/dare-agent-security-cli/{Cargo.toml,src/main.rs}`
- **Dependency direction:** `dare-agent-security` → `dare-mcp-discovery` → `dare-security-evidence`
- **Gates:** `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` passed
- **Tests:** discovery crate identity + inward evidence dependency + evidence manifest isolation; CLI binary depends on discovery
