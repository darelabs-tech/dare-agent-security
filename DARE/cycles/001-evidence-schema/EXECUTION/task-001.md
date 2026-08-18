# task-001 — Bootstrap Rust workspace and evidence crate

> Cycle: `001-evidence-schema`
> Status: DONE
> Depends on: none
> Complexity: LOW

## Objective

Create the minimal Rust workspace and isolated `dare-security-evidence` library crate required by the approved Blueprint.

## Scope

Create only the workspace and library foundation needed by later tasks.

Target structure:

```text
Cargo.toml
crates/
  dare-security-evidence/
    Cargo.toml
    src/
      lib.rs
```

## Required implementation

1. Create a root Cargo workspace.
2. Add `crates/dare-security-evidence` as a workspace member.
3. Configure package metadata consistently with Apache-2.0.
4. Keep the crate as a library only.
5. Add only dependencies justified by the approved Blueprint; avoid protocol/network/database dependencies.
6. Add a minimal crate-level documentation comment describing the evidence kernel boundary.

## Architectural constraints

- Do not create CLI, MCP, AuthZEN, COAZ, graph, network, database or SaaS modules.
- Do not import proprietary DARE/NEXORA crates.
- The evidence crate must remain independently reusable.
- Do not add TODO/FIXME/stub production behavior.

## Files expected to change

```text
Cargo.toml
crates/dare-security-evidence/Cargo.toml
crates/dare-security-evidence/src/lib.rs
Cargo.lock
```

## Validation gates

Run:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Done when

- the workspace is valid;
- the evidence crate builds as a standalone library member;
- all Rust gates pass;
- no future-domain dependency has been introduced.

## Execution result

- Status: DONE
- Files: `Cargo.toml`, `Cargo.lock`, `.gitignore`, `crates/dare-security-evidence/Cargo.toml`, `crates/dare-security-evidence/src/lib.rs`
- Gates: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` — pass
- Notes: library-only workspace member; Apache-2.0 metadata; no protocol/network/database dependencies introduced.
