# task-007 — Create the `dare-remote-validation` crate skeleton and network-stack manifest guard

**Status:** DONE  
**Complexity:** LOW

## Files changed

- `Cargo.toml`: workspace member added
- `crates/dare-remote-validation/{Cargo.toml,src/lib.rs}`

## Result

The runtime dependencies are the four engines, `dare-adversarial`, `dare-coverage` and
`dare-security-evidence`, plus `reqwest` (workspace, rustls), `tokio` (+`net`),
`zeroize`, `serde`/`serde_json`, `jsonschema`, `sha2`, `thiserror` and `time`.
`rcgen`, `hyper` and `tokio-rustls` are added as dev-dependencies in task-023, where
they are first used.

The manifest guard parses the `[dependencies]` section on its own, so a dev-only
`hyper` is allowed and a runtime one is not.

## Tests

- `the_only_network_stack_is_reqwest`
- `the_check_catches_a_forbidden_runtime_dependency`: rmcp, hyper, openssl, hickory-resolver
- `a_test_only_dependency_is_not_a_runtime_dependency`
- `the_manifest_check_actually_sees_dependencies`

No engine crate's manifest or no-network test was touched.

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets -- -D warnings` green
- `cargo test -p dare-remote-validation`: 21 passed
- `cargo audit`: exit 0. `Cargo.lock` gained only the `dare-remote-validation` package entry. `zeroize` and `reqwest` were already locked, so no new external crate was added.
