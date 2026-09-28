# task-007 — Create the `dare-attack-path` crate skeleton and the containment manifest guard

**Status:** DONE  
**Complexity:** LOW

## Change

- `crates/dare-attack-path` is added to `[workspace].members`, which now has 23 members.
- Its `[dependencies]` are exactly those of BLUEPRINT §2: nine engine crates,
  `dare-attack-graph`, `dare-security-evidence`, `dare-coverage` and `dare-adversarial`,
  plus `serde`, `serde_json`, `jsonschema`, `sha2` and `thiserror`. `tempfile` is a
  dev-dependency.
- No third-party crate is new to the workspace.

## Tests (`crates/dare-attack-path/tests/manifest.rs`)

- `no_network_process_or_scheduler_dependency_is_declared`: `[dependencies]` names none of
  `reqwest`, `hyper`, `rmcp`, `tokio`, `axum`, `ureq`, `openssl`, `native-tls`,
  `dare-remote-validation`, `dare-mcp-discovery` or `dare-continuous`.
- `the_source_reaches_no_socket_process_or_thread_pool`: `src/**` contains none of
  `std::net`, `std::process`, `TcpStream`, `UdpSocket`, `Command::new` or
  `std::thread::spawn`.
- `only_the_cli_depends_on_this_crate`: no `crates/*/Cargo.toml` other than the CLI
  mentions `dare-attack-path` (BQ-3 (a)).

## Ralph Loop

- Green: fmt, clippy `-D warnings`, `cargo test -p dare-attack-path`.
- Audit: no new crate in the lockfile (only the new workspace member).
