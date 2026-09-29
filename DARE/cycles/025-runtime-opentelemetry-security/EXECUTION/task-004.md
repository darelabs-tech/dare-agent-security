# task-004 — Create the `dare-runtime-telemetry` crate skeleton and the manifest guards

**Status:** DONE  
**Complexity:** LOW

- **Workspace:** the crate is a member, listed after `dare-blast-radius`.
- **`[dependencies]`:** exactly the AD-01 list: `dare-coverage`,
  `dare-security-evidence`, `jsonschema`, `serde`, `serde_json`, `sha2`, `thiserror`.
- **`[dev-dependencies]`:** `dare-attack-graph`, used only by the BQ-3 marker-equality
  test, and `tempfile`.
- **`src/lib.rs`** holds the `FORBIDDEN` dependency test in the Cycle 021 pattern, with 34
  names. Besides the network, TLS and random-number crates, the list covers every
  OpenTelemetry SDK, exporter and proto crate, `prost`/`protobuf`, `tokio`/`async-std`,
  and the server frameworks. A companion test proves the check fires when a forbidden
  line is added, and another proves it reads the manifest.
- **`tests/manifest.rs`:**
  - `the_dependencies_are_exactly_the_blueprint_list` covers both sections.
  - `the_source_reaches_no_socket_process_thread_or_environment` walks `src/`
    recursively.
  - `only_the_cli_depends_on_this_crate`.

Ralph Loop: fmt and clippy `-D warnings` are clean, and the 6 tests pass.
