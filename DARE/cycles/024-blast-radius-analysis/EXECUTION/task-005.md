# task-005 — Create the `dare-blast-radius` crate skeleton and the manifest guard

**Status:** DONE  
**Complexity:** LOW

- The workspace gains the member `crates/dare-blast-radius`, and now has 24 members.
- **Dependencies:** `dare-attack-graph`, `jsonschema`, `serde`, `serde_json`, `sha2` and
  `thiserror`; dev: `tempfile`. All are already locked, so nothing third-party is new.
- `tests/manifest.rs` has three tests:
  - `the_dependencies_are_exactly_the_blueprint_list` compares both dependency sections
    exactly;
  - `the_source_reaches_no_socket_process_thread_or_environment` scans `src/` for
    `std::net`, `std::process`, `std::thread`, `std::env`, `env::var`, `TcpStream`,
    `UdpSocket`, `Command::new` and `dare_attack_path`;
  - `only_the_cli_depends_on_this_crate`.
- The Cycle 023 guard `only_the_cli_depends_on_this_crate` (in `dare-attack-path`)
  still passes. The first draft of the new `Cargo.toml` comment named that crate, the
  guard caught the string, and the comment was reworded.

Ralph Loop green: fmt, clippy `-D warnings --all-targets`, and the tests.
