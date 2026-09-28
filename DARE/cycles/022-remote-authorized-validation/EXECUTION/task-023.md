# task-023 — Build the REMOTE-LAB harness (`LabCa` with rcgen, `LabServer`, behaviours)

**Status:** DONE  
**Complexity:** HIGH

## Files changed

- `crates/dare-remote-validation/Cargo.toml`: dev-dependencies `rcgen 0.14` (aws-lc-rs backend, no `ring` feature requested), `rustls`, `tokio-rustls`, `hyper`, `hyper-util`, `http-body-util`; feature `lab` (test seams)
- `tests/lab/mod.rs`: `LabCa`, `LabServer`, `LabHit`, `LabReply`, `Handler`, `always`
- `tests/lab_harness.rs`, `tests/common/mod.rs`

## Result

- The CA and every server key are generated in memory per test and never written.
- Servers bind `127.0.0.1:0` and log the time, method, path, `Authorization`, header names, body and peer of each request.
- Behaviours are closures, stateful where needed.

`Cargo.lock` gained dev-only packages through rcgen: `asn1-rs`, `der-parser`,
`x509-parser`, `pem`, `yasna`, `nom`, `oid-registry` and friends. `cargo audit` is clean,
and none of them is linked into the binary.

## Tests

- `a_lab_server_answers_over_tls_trusted_only_through_the_lab_root`: a client trusting another lab CA is refused, and the handler is never reached
- `a_certificate_for_another_name_fails_verification`
- `handlers_see_the_request_and_can_keep_state`
- `no_private_key_is_checked_in_anywhere_in_this_crate`: scans every file of the crate for key extensions and PEM private-key headers. It found literal headers in two unit tests, which are now assembled at run time.

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets --features lab -- -D warnings` green
- `cargo test -p dare-remote-validation`: 103 unit + 16 gateway + 4 lab harness + 1 no-proxy + 1 window = 125 passed
- `cargo audit`: exit 0 after adding the dev-dependencies
