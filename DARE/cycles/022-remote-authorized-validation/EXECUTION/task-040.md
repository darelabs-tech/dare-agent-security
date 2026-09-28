# task-040 — Security, dependency and container audit

**Status:** DONE  
**Complexity:** MED

## Results

| Check | Command | Result |
|---|---|---|
| Advisories | `cargo audit` | **exit 0**, 1271 advisories, 320 crates, including `rcgen 0.14.10` and its dev-only closure |
| rcgen stays dev-only | `cargo tree -p dare-agent-security -e normal` | no `rcgen`, `x509-parser` or lab crate. The only TLS crate present, `tokio-rustls`, was already in the baseline `Cargo.lock` (through `reqwest`) |
| Credential and endpoint sweep | `python scripts/k22/assert_no_real_credentials.py` | **exit 0** over 33 shipping files, 20 test files and 12 artifacts |
| Builder-stage image | `docker build --target builder` (see below) | **exit 0**. The whole workspace, including `dare-remote-validation` and the CLI, compiled in release **inside the image** with the image's own **Rust 1.88** (the build stage took 219 s) |
| In-image refusal with networking disabled | `docker run --network none … validate remote --authorization <expired>` | **exit 3**: "authorization refused: the authorization window is invalid or not current". Nothing was written (`/tmp/out` absent), and `--help` offers no `--url` |

## How the image was built

As in Cycle 021 (task-035), the build used a **temporary copy** of the root
`Dockerfile` in the session scratchpad. It adds only the two lines the session proxy
requires, so the builder can reach crates.io through it:

```
+ COPY --from=ca ca-bundle.crt /ca/ca-bundle.crt
+ ENV CARGO_HTTP_CAINFO=/ca/ca-bundle.crt SSL_CERT_FILE=/ca/ca-bundle.crt
```

It was run with `docker build --network host --build-context ca=<scratchpad>/ca
--build-arg http(s)_proxy=…`. The repository `Dockerfile` is unchanged, and no `COPY`
line changed.

The runtime stage's `apt-get` targets `deb.debian.org`, which the session network
policy denies (as recorded at baseline). The authoritative full-image check is
`action-e2e.yml` on the pull request. The in-image refusal was therefore run against the
builder-stage binary (`/src/target/release/dare-agent-security`), which is the same file
the runtime stage copies.

The expired authorization is the committed CLI fixture with `not_before` and
`not_after` moved to January 2026. Rule 7 (the window) is checked before rule 12 (the
digest), so the refusal is the window's.

## Additional hardening found during the audit

Checking the Design's §4.5 credential row ("a token in a header") showed a gap: a
credential echoed in `WWW-Authenticate` was scrubbed but did **not** arm the kill switch,
unlike an echo in the body.
- **Fix:** header echoes now count toward `scrubbed_credential` and trigger `SECRET_DETECTED`.
- **Test:** `gateway.rs::a_credential_echoed_in_the_challenge_header_is_scrubbed_and_kills`.

Added for the Design's rows on timeouts and determinism:
- `gateway.rs::a_reply_slower_than_the_read_timeout_is_a_timeout_never_a_pass`: a 16 s reply gives `READ_TIMEOUT`, and the client gives up first.
- `replay_equivalence.rs::ten_replays_of_one_capture_are_byte_identical` (RNF-01).

The image and its build cache were removed afterwards to free the session disk.
