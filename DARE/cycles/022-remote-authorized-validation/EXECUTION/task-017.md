# task-017 — Implement `Credential` and `Scrubber`

**Status:** DONE  
**Complexity:** MED

## Result

**Credential.**
- The value is held in `Zeroizing<String>` and read once through an injected lookup.
- The value must be printable ASCII, 1–4096 bytes.
- The reference name is checked against `^DARE_REMOTE_[A-Z0-9_]{1,48}$`.
- `Debug` prints `Credential(<redacted>)`, and the header value is `set_sensitive(true)`.

**Scrubber.**
- Needles: the raw value, unpadded standard and URL-safe base64, and the percent-encoding. They are replaced longest first, and the exact-match count is returned because an echo is a kill trigger.
- The credential shapes of Cycle 021 are scrubbed too, plus `github_pat_`, bearer runs of 16 or more characters and JWTs.
- Base64 and percent-encoding are implemented locally (RFC 4648 vectors tested), so no `base64` dependency is added.

## Tests

- `reference_names_follow_the_pattern`
- `a_missing_empty_oversized_or_non_printable_value_is_refused`
- `debug_never_shows_the_value_and_the_header_is_sensitive`
- `every_echo_form_is_scrubbed_and_counted`
- `padded_base64_is_still_scrubbed`
- `credential_shapes_are_scrubbed_without_a_credential`
- `prose_about_credentials_is_left_alone`
- `base64_matches_the_rfc_4648_vectors_unpadded`

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets -- -D warnings` green
- `cargo test -p dare-remote-validation`: 74 passed
- No dependency change
