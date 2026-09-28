# task-019 — Implement `capture.rs` with chained digests and `verify`

**Status:** DONE  
**Complexity:** MED

## Result

The capture follows BLUEPRINT §4.9, with two stricter refinements, both recorded in
REGRESSION.md:

1. **The chain seed binds more.** It is
   `sha256("dare-remote/v1|" ‖ capture_id ‖ "|" ‖ authorization_digest ‖ "|" ‖ plan_digest ‖ "|" ‖ origin)`,
   so a capture cannot be re-attributed to another authorization or origin.
2. **Bodies are neutralized.** Every entry records `scrubbed_credential`,
   `scrubbed_shapes` and `neutralized_chars`. Response text has control, bidi and
   zero-width characters replaced by U+FFFD. The live pass uses the same neutralized
   text as the capture, so strategy selection cannot differ between the live pass and
   the replay.

Only `WWW-Authenticate` is kept among the response headers (scrubbed).
`Capture::admit` checks size (16 MiB), depth and schema, then `verify`.

## Tests

- `push_chains_and_verify_accepts`
- `a_one_byte_change_is_detected_at_its_entry`
- `gaps_duplicates_and_reorders_are_detected`
- `the_seed_binds_the_authorization_plan_and_origin`
- `neutralize_replaces_only_hostile_characters`
- `a_capture_round_trips_through_admission`

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets --features lab -- -D warnings` green
- `cargo test -p dare-remote-validation`: 103 passed
- No external dependency added
