# task-012 — Implement `origin.rs` `Origin::parse`

**Status:** DONE  
**Complexity:** MED

## Result

The parser implements every rule of BLUEPRINT §4.3. In addition, dotted quads with
leading zeros (`010.0.0.1`) are refused, because some resolvers read them as octal.
Serde round-trips the normalized form, and `is_loopback` supports rule 5.

## Tests

- `well_formed_origins_parse_and_normalize` (8 cases, including `:443` equality)
- `every_refused_shape_is_refused_without_echo` (26 shapes)
- `control_and_bidi_characters_are_named_by_codepoint`
- `serde_round_trips_the_normalized_form_and_refuses_bad_values`
- `loopback_detection`

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets -- -D warnings` green
- `cargo test -p dare-remote-validation`: 74 passed
- No dependency change
