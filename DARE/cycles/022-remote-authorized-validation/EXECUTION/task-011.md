# task-011 — Implement `source.rs`/`schema.rs` byte, depth, hostile and schema admission

**Status:** DONE  
**Complexity:** MED

## Result

`source::admit` runs these steps in order:
1. byte ceiling (256 KiB);
2. JSON parse;
3. iterative depth check (32);
4. `schema_version == "1"`;
5. hostile sweep:
   - 44 forbidden field names in any case (credential, raw target and transport override, executable, generation, self-declared outcome);
   - control, bidi and zero-width characters by code point;
   - credential-shaped values, including JWT and bearer runs;
6. embedded JSON Schema (pointer only);
7. serde into the domain type.

`credential_ref` and `endpoints` stay admissible, because the name match is exact.
`read_bounded` never reads past the ceiling.

## Tests

- `well_formed_documents_are_admitted`
- `oversize_and_deep_documents_are_refused_before_parsing`
- `a_wrong_version_is_refused_first`
- `every_forbidden_field_name_is_refused_in_any_case`
- `credential_shaped_values_are_refused_but_the_reference_is_not`
- `control_and_bidi_characters_are_refused_by_codepoint`
- `schema_violations_report_the_pointer`
- `read_bounded_refuses_directories_and_oversize_files`
- schema tests: `every_embedded_schema_compiles_and_self_describes`, `the_embedded_copies_equal_the_files_on_disk`, `a_violation_reports_the_pointer_not_the_value`, `the_request_schema_has_no_field_that_could_reveal_the_test`

The capture, audit and result documents are admitted by their own modules
(tasks 019, 020 and 033), because their bodies are scrubbed text rather than
authored input.

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets -- -D warnings` green
- `cargo test -p dare-remote-validation`: 74 passed
- No dependency change
