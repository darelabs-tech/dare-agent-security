# task-008 — Implement `normalize.rs` and value fingerprints (AD-07)

**Status:** DONE  
**Complexity:** MED

- **`Fingerprint{kind, length, digest}`** is the only form in which a value may reach an
  artifact.
  - `kind` is one of 8 `ValueKind`s.
  - `length` is bytes for strings and bytes, items for arrays and kvlists.
  - `digest` is `sha256:` over a tagged, length-prefixed canonical encoding. Kind,
    nesting and boundaries are all part of the digest, so `["ab","c"]` and `["a","bc"]`
    differ, and so do `"42"` and `42`.
- **`NValue`** holds the value in a **private** field and has no `Serialize`. Its
  accessors `as_str`, `as_i64` and `texts` (every nested string or bytes text, for T-1)
  are `pub(crate)`.
  - A temporary `#[allow(dead_code)]` on the impl keeps clippy quiet until the
    evaluators use the accessors (tasks 013–016). task-017 removes it.
- **`NSpan`** carries the file index, ids, parent, and the **span name as an `NValue`**
  (a name can embed a tool or agent name). It also carries kind, times, flags, status,
  span and resource attributes, events, and link and dropped counts.
  - `attr(key)` reads the span first, then the resource.
  - `sampled()` returns the W3C flag bit 0, or `None` when not recorded.
  - A duplicate attribute key keeps its **first** value and is reported in
    `duplicate_keys`, so a later entry cannot silently override an earlier one.

## Tests

- `fingerprints_separate_kinds_and_values_and_carry_no_value`: a canary value's
  serialized fingerprint does not contain it.
- `normalization_keeps_first_of_duplicate_keys_and_reads_resource_as_fallback`
- `texts_reach_nested_strings_and_bytes`
- `the_raw_value_has_no_serializer_and_no_public_accessor`: a source check that the
  field is private, there is no `Serialize`, and the accessors are `pub(crate)`.

Ralph Loop green.
