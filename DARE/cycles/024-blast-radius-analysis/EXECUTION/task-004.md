# task-004 — Move the output sweep and publish the label escaper

**Status:** DONE  
**Complexity:** LOW

## Change

- **`crates/dare-attack-graph/src/v2/sweep.rs` (new)** holds `MARKERS`,
  `contains_bearer_credential` and the new `is_sensitive(bytes) -> bool`, moved from
  `dare-attack-path`. They carry no error type, so any crate can use them.
- **`crates/dare-attack-path/src/sweep.rs`** re-exports them and keeps its
  `sweep(file, bytes) -> Result<()>` wrapper, which now calls `is_sensitive`. The
  refusal (`SensitiveOutput`) and its tests are unchanged.
- **`crates/dare-attack-graph/src/render.rs`:** `safe_label` becomes the public
  `escape_label`, re-exported from the crate root. The v1 and v2 renderers call it, and
  its body is unchanged.

## Tests

- New: `every_marker_and_a_bearer_credential_is_sensitive` in `dare-attack-graph`.
- Unchanged and green:
  - `every_marker_and_a_bearer_credential_is_refused`, `ordinary_text_passes`;
  - `v1_output_is_byte_identical_to_the_baseline`;
  - `views_label_state_in_text_and_escape_hostile_labels`;
  - `hostile_labels_are_escaped_in_the_views_and_credential_shaped_ids_are_hashed`;
  - `every_attack_path_lab_output_keeps_its_baseline_digest` (156 files);
  - `attack_path_lab`.
- `dare-attack-path` and `dare-attack-graph`: 125 tests passed, 0 failed.

## Ralph Loop

Green: fmt, and clippy `-D warnings --all-targets` on both crates. No dependency changed.
