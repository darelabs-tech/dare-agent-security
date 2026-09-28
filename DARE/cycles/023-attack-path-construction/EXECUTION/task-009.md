# task-009 — Implement `admit.rs` file admission and the `sweep.rs` artifact secret sweep

**Status:** DONE  
**Complexity:** MED

## Change

- `admit_dir` refuses a missing path, a non-directory or a symlinked artifact directory.
  It then canonicalizes the root.
- `AdmittedDir::read_bytes` checks, in this order:
  1. the path is not a symbolic link (`symlink_metadata`);
  2. `canonicalize` resolves under the root (`PathEscape`);
  3. the path is a regular file;
  4. the read goes through `take(MAX_FILE_BYTES + 1)`, so a file that grows after `stat`
     is still bounded (`FileTooLarge`).
- `read_json` then parses the file and measures its depth iteratively, so measuring
  cannot overflow the stack (`TooDeep` above 64).
- `list_files` lists a directory, refusing links and nested directories.
- `sweep.rs` refuses the six AD-12 markers, and `bearer ` followed by at least eight
  token characters, case-insensitive.

## Tests

- `admission_refuses_links_escapes_oversize_and_depth` covers:
  - an ordinary file (accepted);
  - depth 65 (`TooDeep`);
  - 16 MiB + 1 byte, as a sparse file (`FileTooLarge`);
  - broken JSON;
  - a symlinked file (`Symlink`);
  - `../` (refused);
  - a directory given as a file (refused).
- `a_path_through_a_linked_directory_that_leaves_the_root_is_refused` (`PathEscape`).
- `a_linked_artifact_directory_is_refused`.
- `depth_is_counted_per_level`.
- `every_marker_and_a_bearer_credential_is_refused` and `ordinary_text_passes`.

## Ralph Loop

Green: fmt, clippy `-D warnings`, tests.
