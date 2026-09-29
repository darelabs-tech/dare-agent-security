# task-002 — Convert the registry and profile pins to the prefix rule (BQ-1)

**Status:** DONE  
**Complexity:** MED

This is the test-only exception that APPROVAL BQ-1 (a) authorizes. Exactly two test files
changed, and no engine `src/` file changed: the check
`git diff 00e7aff --name-only -- 'crates/dare-*/src'` restricted to engine crates 013–022
lists nothing.

| File | Change |
|---|---|
| `crates/dare-remote-validation/tests/compatibility.rs` (Cycle 022) | `the_registry_and_every_profile_are_byte_for_byte_unchanged` now takes the whole-file registry digest out of `UNCHANGED_FILES` (which goes from 12 entries to 11) and checks it with `REGISTRY_PREFIX` instead |
| `crates/dare-agent-security-cli/tests/attack_path_compatibility.rs` (Cycle 023) | `the_registries_and_every_profile_are_unchanged` gets the same `REGISTRY_PREFIX` check (v1 registry still pinned whole). The profile count goes from `== 11` to `>= 11`, with the 11 earlier profiles still pinned byte for byte. `ENGINE_TREES` re-pins `dare-remote-validation` from `1b494a04…` to `e13f3c63…`, and that change is the edit to its test file |

The `REGISTRY_PREFIX` rule works as follows:
- The first 63 498 bytes of `schemas/coverage/v2/registry.json` must keep the SHA-256
  `5364f9dc…fef91ec4`. They run through the closing brace of the 65th, and last
  pre-existing, property.
- Anything after them must be either the original tail `\n  ]\n}\n` or begin with `,\n`,
  which marks an appended entry.

## Evidence

- Both tests pass on the unchanged tree, and so do the other 6 + 3 tests in their files.
- The rule was checked against the real file by temporarily editing it and then
  restoring it:
  - appending an entry → **pass**;
  - one byte changed inside an existing entry → **fail**, "an existing entry changed".

  After the restore, `git status` shows the registry clean.
- `cargo clippy -p dare-remote-validation -p dare-agent-security --tests -D warnings` is
  clean, and `cargo fmt` is clean.
