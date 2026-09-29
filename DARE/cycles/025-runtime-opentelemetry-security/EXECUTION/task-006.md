# task-006 — Implement `admit.rs`

**Status:** DONE  
**Complexity:** LOW

Admission runs in three steps:
- **`read_bytes(path, input, max)`** refuses, in order, a symbolic link, a non-file and a
  file over `max`. It reads through `take(max + 1)`, so a file that grows after `stat` is
  still bounded.
- **`parse_admitted`** refuses invalid JSON (`InvalidTrace{reason: "json"}` or
  `InvalidPolicy`) and depth above 64.
- **`TotalBudget`** refuses the byte that takes the run over 256 MiB.

## Tests

- `a_valid_file_is_admitted`
- `admission_refuses_links_size_depth_and_garbage`: symlink; limit + 1 byte refused and
  exactly the limit read; depth 65 refused and depth 64 accepted; `0xff 0xfe`; missing
  file; directory.
- `the_total_budget_refuses_one_byte_over`

Ralph Loop green.
