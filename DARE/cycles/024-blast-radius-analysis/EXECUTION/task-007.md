# task-007 — Implement `admit.rs`

**Status:** DONE  
**Complexity:** LOW

`read_admitted(path, file, max_bytes)` refuses the following, in this order: a
symbolic link, a non-file, a missing file, a file over the bound (read through
`take(max + 1)`), bytes that are not JSON, invalid UTF-8, and nesting deeper than 64.

Two tests cover it:
- `a_valid_file_is_admitted`;
- `admission_refuses_links_size_depth_and_garbage`, which covers:
  - a symlink;
  - 101 bytes against a limit of 100, and exactly 100 bytes, which is read and then
    refused as not JSON;
  - depth 65 refused and depth 64 admitted;
  - `0xff 0xfe`;
  - a missing file and a directory.

Ralph Loop green.
