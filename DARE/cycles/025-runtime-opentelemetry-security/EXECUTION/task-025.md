# task-025 — Add the no-value-leaves, determinism and hostile tests

**Status:** DONE  
**Complexity:** MED

## `tests/no_value_leaves.rs` (O-04, RS-02, AD-07)

- **`no_input_value_reaches_any_artifact_of_any_lab_entry`** covers every non-refusal
  lab entry (54) and all four rendered artifacts (216 files).
  - It collects every attribute value longer than 3 characters in the inputs: span,
    event, resource and scope attributes, including values nested in arrays and kvlists,
    and int and double values as text.
  - It asserts that none of them appears in any artifact. The values include tool,
    agent and host names, principals, tenants, operation names, URLs, content and the
    synthetic credentials.
- **`the_scan_would_see_a_leak`** checks the collector itself on strings, nested array
  ints and kvlists.

## `tests/determinism.rs` (O-06, RNF-01; see REGRESSION R-8)

The whole lab (non-refusal entries) is merged into one input folded to 64 files, and a
fixed-seed LCG drives the shuffles (no clock).
- **`ten_file_order_shuffles_give_byte_identical_artifacts`**: all four artifacts are
  identical in each of 10 rounds.
- **`ten_span_order_shuffles_give_the_same_findings_and_verdicts`**: spans are shuffled
  inside every scope and the files are shuffled too. Each round asserts that the input
  bytes changed. The findings file is byte-identical, and the result is identical apart
  from the input digests and the evidence ids derived from them.

## `tests/hostile.rs` (RF-12), 8 tests

| Fixture | Outcome |
|---|---|
| 16 MiB + 1 file (sparse); 65-deep JSON; invalid UTF-8 | refused before parsing (`TooLarge`, `TooDeep`, `InvalidTrace`) |
| span flood: 5 001 spans with `max_spans` 1 000 | exactly 1 000 analysed, `stop_reason: max_spans`, no PASS |
| 257 attributes on one span | refused by position |
| identical duplicate across files | deduplicated (`duplicates_removed: 1`), B-1 PASS |
| conflicting duplicate | B-1 and B-3 INCONCLUSIVE: never merged, never a guess |
| parent cycle; a tree deeper than 256 | terminates; T-2 and B-1 INCONCLUSIVE |
| bidi, BEL, markup and a reversed file name in span names and agent names | none reaches any artifact |
| bearer, marker and `BEGIN PRIVATE KEY` values (synthetic) | T-1 FAIL citing the span; every artifact passes the product sweep; no value is echoed |
| a value over 64 KiB | T-1 INCONCLUSIVE, never PASS |
| `url.full` to the metadata IP (RS-03) | B-5 FAIL; the URL is never fetched and never echoed |

## Ralph Loop

| Step | Result |
|---|---|
| Build | ok |
| Test | `no_value_leaves` 2/2 (about 18 s in debug); `determinism` 2/2 (about 7 s); `hostile` 8/8 |
| Lint | fmt; clippy `-D warnings --all-targets`: clean |
| Audit | No dependency change |
