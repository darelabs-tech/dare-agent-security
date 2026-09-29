# task-021 — Implement `summary.md`

**Status:** DONE  
**Complexity:** LOW

## `src/summary.rs`

`summary(run) -> String` is a pure function of the run. It has these sections:

1. **Header:**
   - the run verdict and its reason;
   - the mode, marked "synthetic traces" in SIMULATED runs;
   - the semconv core and GenAI releases, and the mapping digest;
   - the policy id and digest, or "none" with the statement that B-1..B-6 are not
     applicable;
   - the counts of files, traces, analysed spans, removed duplicates and unrecognized
     keys;
   - the span bound, and whether it was reached.
2. **Spans by kind.**
3. **Properties:** one row per rule, with:
   - the rule code, property id, verdict (`-` if none), coverage and reason;
   - the per-trace counts (failed / undecided / passed / not exercised);
   - the gaps and the evidence id.
4. **Incomplete traces:** the trace id and its gaps, up to 50 rows, with the rest
   counted.
5. **Failing traces:** the rule, trace id, reason codes and number of deciding spans,
   up to 50 rows. No key and no value is listed.
6. **Not claimed:**
   - the traces are self-reported;
   - no authenticity is claimed (the exports are unsigned);
   - absence is not proof;
   - a PASS covers only complete traces;
   - the result's bounded claim;
   - no attribute value, prompt, completion or tool argument is copied.

**Neutralization (`neutral`):**
- control characters and bidi or invisible characters are dropped (U+061C,
  U+200B–U+200F, U+202A–U+202E, U+2060–U+2069, U+FEFF);
- names are capped at 80 characters;
- `| < > &` are escaped, and so are the Markdown markup characters `` ` * _ [ ] # ``.

A `missing_key` gap goes through `safe_key`, so a hostile key appears as `key-<digest>`.

There is no time stamp anywhere, since the result carries none (R-6).

## Tests

`tests/summary.rs` has 5 tests:
- `counts_verdicts_reasons_and_incomplete_traces_are_reported`
- `no_value_and_no_time_stamp_appear`: canary values, a bearer token, the principal,
  tool, host and agent names, and the strings `1970`, `2026`, `UTC` and `T00:` are all
  absent.
- `it_ends_with_the_not_claimed_statements`: also checks the NOT_APPLICABLE row without
  a policy and the NOT_TESTED row with one.
- `the_summary_does_not_depend_on_file_order`
- `a_span_bound_stop_is_stated`

There are also 2 unit tests: neutralization, and `missing_key` digesting.

## Ralph Loop

| Step | Result |
|---|---|
| Build | ok |
| Test | `dare-runtime-telemetry`: 74 unit + 10 evidence + 3 manifest + 9 result + 5 summary, 0 failed |
| Lint | fmt and clippy `-D warnings`: clean |
| Audit | No dependency change |
