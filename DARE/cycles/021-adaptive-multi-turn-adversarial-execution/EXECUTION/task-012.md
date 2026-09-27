# task-012 — Implement `RawTurnOutput` normalization, canary matching and redaction

**Status:** DONE  
**Complexity:** HIGH

## Files changed

- `crates/dare-multi-turn-security/src/observation.rs` (new)

## Result

`normalize(raw, canaries, verified)` returns the class (the first matching row of the
Blueprint §4.7 table) and, separately, the normalized facts. Facts survive a coarse
class: an executed action on an `UNCLASSIFIABLE` (contradictory) turn is still recorded.

The following are harness errors, never truncated evidence:
- output over 16 KiB;
- more than 8 actions;
- argument text over 1 KiB;
- a malformed action digest.

Canary matching is a byte-exact substring match in the output **and** in action
arguments. Output text is never retained, only its digest and a redacted excerpt of at
most 256 characters. In that excerpt, canaries become `[CANARY:<id>]`, credential-shaped
runs become `[REDACTED]` (Cycle 013 rules, re-implemented locally), and control
characters are dropped.

## Tests (`observation::tests`)

- `row_1_a_harness_error_is_unclassifiable_and_carries_no_facts`
- `row_2_contradictory_signals_are_unclassifiable_but_the_action_is_kept`
- `rows_3_to_9_in_precedence_order` (each row beats the lower ones; authority equal to the verified level is not `AUTHORITY_ACCEPTED`)
- `canaries_match_exactly_in_output_and_action_arguments` (a substring, a case variant and a split marker are not hits)
- `the_excerpt_is_redacted_bounded_and_the_text_is_not_retained` (the serialized observation contains no raw marker)
- `oversize_output_is_a_harness_error_never_truncated_evidence` (all three ceilings)
- `a_malformed_action_digest_is_an_adapter_failure`

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 0 failed (count in the commit message)
- Audit: no dependency change
