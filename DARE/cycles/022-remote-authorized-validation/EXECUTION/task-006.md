# task-006 — Add the 32-record every-bridge validation test and update the changed 018/019/020 assertions

**Status:** DONE  
**Complexity:** MED

## Files changed

- `crates/dare-agent-security-cli/tests/every_bridge_validates.rs` (new)
- The three tests updated in tasks 002–004

## Result

`every_record_of_every_bridge_is_valid_cycle_001_evidence` runs the built binary over
**every built-in scenario of all nine engines** in the default offline mode. It
validates every emitted record: **1 882 records, all valid**. It then asserts:
- every engine produced both PASS and FAIL;
- the three corrected bridges produced undecided records;
- every undecided record carries no decision.

| Engine | Verdicts covered |
|---|---|
| a2a, supply-chain | PASS, FAIL, INCONCLUSIVE, ERROR |
| identity, memory, rag, tool, prompt-injection, mcp-auth, multi-turn | PASS, FAIL, INCONCLUSIVE |

That is **29 of 36** bridge × verdict cells. The seven engines without an ERROR cell
produce no ERROR evidence from their built-in scenarios in the default mode: their
harness-error entries stop before any artifact is written. For every bridge, ERROR
records are built by the same branch as INCONCLUSIVE records, which is exercised.
Design O-09 stated "32/32" assuming 8 bridges × 4 verdicts. The measured coverage is
recorded here as it is.

## Findings while writing the test

- **Corpus vector ids are not scenario ids.** The first version passed vector ids,
  every run was refused with exit 3 and silently skipped, and the test failed only
  because of its coverage check. The test now reads scenario ids from each CLI's
  scenarios directory.
- **Exit 1 without artifacts is tolerated only when stderr names the output budget.**
  This is the case for the Cycle 021 GAP entry `multiturn-lab-018`, which lowers the
  budget on purpose. A broader tolerance had hidden a missing-parent-directory failure
  during development.

## Assertions changed (listed in REGRESSION.md)

- `dare-a2a-security/src/evidence_bridge.rs`: `an_undecided_record_is_not_applicable_and_never_a_pass` → `an_undecided_record_carries_no_decision_and_never_a_pass`
- `dare-mcp-auth-security/src/evidence_bridge.rs`: `an_undecided_trial_carries_no_decision_in_either_direction` (assertion body)
- `dare-supply-chain-security/src/evidence_bridge.rs`: `an_undecidable_invariant_is_recorded_as_insufficient_evidence_not_as_a_pass` (assertion body)

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- `cargo test --workspace`: 281 suites, 3 957 passed, 0 failed (baseline 3 955 + 2 new tests)
- No dependency change, so no audit was required
