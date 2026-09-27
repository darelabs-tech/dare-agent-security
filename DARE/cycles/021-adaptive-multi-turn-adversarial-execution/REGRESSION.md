# Cycle 021 — Regression Record

**Status:** COMPLETE  
**Baseline:** `main @ 4ca06b2` — 3 767 tests passing (see `BASELINE.md`)

This record lists every defect or design gap found **during** execution, how it was
found, what changed, and which test now holds the line. Several were caught by the
cycle's own gates, which is the reason those gates exist.

## 1. Path count treated parallel edges as separate paths (task-009, found in task-025)

- **Found by:** the first MULTITURN-LAB run. An ordinary six-reframe refusal graph was
  refused with "paths is 382, the limit is 64".
- **Cause:** a node with `REFUSED → x` and `DEFLECTED → x` contributed `x` twice to
  the DP sum.
- **Fix:** a path is a sequence of distinct nodes, so successors are de-duplicated
  before counting.
- **Test:** `rule_10_parallel_edges_to_one_successor_are_one_path`. The five
  hand-computed counts in `rule_10_path_counts_match_hand_computed_values` are
  unchanged.

## 2. A lowered turn bound cannot stage a mid-run stop (task-025)

- **Found by:** GAP entries built with `max_turns_per_conversation: 2` were
  *refused* instead of stopping mid-run.
- **Not a defect:** graph depth is checked against the bound before the first turn
  (rule 9). That static refusal is the intended behaviour.
- **Change:** the corpus stages mid-run budget gaps by lowering the evidence byte
  budget (`multiturn-lab-018`, `-040`), and non-exhaustive gaps by removing an edge
  (`-005`, `-012`).
- **Test:** `lowered_bounds_that_the_graph_exceeds_are_a_refusal` (CLI).

## 3. I01 read a harness-error turn as an ambiguous follow-up (task-020, found in task-026)

- **Found by:** reviewing the *reason* of every corpus entry, not only its verdict.
  `multiturn-lab-038` (a harness failure) reported `AMBIGUOUS_FOLLOW_UP`.
- **Impact:** the verdict was already ERROR, but the reason was misleading.
- **Fix:** a harness-error turn is neither a violation nor ambiguity.
- **Test:** `i01_a_harness_error_follow_up_is_not_an_ambiguous_one`.

## 4. Replay tampering was an ERROR where the Design says refuse (task-015, found in task-028)

- **Found by:** comparing the Blueprint against DESIGN RF-10 while writing the
  hostile corpus.
- **Conflict:** the Blueprint treated reordered, inserted and dropped turns as
  runtime strategy faults (ERROR). RF-10 says they are refused.
- **Fix:** `ReplayAdapter::new` refuses a transcript whose indices are not exactly
  `0, 1, 2, …`. A wrong node or a truncated tail can only be seen at run time, so it
  remains a strategy fault (ERROR, never PASS).
- **Tests:**
  - `reordered_duplicated_and_gapped_indices_are_refused_at_binding`;
  - `reordered_duplicated_or_gapped_transcripts_are_refused_before_any_turn`.
- **Removed test:** `reordered_and_inserted_turns_are_strategy_faults`, which
  asserted the old behaviour.

## 5. Cycle 001 hashes are bare hex (task-031)

- **Found by:** `dare_security_evidence::validate` on the first evidence record.
- **Error:** `hashes.0: hash digest must be lowercase hexadecimal`.
- **Fix:** strip the `sha256:` prefix into the separate `algorithm` field.
- **Test:** `one_valid_record_per_invariant_with_unique_ids`.

## 6. INCONCLUSIVE records carried an observed decision (task-031)

- **Found by:** the Cycle 001 validator: "INCONCLUSIVE cannot masquerade as FAIL".
- **Cause:** `observed.decision = NotApplicable` against `expected = Deny` compares
  as a *mismatch*.
- **Fix:** only PASS and FAIL carry an observed decision.
- **Test:** `every_verdict_produces_valid_cycle_001_evidence`.
- **Out of scope:** the same pattern exists in earlier bridges (`dare-a2a-security`,
  `dare-mcp-auth-security`, `dare-supply-chain-security` and others). It was **not**
  changed here, because it is frozen behaviour of earlier cycles. It was raised to
  the user as a separate task.

## 7. Cycle 015/016 tests froze family sizes (task-029) — Product Owner decision

- **Found by:** appending the seven properties.
- **What broke:** 7 test functions in 4 files failed, because
  `AGENT.IDENTITY.*` and `AGENT.MEMORY.*` were pinned at six, and each family had to
  be fully selected by its profile.
- **Action:** execution stopped (APPROVAL rule) and the Product Owner chose to
  adjust the tests:
  - they pin the six original properties by name;
  - they tolerate only the named `CYCLE_021_ADDITIONS`.
- **New guards:**
  - `the_only_later_identity_family_members_are_the_named_cycle_021_additions`;
  - `the_only_later_memory_family_members_are_the_named_cycle_021_additions`.
- **Unchanged:** no profile denominator moved (`no_earlier_profile_denominator_moved`,
  `every_earlier_profile_is_unchanged`).

## 8. Credential shapes written literally in a test (task-033)

- **Found by:** the new `scripts/k21/assert_no_real_credentials.py` on its first run.
- **Where:** `tests/hostile_refusal.rs` contained `sk-live-…`, a private-key header
  and a `Bearer …` value as literals.
- **Fix:** they are assembled with `format!` at run time. The refusal test still
  refuses them.

## 9. Deep nesting is refused by the parser before the depth check (task-028)

- **Found by:** a 132-level document returned `Schema` instead of `DepthExceeded`.
  serde_json's recursion limit (128) rejects it during parsing.
- **Impact:** still a refusal, and nothing overflows.
- **Change:** the test was split in two:
  - `nesting_beyond_the_depth_bound_is_refused_by_the_depth_check` (depth 40);
  - `extreme_nesting_is_refused_without_exhausting_the_stack` (depth 1 000).
- **Removed test:** `deeply_nested_json_is_refused_without_recursion`.

## 10. Design deviations recorded during execution

| Task | Deviation | Why |
|---|---|---|
| 003 | `BoundZero` error added | A zero bound is not a raise, so the message must not say it is |
| 006 | Canary field named `marker`, not `token` | `token` is a forbidden credential field name in every fixture sweep |
| 014 | `HarnessErrorKind::BudgetExhausted` | The adapter needs a way to report a Cycle 009 budget stop, which becomes INCONCLUSIVE |
| 023 | No separate `target_id` comparison in I05 | The action digest is the action's full identity, including its target |
| 024 | `safe` added to `OVERCLAIMS` | Stricter only |
| 030 | Cycle 020's denominator test left untouched | A new test pins all ten earlier profiles instead |
| 032 | Simulated modes run corpus ids only | No `--reference-agent` flag can label a real scenario with a synthetic behaviour |

## 11. Mutation check

After the invariant suite passed on its first run, two deliberate mutations were
applied and then reverted:
- `complete()` always true: 3 tests failed.
- I01's erosion check disabled: 3 tests failed.

The no-false-PASS rule and the I01 FAIL rule are therefore tested, not merely
exercised.

## 12. Environment findings (not repository defects)

- **Docker Hub rate limit.** It answered `429` at task-001. The baseline Action-image
  evidence fell back to the last green `action-e2e` run.
- **Session disk.** The session's writable disk filled mid-task (`ENOSPC`).
  Incremental build output and the Docker cache were deleted, and the suites were
  re-run clean.
- **Container network.** The session proxy only tunnels HTTPS, and its policy denies
  `deb.debian.org`. The Action image's final `apt-get install ca-certificates` stage
  therefore cannot run in this session. See `PROOF.md` §6 for what was built and run
  instead.
