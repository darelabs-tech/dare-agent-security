# task-031 — Implement coverage facts and Cycle 001 evidence bridge

**Status:** DONE  
**Complexity:** MED

## Files changed

- `crates/dare-multi-turn-security/src/coverage.rs` (new): `assessment_facts`, `coverage_rows`, `coverage_report`
- `crates/dare-multi-turn-security/src/evidence_bridge.rs` (new): `build_evidence`, `evidence_index`

## Result

**Coverage:**
- A decided invariant is `APPLICABLE` and carries its verdict.
- An invariant the scenario could not decide is `NOT_TESTED`, never `NOT_APPLICABLE`: the agent is stateful, so the surface exists.
- Only the Cycle 021 profile is used.

**Evidence:** there is one Cycle 001 `SecurityEvidence` record per invariant. It carries
identifiers, digests, the path (node ids and classes) and the deciding turn references.
It never carries content, output or canary markers.

## Defects caught by the Cycle 001 validator (fixed in this task)

1. `HashRef.value` must be bare hex. The first version passed `sha256:`-prefixed digests.
2. For INCONCLUSIVE and ERROR, `observed.decision` must be `None`. `Some(NotApplicable)` compares as a *Mismatch*, and the record is rejected as "INCONCLUSIVE cannot masquerade as FAIL".

## Out-of-scope finding

Defect 2 exists in earlier cycles' bridges: `dare-a2a-security`, `dare-mcp-auth-security`
and `dare-supply-chain-security` set `Decision::NotApplicable` for INCONCLUSIVE/ERROR,
and other bridges reference it. This was not fixed here, because it is outside Cycle 021
and changes frozen behaviour. It was raised to the user as a separate suggested task.

## Tests

- `coverage::tests::the_facts_make_every_multi_turn_property_applicable`
- `coverage::tests::decided_invariants_are_applicable_and_the_rest_are_not_tested_never_not_applicable`
- `coverage::tests::the_report_builds_over_the_seven_property_profile`
- `evidence_bridge::tests::one_valid_record_per_invariant_with_unique_ids` (runs `dare_security_evidence::validate` on every record)
- `evidence_bridge::tests::every_verdict_produces_valid_cycle_001_evidence` (PASS, FAIL, INCONCLUSIVE)
- `evidence_bridge::tests::the_verdict_and_decision_follow_the_invariant`
- `evidence_bridge::tests::records_carry_no_turn_content_or_canary`
- `evidence_bridge::tests::each_record_maps_to_the_asi_of_its_family`

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 3917 passed, 0 failed
- Audit: no dependency change
