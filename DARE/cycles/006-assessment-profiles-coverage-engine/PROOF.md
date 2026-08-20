# Cycle 006 — DARE Proof

> Cycle: `006-assessment-profiles-coverage-engine`
> Date: 2026-08-20
> Branch: `agent/cycle-006-assessment-profiles-coverage-engine`

Maps DESIGN acceptance criteria to implementation and tests.

| # | Criterion | Evidence |
|---|-----------|----------|
| 1 | Cycles 001–004 reconciled | `IMPLEMENTATION-NOTES.md`, `crates/dare-agent-security-cli/tests/cycle006_reconcile.rs` |
| 2 | Core independent of Cycle 005 | `dare-coverage` has no runtime dep on `dare-mcp-lab`; adapter is `integrations/cycle-005/` |
| 3 | Property registry | `schemas/coverage/v1/registry.json`, `crates/dare-coverage/src/property.rs` |
| 4 | Profile schema | `schemas/coverage/v1/profile.schema.json`, `profiles/mcp-security-baseline.json` |
| 5 | Applicability engine | `crates/dare-coverage/src/applicability.rs` |
| 6 | Assessment plan before execution | `build_assessment_plan` in `plan.rs` |
| 7 | CoverageStatus ≠ Verdict | `status.rs` vs `dare_security_evidence::Verdict` |
| 8 | Invalid status/verdict fail | `math.rs` tests `invalid_final_combinations` |
| 9 | Distinct NA / NT / OOS / BLOCKED | `CoverageStatus` enum + fixtures |
| 10 | Denominator documented and tested | `docs/assessment-coverage.md`, `DENOMINATOR_DOC`, `denominator_excludes_na_and_oos` |
| 11 | Required coverage measurable | `CoverageReport.required_coverage` |
| 12 | Evidence correlation | `correlate.rs` requires evidence ids for confirmed verdicts |
| 13 | CI reports profile/coverage | `summary_markdown`, Action optional inputs |
| 14 | Threshold deterministic | `evaluate_gate`, CLI `--min-required-coverage` |
| 15 | ROE BLOCKED ≠ NOT_APPLICABLE | fixture C + applicability tests |
| 16 | Untested applicable ≠ PASS | `finalize_row` → NOT_TESTED |
| 17 | Deterministic rationale | `PlannedProperty.rationale` |
| 18 | Profiles are data | JSON schema `additionalProperties: false`; adversarial extra `script` rejected |
| 19 | Local fixtures without lab | `fixtures/coverage/`, `tests/coverage_fixtures.rs` |
| 20 | Cycle 005 adapter optional for core | Unmapped 007–010; core tests pass without lab types |
| 21 | This proof | `PROOF.md` |

## Ralph Loop

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Out of scope (unchanged)

Agent Attack Graph, public benchmark corpus, dashboard, Marketplace publish.
