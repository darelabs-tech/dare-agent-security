# Cycle 007 — DARE Proof

> Cycle: `007-mcp-security-benchmark-corpus-methodology`
> Date: 2026-08-20
> Branch: `agent/cycle-007-mcp-security-benchmark-corpus-methodology`

| # | Criterion | Evidence |
|---|-----------|----------|
| 1 | Post-Cycle-006 reconciled | `IMPLEMENTATION-NOTES.md`, `tests/cycle007_reconcile.rs` |
| 2 | Corpus Manifest schema | `schemas/benchmark/v1/corpus-manifest.schema.json` |
| 3 | Benchmark Run schema | `schemas/benchmark/v1/benchmark-run.schema.json` |
| 4 | Benchmark Record schema | `schemas/benchmark/v1/benchmark-record.schema.json` |
| 5 | Pinned revisions | commit pattern `^[a-f0-9]{40}$`; pilot test |
| 6 | Fork/duplicate handling | `lineage.rs`, pilot mirror exclusion test |
| 7 | Inclusion/exclusion documented | manifest `selection` + `docs/benchmark-methodology.md` |
| 8 | Sampling limitations | methodology + aggregate disclaimer |
| 9 | Profile/version explicit | `BenchmarkRun.assessment_profile` |
| 10 | Cycle 006 contracts reused | `CoverageStatus` / `Verdict` in records |
| 11 | Coverage eligibility threshold | `benchmark-policy.json` |
| 12 | Blind statuses visible | aggregate `blind_spots` |
| 13 | Property-specific denominators | `aggregate.rs` |
| 14 | Human validation +/- | `validation.rs` + pilot test |
| 15 | Cycle 005 ground truth | notes; not used as prevalence |
| 16 | Reproducibility manifest | `BenchmarkRun` digests |
| 17 | Deterministic records | offline runner |
| 18 | Finding vs affected counts | aggregate fields |
| 19 | Confidence threshold | policy + eligibility |
| 20 | Disclosure policy | `docs/responsible-disclosure.md` |
| 21 | Dynamic disabled by default | hostile_runner test |
| 22 | Pilot without unauthorized remote | fixture corpus + offline runner |
| 23 | Regression tests | `dare-benchmark` tests + CI job |
| 24 | This proof | `PROOF.md` |
| 25 | APPROVAL present for execution | `APPROVAL.md` (execution round) |

## Ralph Loop

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p dare-benchmark
```
