# Cycle 020 — Hotfix 002: Subject-Keyed Positive Coverage

**Status:** IMPLEMENTED — REVIEW REQUIRED
**Branch:** `hotfix/cycle-020-subject-keyed-coverage`
**Baseline:** `main @ 6f6aa37852a9f725c645b2b480f5711c172017f2`

## Finding addressed

The post-merge audit of PR #42 found a second false-PASS class: positive coverage was existential at invariant scope. In multi-subject runs, one valid peer/message/exchange could satisfy `any(...)` while another applicable subject had missing or undecided evidence.

This violated the Cycle 020 aggregation rule `missing evidence must not be collapsed to PASS`.

## Remediation

`crates/dare-a2a-security/src/coverage.rs` now evaluates positive coverage universally across the applicable subjects of each invariant rather than asking whether any positive observation exists.

Key bindings:

- I01 — every observed Agent Card must carry at least one local binding comparison.
- I02 — every peer identity must be fully bound and have VALID authentication evidence for the same `peer_id`.
- I03 — every message must have VALID authentication evidence bound to the same `message_id` and exact observed envelope.
- I04 — every exchange message must have a security-requirement context bound to the same `message_id` + `peer_id`, with the used mechanism fully established.
- I05 — every observed skill invocation must have a decidable subject/grant decision.
- I07 — every observed task must have exactly one context id and one initiating principal before positive coverage is allowed.
- I09 — every tenant subject must positively match policy and be positively permitted to reach its peer.
- I10 — every data-scope subject must be positively within its peer ceiling.
- I11 — every applicable repeated state-changing subject must be positively proven replay-safe.
- I12 — every protocol subject must be decidable.
- I14 — every push configuration must have an approved destination and VALID recorded destination verification.

I06, I08 and I13 remain observation-only boundaries: they do not borrow approval evidence from another subject and do not require a second policy-side channel to decide their local observation semantics.

## Regression tests added

The coverage test module now includes explicit cross-subject regressions for:

- one VALID peer plus a second peer with no authentication => INCONCLUSIVE;
- one authenticated message plus a second unauthenticated message => INCONCLUSIVE;
- one established security requirement plus a second uncovered exchange => INCONCLUSIVE;
- one decided skill authorization plus an undecided invocation => no positive coverage;
- one decided tenant binding plus an undecided tenant subject => no positive coverage;
- one decided data-scope subject plus an undecided one => no positive coverage;
- one decided protocol subject plus an undecided one => no positive coverage;
- push destination approval with UNRECORDED destination verification => INCONCLUSIVE.

## Safety / compatibility

Unchanged:

- all 14 invariant IDs and meanings;
- public `AGENT.A2A.*` property IDs;
- FAIL precedence;
- Cycle 006 applicability semantics;
- Cycle 018 aggregation ordering;
- local/offline-only boundary;
- no network, credential acquisition, remote key resolution, shell execution or target state change;
- no Cycle 021/022/023 implementation.

## Verification note

The GitHub connector cannot execute the Rust workspace. This hotfix therefore requires the standard repository gates on the branch before merge:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p dare-a2a-security
cargo test --workspace
cargo audit
python scripts/run-ci-job-locally.py .github/workflows/ci.yml a2a-security-2026
```

The hotfix must not be considered merge-ready until these gates pass and any compile/test defects introduced by the remediation are corrected without weakening the subject-keyed semantics.
