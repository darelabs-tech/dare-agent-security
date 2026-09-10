# hotfix-001 — Enforce the Cycle 020 positive authentication contracts

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security
**Kind:** post-merge security remediation, not approved cycle scope

Cycle 020 originally completed 57/57 tasks. That count is unchanged. This record
sits alongside the task files rather than extending them, because the work is
remediation of shipped behaviour rather than a task anyone approved.

## Objective

Remove the false-`PASS` paths in I02, I03 and I04 by making the implementation
meet the DESIGN it was approved against. The DESIGN is normative here: it was not
edited to accommodate what the code did.

## Files changed

- `crates/dare-a2a-security/src/source.rs` — `BindingCheck`; five reference behaviours
- `crates/dare-a2a-security/src/policy.rs` — `expected_logical_agent`, `requires_delegated_identity`
- `crates/dare-a2a-security/src/observation.rs` — identity bindings, `verification_status`, two contract methods
- `crates/dare-a2a-security/src/coverage.rs` — the I02, I03 and I04 positive contracts
- `crates/dare-a2a-security/src/invariant.rs` — three new concrete failures
- `crates/dare-a2a-security/src/corpus.rs` — A2A-LAB-059..063
- `crates/dare-a2a-security/src/simulated.rs` — staging for the new behaviours
- `crates/dare-a2a-security/src/positive_evidence.rs` (new) — the 30-test matrix
- `crates/dare-a2a-security/src/capture.rs`, `lib.rs` — construction and module wiring
- `.github/workflows/ci.yml` — three steps in `a2a-security-2026`
- `DARE/cycles/020-a2a-inter-agent-security/HOTFIX.md` (new), `REGRESSION.md`, `PROOF.md`

## The bugs were reproduced before anything was fixed

Commit `8960fe5` is deliberately red. It states the contract and fails against
the merged implementation:

```
I02 on INDETERMINATE: PEER_IDENTITY_BOUND held ...        left: Pass  right: Inconclusive
I03 on INDETERMINATE: MESSAGE_AUTHENTICITY_ESTABLISHED ... left: Pass  right: Inconclusive
a verification for another scheme satisfied the requirement: left: Pass right: Pass
an undecided invariant passed:                              left: Pass right: Pass
```

6 failed, 7 passed. Fixing first and describing afterwards would have left the
defect as an assertion in a commit message instead of a reproducible artifact.

## Root cause

`may_satisfy_positive_evidence` was already correct and already had a passing
test. The evaluators and coverage contracts simply never called it: I02 asked
`is_recorded_evidence()` ("was it checked?", true of `INDETERMINATE`), and
I03/I04 asked only whether a comparison had been made, never what it concluded.

A correct predicate with a green test proves nothing about the call sites that
ignore it. That is the reusable lesson from this hotfix.

## Commands executed

```
cargo test -p dare-a2a-security --lib positive_evidence     # red, then green
cargo test -p dare-a2a-security
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
python scripts/k20/assert_no_real_credentials.py
python scripts/k20/verify_proof_citations.py
python scripts/run-ci-job-locally.py .github/workflows/ci.yml a2a-security-2026
cargo run -p dare-agent-security -- validate a2a --scenario A2A-LAB-0{59..63} --mode simulated
```

## Real result

```
cargo test -p dare-a2a-security ......... 356 passed, 0 failed
cargo test --workspace .................. 3759 passed, 0 failed
cargo fmt --all -- --check .............. clean
cargo clippy --workspace ................ 0 issues
cargo audit ............................. exit 0, 1 allowed warning (yanked chacha20)
assert_no_real_credentials.py ........... pass (33 shipping, 5 test, 2 artifacts)
verify_proof_citations.py ............... pass (103 names against 754 tests)
a2a-security-2026 ....................... 29/29 steps passed

A2A-LAB-059 -> INCONCLUSIVE | PEER_IDENTITY_BOUND
A2A-LAB-060 -> FAIL         | PEER_IDENTITY_BOUND
A2A-LAB-061 -> FAIL         | PEER_IDENTITY_BOUND
A2A-LAB-062 -> INCONCLUSIVE | MESSAGE_AUTHENTICITY_ESTABLISHED
A2A-LAB-063 -> INCONCLUSIVE | SECURITY_REQUIREMENT_SATISFIED
```

## Tests executed

30 new tests in `positive_evidence`, 5 new A2A-LAB vectors, and the whole
workspace. The new tests were checked for teeth by mutation rather than trusted:
forcing `binding_established()` true fails four of them; making
`requirement_established()` ignore the verification status fails six.

## Deviations and corrections found along the way

**The FAIL steps first expected CLI exit 1.** The CLI returns 2 for a concrete
failure. Caught by running the scenario before writing the assertion, not after.

**Staging A2A-LAB-063 was refused at admission.** The first attempt gave the
peer an API-key verification carrying a delegated subject, and the bundle
correctly rejected it: an API key authenticates a service and carries no user,
so claiming one is a contradiction. The vector now varies the scheme id and
holds the kind — which is the binding actually under test. The refusal was
right and stayed as it was.

**One fixture policy gained two fields.** `base_policy()` in `simulated.rs` now
declares `expected_logical_agent` and `requires_delegated_identity`. This is
supplying evidence the strengthened contract requires, not weakening a test: no
expectation, classification or verdict was changed anywhere in the corpus, and
`corpus.rs` needed no edit for the existing 59 vectors to keep passing.

## Review result

**REVIEW PASS** — the fourteen invariants, their semantics and ids, the four
verification statuses, the public `AGENT.A2A.*` property ids, FAIL precedence,
cycle ownership and the offline boundary are all unchanged. Tenant remains with
I09 and skill authorization remains with I05.
