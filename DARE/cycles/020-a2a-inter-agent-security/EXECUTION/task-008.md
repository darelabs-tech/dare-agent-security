# task-008 — Define authentication verification evidence semantics

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Record what another verifier concluded, and make it impossible for this engine to be mistaken for that verifier.

## Files changed

- `crates/dare-a2a-security/src/authentication.rs` (new — `PeerAuthenticationEvidence`, `MessageAuthenticationEvidence`)

## The four statuses, and the two that can never pass

`VerificationStatus` is `VALID`, `INVALID`, `INDETERMINATE`, `UNRECORDED`, with three separate predicates:

- `may_satisfy_positive_evidence()` — only `VALID`
- `is_concrete_failure()` — only `INVALID`
- `is_recorded_evidence()` — `VALID` and `INVALID`

`INDETERMINATE` and `UNRECORDED` satisfy none of them. Missing evidence cannot be silently read as success, and equally cannot be reported as a finding — it is a gap, and coverage is what says so.

## Two refusals that are structural

`PeerAuthenticationEvidence::validate` refuses `EvidenceSource::AgentCard`. A card describes what a peer says it supports; it cannot be the record of that peer authenticating — *declared security scheme != successful authentication*.

It also refuses a delegated subject under `OAUTH2_CLIENT_CREDENTIALS`, `API_KEY` or `MUTUAL_TLS`. Those schemes carry no end-user subject, so a record claiming one is a record that invented it. `SecuritySchemeKind::may_carry_delegated_subject()` is the single place that judgement lives.

`MessageAuthenticationEvidence::covers()` compares the recorded covered-envelope digest against the observed envelope. A signature over a message is not a signature over this message, and without that comparison the two are indistinguishable.

## Commands executed

```
cargo test -p dare-a2a-security authentication
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

9 tests passing.

## Evidence

```
cargo test -p dare-a2a-security authentication::
test result: ok. 9 passed; 0 failed
```

## Review result

**REVIEW PASS**
