# task-048 — Implement `A2aSecurityResult`, bounded artifacts and Cycle 001 evidence bridge

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Produce the run artifact, the operator summary, and Cycle 001 evidence records — each stating exactly what the run established and nothing more.

## Files changed

- `crates/dare-a2a-security/src/result.rs` (new — `A2aSecurityResult`, `PeerRecord`, `ExchangeRecord`, `DocumentRecord`, `run_scenario`, `render_summary`, `assert_summary_is_bounded`)
- `crates/dare-a2a-security/src/evidence_bridge.rs` (new — `build_invariant_evidence`, `build_evidence`, `evidence_id`)
- `crates/dare-a2a-security/src/lib.rs`

## The claim the artifact makes

`reason_for` writes the qualification into the artifact rather than leaving it to a reader who may only ever see the JSON:

> all N applicable invariant(s) remained satisfied under the local evidence analysed; this is a statement about that evidence, not that the remote agent is secure.

`a_clean_run_states_what_its_pass_covers_and_what_it_does_not` asserts that sentence is present. It is the single most expensive sentence this engine could get wrong.

## Three Cycle 019 corrections carried in from the start

**`violations` is always serialized.** Cycle 019 skipped the empty list and broke every CI assertion of the form `--count violations=0`. `violations_are_always_serialized_even_when_there_are_none` asserts the field exists and equals `[]` on a clean run — a field a check counts has to exist for the check to mean anything.

**`applicable` is distinct from `coverage_satisfied`.** `undecided()` returns only the outcomes that *apply* and could not be decided, so an operator's gap list does not fill with invariants that had no subject.

**The artifact accounts for itself.** The budget is a `snapshot()` taken after collection, and the CLI charges the result artifact's own bytes through `admit_output` before writing it (task-050).

## What the artifact deliberately does not carry

No message content. `the_artifact_carries_no_message_content` asserts no `content`, `body`, `text` or `payload` field appears — peer text in an artifact is attacker-chosen text in every downstream consumer of that artifact. Part *counts* are recorded; part *contents* are not.

The six peer identity fields stay separate. `the_six_peer_identity_fields_stay_separate_in_the_artifact` asserts `authorization_subject` is never the provider and never the logical agent — an artifact that flattened them into one `identity` would let a reader make the substitution the whole cycle is about.

## A harness failure still produces an artifact

Verdict ERROR, reason "no inter-agent conclusion is available in either direction", empty violations, empty documents. Returning nothing would let a caller that ignores errors record silence as success.

## A defect found and fixed in this task

`the_summary_never_claims_more_than_the_run_established` initially banned the phrase `agent is secure` and failed against the summary's own disclaimer — *"not a statement that a remote agent is secure"* contains it.

This is the same class as the `contains_bearer_credential` defect in task-018 and the `expected_audience` defect in task-040: a word-ban catches the document's own denial. `assert_summary_is_bounded` is now anchored on the **claim**, checking a sixty-character window before each occurrence for a negation. `the_summary_gate_refuses_a_claim_and_permits_its_denial` pins both directions with four cases — a gate that cannot let a document deny something forces the document to stop denying it.

The helper is public, because the CLI needs the same gate and two copies would drift.

## The evidence bridge

Fourteen `SecurityEvidence` records per run, one per invariant, so an operator filtering by property finds the invariant that decided their question rather than an aggregate to unpack.

Every record:

- targets `synthetic-a2a-inter-agent-lab`, never a deployment — an offline analysis filed against a real target would read as a statement about a live relationship
- carries all sixteen frozen relations and the offline execution note in `dare.a2a-security.v1`, so a consumer holding one record knows what the verdict means without finding this documentation
- names Cycles 013, 014, 015, 018 and 019 and states it takes verdict authority over none of them
- carries no `severity` — that is a judgement a consumer makes, and baking one in would make this engine's opinion look like a fact
- carries no standards `url` — a reference is not a retrieval target, and a URL there would be the first place somebody added a fetch
- passes Cycle 001 `validate_secret_safety` before it is returned

`an_undecided_record_is_not_applicable_and_never_a_pass` is the bridge's version of this cycle's central rule: an INCONCLUSIVE outcome reaches a Cycle 001 consumer as `evidence-insufficient` and `NOT_APPLICABLE`, never as `invariant-holds`.

## Commands executed

```
cargo test -p dare-a2a-security --lib result::
cargo test -p dare-a2a-security --lib evidence_bridge::
cargo test -p dare-a2a-security
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
cargo fmt --all
```

## Result

12 result tests and 10 bridge tests passing. Whole crate green: 297 unit + 13 A2A-LAB + 8 missing-evidence = 318 tests. Clippy clean under `-D warnings`.

## Evidence

```
cargo test -p dare-a2a-security
running 297 tests ... test result: ok. 297 passed; 0 failed
running 13 tests  ... test result: ok. 13 passed; 0 failed
running 8 tests   ... test result: ok. 8 passed; 0 failed
```

## Review result

**REVIEW PASS**
