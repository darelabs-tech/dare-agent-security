# Cycle 017 Follow-up — Replay Semantic Binding

**Date:** 2026-09-06

**Baseline:** `main @ e89791c40872006c6addf7a14d06f424ad69cac9`

**Branch:** `fix/cycle-017-replay-semantic-binding`

## Purpose

This follow-up preserves the historical Cycle 017 proof and records two defects found by post-merge review. It does not rewrite the original `PROOF.md` or `REGRESSION.md` as though the defects had never existed.

## Finding 1 — Replay could self-declare authorization-relevant query/candidate semantics

The replay trace was bound to a `scenario_id`, but its query and candidate observations were not compared with the scenario-approved query/candidate declarations before evaluation.

That allowed a same-scenario replay trace to attempt to widen or substitute authorization-relevant evidence such as:

- query id;
- collection scope;
- requested top-k;
- mandatory metadata filters;
- objective id;
- candidate membership or candidate document binding.

The result-set invariant also used the observed candidate set as the approved side of its comparison. An adapter-controlled observation must not define its own permission boundary.

### Correction

`RagTrace::assert_matches` now performs deterministic semantic binding before replay:

- every observed query id must exist in the scenario;
- collection ids, requested top-k, filter and objective must equal the approved query semantics;
- every observed candidate set must map to a scenario-approved candidate set;
- candidate authority is compared by `(chunk_id, document_id)` membership; score/order are excluded because they are ranking evidence, not authority;
- result-set and filter-decision query ids must refer to scenario-declared queries.

`RESULT_SET_WITHIN_APPROVED_CANDIDATES` now reads candidate authority directly from `scenario.candidate_set(query_id)`, never solely from the adapter observation.

Added regression cases cover:

- unknown/shadow query id;
- collection widening;
- top-k widening;
- mandatory-filter removal;
- candidate-set expansion;
- same scenario id with changed approved query semantics;
- score-only changes remaining allowed because score is not authority.

## Finding 2 — Forbidden fallback finding could have no deciding event digest

The `RETRIEVAL_FALLBACK_DOES_NOT_WIDEN_AUTHORITY` branch for `fallback.allowed == false` constructed a violation with an empty `deciding_event_digests` list.

That contradicted the Cycle 017 evidence contract: a security finding without a retained deciding observation is an assertion, not evidence.

### Correction

The finding now binds to retained observations that establish the decision:

- retrieval policy;
- ranked result sets marked as fallback;
- retrieved chunks marked as fallback.

The regression test for violation evidence was expanded across all reachable failing reference behaviours and verifies both:

1. every produced `RagViolation` has at least one deciding-event digest; and
2. every cited digest belongs to an event retained by that trial.

A dedicated forbidden-fallback regression pins the repaired branch.

## Scope and safety

No live/remote capability was added.

The approved modes remain:

- `REPLAY`
- `SIMULATED`
- `LOCAL_SYNTHETIC`

No provider, vector-store, HTTP, credential or command surface was added.

## Validation status

The ChatGPT execution environment used for this follow-up could write through the authorized GitHub connector but could not resolve `github.com` from its local container, so local Cargo/workflow execution was not available there.

Accordingly, no local gate result is claimed in this record. The pull request is opened once so the repository's real GitHub Actions workflow can provide executed evidence. CI results must be inspected before merge.
