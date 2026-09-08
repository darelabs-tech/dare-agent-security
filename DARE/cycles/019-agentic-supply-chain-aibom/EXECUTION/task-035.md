# task-035 — Implement REPLAY adapter with semantic evidence binding

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-55, AC-56, AC-57

## Evidence

`src/replay.rs`.

## The thing a recording must not bring with it

A capture records what a system **contained**. It must not also record what was **approved**.

A `SupplyChainEvidence` bundle has a `manifest` field, so a capture carries one. If replay accepted it, whoever produced the capture would supply both the evidence and the policy it is judged against — and every invariant that compares observation against approval would be comparing a capture with itself. A capture could approve its own components, its own builder and its own signer.

`ReplayAdapter` therefore **discards** the recorded manifest and applies a local one passed as a separate constructor argument. `a_recorded_manifest_cannot_approve_its_own_components` stages exactly the attack: the capture approves the artifact it recorded, the local policy approves a different one, and the test asserts the run reports FAIL.

This is the Cycle 017 lesson in this cycle's vocabulary — a recorded observation is evidence about what happened, not the authority that says what was allowed.

## Semantic binding

Matching a scenario id is identity, not evidence. `a_capture_of_another_scenario_is_refused` checks the id, and `a_capture_describing_a_different_system_is_refused` checks the harder case: the id matches and the recording is of something else entirely. A capture that describes none of the components the local policy declares is refused, because replaying it under these approvals would report on a system nobody here runs.

## What a capture cannot claim

- **Its own mode.** `a_capture_cannot_ask_to_be_run_in_another_mode` — `mode` is fixed to `REPLAY`.
- **Production status.** `a_capture_cannot_declare_itself_production_evidence` — `synthetic` must be `true`. A replayed observation is a recording, and a report must not present it as something observed now.
- **A verdict.** `a_capture_cannot_carry_a_verdict` — `deny_unknown_fields` refuses `expected_verdict`.

## Re-admission

A capture is a file like any other and can have grown past a bound since it was taken, so components and edges are re-admitted through the ledger rather than trusted. `with_recorded_document` carries the recorded document digest forward rather than recomputing it: the bytes are gone, and a digest computed over the reconstructed bundle would be a digest of something the run never saw.
