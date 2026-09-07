# task-042 — Multi-violation capture and redaction

**Status:** DONE - REVIEW PASS

Preserve independent violations from the same trial and redact before persistence. Every deterministic violation must bind to retained deciding evidence digests.

## Evidence

`crates/dare-mcp-auth-security/tests/violations_and_hygiene.rs` — 11 tests, all passing.

**All of them, not the first.** Lab 034 is one flow that mixes up the response issuer, presents a token minted for another resource, and forwards the inbound credential upstream. An engine stopping at the first finding would report a smaller problem than the one it saw: the operator fixes the issuer, re-runs, learns about the audience, fixes that, learns about the credential — three round trips that each look like progress. The suite asserts all three invariants fail independently from the same trial, that evaluation order changes no verdict, and that `PKCE_BINDING_PRESERVED` — which lab 034 does not breach — still passes on its own, so failures cannot bleed between evaluators.

**Every violation binds to its evidence.** `deciding_event_digests` non-empty, a reason, and the subject the finding is about — lab 010's violation names `as-attacker` rather than reporting that an issuer was wrong. A finding with no deciding evidence is an assertion, not a finding.

**Stop-on-first-fail does not erase what caused it.** The stop is a decision about *later* trials; `stopping_on_first_fail_never_discards_the_evidence_that_caused_it` asserts the failing trial keeps its violations, its event digests and its events.

**Redaction happens before anything is kept, not on the way out.** `EvidenceText::from_raw` masks at construction — masking at render time would leave the unmasked value in memory, in a serialized record, and in whatever read the struct first. The suite sweeps every retained surface across all 34 evaluable labs: outcome reasons, violation reasons, details, subjects, the serialized observations, and the result artifact of a *failing* run, which is the place most likely to quote what breached. Nothing carries a canary, a credential marker, or a reachable target.
