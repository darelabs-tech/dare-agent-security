# task-029 — Implement attestation-binding evaluator

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-34, AC-35, AC-36, AC-37, AC-49

## Evidence

`src/invariant.rs` — `attestation_bound`.

**AC-34 — a misbound statement fails even when a correct one sits beside it.** `a_misbound_attestation_fails_even_when_a_valid_one_is_beside_it`. An attestation naming the component while binding a different artifact's digest is **worse than none**, because it looks like coverage: a reader scanning for "is this component attested?" sees yes.

The evaluator therefore reports `misbound_attestation_ids` unconditionally, rather than only when no correctly bound statement exists. The alternative would let an attacker neutralize the check by adding a valid statement next to the misbound one.

**AC-35/AC-36 — a valid signature is not an approved signer.** `an_unapproved_signer_fails_however_valid_the_signature_is`. The verification status says a local check succeeded; `TrustPolicy::approves_signer` says whether that signer was approved. Both are required, and the finding names the signer.

`unapproved_signer_ids` is populated only when a policy exists, so an absent policy produces a gap rather than a finding against every signer.

**AC-37 — zero remote verification.** No Fulcio, no Rekor, no OCI registry, no transparency log, no key server. Structural: the crate declares no HTTP, OCI or Git dependency (`this_crate_declares_no_fetch_dependency_of_its_own`), `transparency_log_url` and its neighbours are in `FORBIDDEN_FETCH_FIELDS`, and `no_constant_in_this_crate_holds_a_reachable_endpoint` asserts no `const` or `static` holds a place a fetch could start from.

Sigstore and Cosign are recorded as INFORMATIVE in the cycle's standards provenance, not normative: this engine reads their evidence shapes and never performs their protocols.
