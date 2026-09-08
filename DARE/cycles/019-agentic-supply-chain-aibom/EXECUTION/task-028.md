# task-028 — Implement artifact-integrity and source-trust evaluators

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-20, AC-33, AC-35, AC-36, AC-49

## Evidence

`src/invariant.rs` — `artifact_digest_bound`, `source_trust`.

**AC-20 — integrity fires on compared-and-differed, never on nothing-to-compare.** `approved_digest_bound == Some(false)` is a substitution; `None` means the manifest approved no digest, which is a gap the coverage contract reports. Collapsing them would make every component without an approved digest look like an attack.

`a_substituted_artifact_fails_integrity_and_cites_its_evidence` asserts the FAIL, the named component and a non-empty deciding-evidence list — a finding with no deciding evidence is an assertion rather than a finding.

**AC-36 — an unapproved origin fails deterministically.** `an_unapproved_origin_fails_and_an_absent_policy_does_not` asserts both halves in one test:

- a component from `unknown-vendor` under a policy that names approved suppliers is a FAIL, and the reason names the vendor;
- the same component with **no policy** is not a FAIL.

The second half is the one that matters. Denying everything when nobody wrote a policy would make every component a finding, which is indistinguishable from a broken engine, and an operator learns to ignore the output either way.

The evaluator reads `policy_approves_origin == Some(false)` and skips when `policy_present` is false, so the distinction is structural rather than a rule each reader must remember.

**AC-33/AC-35 — trust is separate from verification.** The source-trust evaluator reads origin claims and policy approval. Whether a signature verified is a different field, evaluated by a different invariant, and `SourceTrustAssessment::validate` already refuses an `Approved` class that arrived from a BOM rather than a local approval — so this evaluator cannot be handed a trust class the document granted itself.
