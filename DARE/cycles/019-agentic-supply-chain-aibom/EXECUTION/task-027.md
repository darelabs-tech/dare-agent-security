# task-027 — Implement component identity and mutable-reference evaluators

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-17, AC-18, AC-19, AC-21, AC-49

## Evidence

`src/invariant.rs` — `identity_unambiguous`, `mutable_reference`.

## A design correction this task required

`SupplyChainEvidence::validate` previously called `assert_no_collisions`, refusing a bundle whose identities collided. That made invariant 3's FAIL path **unreachable**: a fixture staging one artifact under two ids would have been refused at import and reported ERROR — a run that could not observe — when the engine had in fact observed the ambiguity perfectly well.

An operator would have seen a broken run instead of the finding.

`validate` no longer refuses it. The ambiguity is retained, `identity_collisions()` reports it, and invariant 3 evaluates it as a FAIL. `a_collision_between_two_documents_is_visible_at_merge_time` now asserts the bundle builds and the collision is reported.

This is safe because the merge already unified same-id rows: the remaining case is one artifact under two *distinct* ids, and both ids stay resolvable, so every other invariant still reads the row it meant to. `assert_no_collisions` remains public for callers that genuinely want to refuse.

**AC-21 — the finding names both sides.** `one_artifact_under_two_ids_fails_identity_and_names_both` asserts the reason names `react` and `react-mirror`, and that the violation cites **two** deciding observation digests. An ambiguity finding citing one side is not evidence of an ambiguity.

Collisions are computed from the `ComponentContext` observations rather than from the evidence bundle, so the citation is exactly the two contexts that disagree.

**AC-19 — a mutable reference is only a finding when nothing else pins the artifact.** `a_floating_tag_with_no_digest_fails_and_one_with_a_digest_does_not`. A container image tagged `latest` *with a digest beside it* is pinned by the digest; reporting it would be reporting a naming convention, and an operator who sees that finding learns to ignore the check.

The evaluator skips a component whose `identity_strength.is_immutable()` or which has a digest context, and fires only when the mutable reference is genuinely standing in for identity.

**AC-17/AC-18 — identity is semantic.** The comparison is over `semantic_key`, which is format-independent, so the same component imported from CycloneDX and SPDX is one identity rather than a self-collision.
