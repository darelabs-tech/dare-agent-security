# task-005 — Define closed component/type schemas and canonical identifier primitives

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-15, AC-16, AC-17, AC-18, AC-19, AC-20, AC-21

## Evidence

`src/source.rs`, `src/component.rs`, `src/identity.rs`, `src/canonical.rs`. `cargo test -p dare-supply-chain-security` → **105 passed, 0 failed**; clippy clean.

**AC-16 — all fourteen classes**, and no fifteenth. `ComponentType` has no `OTHER` variant, checked by `there_is_no_catch_all_component_type`: admitting a component whose class nobody could read means every type-specific evidence requirement goes unasked while the component sits in the graph looking assessed.

**AC-17, AC-18, AC-19 — identity is graded, not binary.** `IdentityStrength` is ordered — `NameOnly < NameAndVersion < Coordinate < ImmutableDigest` — and only the last `is_immutable()`. Evaluators ask for the strength a situation needs rather than for "an identity".

- `a_name_alone_is_never_an_immutable_identity`
- `a_name_and_version_are_not_an_immutable_artifact` — two builds can carry one version and be different bytes, which is the substitution artifact integrity exists to catch
- `mutable_references_are_recognised_in_both_families` — named moving targets (`latest`, `main`, `nightly`) *and* range expressions (`^1.2`, `~1.2`, `>=1.0`, `1.x`, `1.2 || 1.3`). Both resolve to something different tomorrow.
- `a_mutable_reference_plus_a_digest_still_identifies_the_artifact` — the benign control. Tagging an image `latest` is not a finding when the digest is recorded: the tag moves, the digest does not, and an engine reporting it would train readers to ignore it.

**A document cannot declare its own coordinate immutable.** `ComponentIdentifier.immutable` is ignored; the *shape* of the value decides (`?digest=`, `@sha256:`). Asserted by `a_document_cannot_declare_its_own_coordinate_immutable`, because otherwise a document could assert the one thing this module exists to determine.

**AC-20 — digest algorithms are allowlisted with pinned lengths.** `DigestAlgorithm` is an enum, so `md5` fails to decode rather than becoming an opaque label that looks like integrity evidence. Length is checked per algorithm, and uppercase hex is **refused rather than normalized**: `AB…` and `ab…` are the same digest and compare as different strings, so quietly normalizing would work while leaving two documents free to disagree about which form is stored.

**AC-21 — duplicate conflicting identities fail closed, in both directions.** `find_collisions` reports two opposite failures with different reasons: same id describing different artifacts (a finding about one silently omits the other), and one artifact under two ids (approving one leaves the other unapproved while a reader sees it as covered). `the_same_component_listed_twice_identically_is_not_a_collision` is the control — deduplication must stay quiet, or the check fires on every merged document.

**The semantic key is format-independent**, asserted by `the_semantic_key_is_independent_of_which_format_supplied_it`. If it included the evidence source, cross-format equivalence would be comparing parsers rather than descriptions.

## A structural guard worth naming

`SourceTrustAssessment::validate` refuses `TrustClass::Approved` established by a CycloneDX or SPDX source. That is the structural form of "a BOM claiming `trusted=true` does not establish trust": the combination cannot exist in the model, so no evaluator has to remember to check it.
