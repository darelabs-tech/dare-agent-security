# task-013 — Implement canonical component identity resolver

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-17, AC-18, AC-19, AC-20, AC-21

## Evidence

`src/identity.rs`.

```text
component name        != component identity
version string        != immutable artifact
same name and version != same artifact
```

Three of the eleven rules the crate is built on land in this module, and they are the ones a reviewer is most likely to wave through.

**AC-19 — a version string is not an immutable artifact.** `IdentityStrength` is ordered `NameOnly < NameAndVersion < Coordinate < ImmutableDigest`. `is_mutable_reference()` returns true for `latest`, floating tags and version ranges; `coordinate_is_immutable()` returns true only for a coordinate carrying a digest qualifier. A purl with a version is **not** immutable — two builds can and do publish the same version — and treating it as immutable is the substitution this cycle exists to detect.

**AC-21 — conflicting canonical identities fail closed.** `find_collisions()` checks **both directions**: one identity claimed by two different artifacts, and one artifact claiming two different identities. Checking only the first direction is the natural implementation and it misses the case where an attacker splits one artifact across two identities to make each look unremarkable.

`assert_no_collisions()` is called from `EvidenceBuilder::build`, not from the importers, because the collision only exists once the documents are together.

**AC-17/AC-18 — identity is semantic, not textual.** `CanonicalIdentity::semantic_key` is format-independent, so the same component imported from CycloneDX and from SPDX resolves to one identity rather than two.

**AC-20 — digest handling.** Covered jointly with task-012: allowlisted algorithms, pinned hex lengths, lowercase-only values.
