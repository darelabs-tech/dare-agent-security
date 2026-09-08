# task-016 — Implement local provenance subject/artifact/builder binding

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-10, AC-31, AC-32, AC-33

## Evidence

`src/provenance.rs`.

```text
digest presence     != provenance
provenance presence != trusted provenance
```

A digest says what an artifact *is*; provenance says where it came from and who built it. A component can have a perfect digest and no provenance at all.

The second distinction costs more. `provenance_present == true` establishes nothing on its own — it says a record exists. What establishes something is **three independent bindings**:

**AC-31 — the subject is the component being assessed.** `binds_subject()`. The binding an engine is most likely to skip, because a provenance record found *near* a component looks like a record *about* it. `a_record_about_another_component_does_not_bind` asserts an unmatched record lands in `unbound_provenance_ids` and leaves `has_provenance()` false.

**AC-32 — the subject digest is the artifact digest.** `binds_digest()` returns `Option<bool>`: `None` when either side recorded no digest, `Some(false)` when both recorded one and they differ. Those are different findings. `a_record_naming_a_different_digest_is_provenance_for_a_different_build` — reporting that as satisfied would report the substitution as the thing it substituted for.

**AC-33 — the builder is one a local policy approved.** The record *names* a builder; `TrustPolicy::approves_builder` decides whether that name means anything. The record cannot approve itself: `provenance_presence_carries_no_trust_field` asserts a `trusted: true` field fails to decode. A record that could assert its own trust would make the policy decorative.

**Several records for one component agree if any of them does.** `several_records_for_one_component_agree_if_any_of_them_does`. A merged document set normally carries more than one record per component, and requiring all of them to bind would report a finding whenever a second, weaker record existed — a false FAIL that trains operators to ignore the check.

**AC-10 — no remote provenance retrieval.** Records arrive in the local evidence bundle. Nothing in this module has a fetch path.
