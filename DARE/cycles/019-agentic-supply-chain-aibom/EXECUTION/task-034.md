# task-034 — Implement STATIC adapter/import execution path

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-55, AC-56, AC-57, AC-58

## Evidence

`src/harness.rs` — the `SupplyChainAdapter` trait and `StaticAdapter`.

**The trait cannot report a verdict.** Its only output is a `SupplyChainEvidence` bundle, and that type has no verdict, violation, finding or expected-outcome field. `the_adapter_contract_has_no_way_to_report_a_verdict` asserts the serialized bundle carries none of them.

**AC-58 — documents are classified by filename suffix, never by content.** `an_unclassifiable_file_is_refused_rather_than_sniffed`. Guessing what a document is from what it contains gives an attacker a say in **which parser runs**, and every parser has a different attack surface. A file that matches no known suffix is refused rather than tried against each importer in turn.

**AC-56/AC-57 — the filesystem is touched in one direction.** The adapter opens files under a root the caller named and writes nothing. There is no network path: the crate declares no client, and a `purl` or `downloadLocation` inside an imported document is stored and never resolved.

**Path containment has two halves.** The scenario's file names are already refused if they are path-shaped, and `resolve` adds the second half: the canonicalized path must still be under the canonicalized root, because a symlink can leave a directory without the name ever looking like it does. `a_path_shaped_evidence_name_is_refused_before_anything_is_opened` covers both `../` and `..\`.

**Errors name the file the caller asked for, not the resolved path.** `a_missing_file_is_refused_without_echoing_the_system_path`. An error message is a persistence surface: quoting a resolved path prints a directory layout the operator did not ask to publish.

**Two manifests are refused rather than merged.** `two_manifests_are_refused_rather_than_merged`. A deployment has one approved policy; merging two would silently widen it, and nothing decides which one was meant.

**The manifest is applied last, whatever order the files were listed in.** `the_manifest_is_applied_after_every_document_whatever_order_it_was_listed_in` runs both orderings and asserts both reach PASS. The manifest is the only input that can raise trust, and applying it before every component exists would leave later components unapproved for no reason an operator could see.

**AC-55 — STATIC is the only adapter whose evidence is not synthetic.** `static_evidence_is_not_marked_synthetic_and_every_other_adapter_is`. Local documents describe a real deployment; every other adapter stages something, and the trait's default is the answer that says so.
