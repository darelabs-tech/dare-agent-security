# task-009 — Implement hostile secret/executable/path/bidi/remote-action refusal layer

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-59, AC-60, AC-61, AC-62, AC-63, AC-69, AC-83

## Evidence

`src/schema.rs` (the document gate) and `src/canonical.rs` (identifier safety).

A bill of materials is a file somebody else produced, often by an unaudited tool, describing artifacts from places nobody controls. It is the widest input surface the engine has, so there are **three gates**, each catching what the others structurally cannot: the sweep sees every value at every depth including inside fields no model has a place for; the schema closes the object; `deny_unknown_fields` catches anything that reached the decoder despite both.

**AC-61 — credential fields refused by name, whatever they hold.** 24 field names, normalized for `-` and spaces first (`a_hyphenated_or_spaced_field_name_is_normalized_before_comparison`), plus 12 value markers. `a_credential_field_is_refused_even_when_empty`: the field is what is wrong, and admitting the empty case leaves it available for the next author.

`every_credential_marker_is_lowercase` prevents the Cycle 018 bug where `AKIA` and `eyJhbGci` were compared against a lowercased string and never matched. The list looked right.

**AC-62 — executable and callback fields refused.** 18 names. A bill of materials describes what a system is made of and never what to run.

**AC-59 — external references stay inert, and this is the hard part.** `ordinary_bom_coordinate_fields_stay_readable` asserts that `purl`, `downloadLocation`, `externalReferences` and `repository` all pass. Refusing them would refuse every real document. What *is* refused is a field whose name asserts an **action** — `fetch`, `download_url`, `pull_policy`, `auto_fetch`, `transparency_log_url` — because a coordinate names a location and an instruction does not.

**AC-63 — path traversal and bidi spoofing refused.** In `canonical.rs`: control characters forge log lines; bidirectional overrides make a string render differently from how it compares, so two components look identical in a report and are different rows in the graph. Leading and trailing whitespace is refused for the same reason — ` react` and `react ` are a duplicate-identity trap that costs nothing to close.

`ordinary_identifiers_stay_usable` is the control: purls, scoped packages, model ids, image tags and URNs all pass.

**AC-83 — a refusal never echoes what it refused.** `a_refusal_never_echoes_what_it_refused` in both modules. An error log is a persistence surface like any other, and a message quoting a smuggled token back would store the credential it declined to store. `From<serde_json::Error>` deliberately drops serde's message, which embeds the offending input, and reports line and column instead.

**AC-60 — nothing is executed.** Structural: the crate declares no process spawner, archive extractor, model runtime or dynamic loader, asserted by `this_crate_declares_no_fetch_dependency_of_its_own`.

## Two tests that had to be corrected

**A source scan that could never have passed.** A first version of `the_crate_source_names_no_reachable_target` scanned every source line for `://` and failed immediately — because the crate *must* contain URL-shaped strings to refuse them, and the tests use `https://registry.npmjs.org/react` as a hostile fixture. Banning the characters would have meant deleting the checks that keep them out of admitted documents.

It was replaced by `no_constant_in_this_crate_holds_a_reachable_endpoint`: a `const` or `static` holding an endpoint is where a fetch would start, and unlike a refusal list it has no legitimate reason to exist. That claim is both true and dangerous if violated.

**A substring check that fired on its own message.** `no_error_message_reads_as_a_verdict` compared uppercased text against `FAIL`, and `serialization failed` contains it. That is the same false positive that cost Cycle 013 a red build when `SECURE` matched inside `INSECURE_INTER_AGENT_COMMUNICATION`. The check now splits on non-alphanumerics and compares whole words.
