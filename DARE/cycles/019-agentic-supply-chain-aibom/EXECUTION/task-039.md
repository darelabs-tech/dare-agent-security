# task-039 — Build provenance/attestation/dependency SUPPLY-LAB paired corpus

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-66, AC-67

## Evidence

`src/corpus.rs` (the forty entries) and `crates/dare-supply-chain-security/tests/supply_lab.rs` (the harness contract).

## The split that makes the corpus worth having

An entry records a **class** — `CONTROL`, `ATTACK`, `REFUSAL`, `GAP` — and never a verdict. There is no `expected_verdict`, no `expected_findings`, no `is_secure`. `no_entry_declares_an_outcome_anywhere_in_its_evidence` asserts none of those strings reaches the evaluator from any of the forty bundles.

The expectation lives in the harness contract instead, asserted once per class rather than per fixture:

- **ATTACK** — the declared invariant must report `FAIL`, and every violation must cite deciding evidence.
- **CONTROL** — nothing may `FAIL`, and the declared invariant must reach `PASS`.
- **REFUSAL** — the bundle must be refused before evaluation, and the refusal must not echo what it refused.
- **GAP** — the declared invariant must be `INCONCLUSIVE`: never `PASS`, and never `FAIL` either, because thin evidence is not a finding.

## Entries 009–019, 028 and 040

| Entry | Class | What it stages |
| --- | --- | --- |
| 009 | control | provenance binds the subject artifact and names an approved builder |
| 010 | attack | provenance names the component and describes a different artifact |
| 011 | attack | provenance names a builder policy does not approve |
| 012 | gap | no provenance evidence collected at all |
| 013 | control | the attestation binds this artifact's digest and an approved signer |
| 014 | attack | the attestation names the component and binds another artifact's digest |
| 015 | attack | a locally valid signature by a signer nobody approved |
| 016 | control | declared and observed dependency edges agree |
| 017 | attack | a dependency edge nobody declared |
| 018 | attack | a declared dependency edge nothing observed |
| 019 | refusal | an edge naming a component nothing inventoried |
| 028 | control | an MCP server carrying the same provenance evidence a package does |
| 040 | control | the same dependency edge recorded twice stays one edge |

**010 and 011 are separate entries because they are separate findings.** One is a substitution and the other is a policy gap, and an operator remediates them differently.

**012 is a gap, not an attack.** No provenance evidence of any kind is different from provenance that exists and names somebody else — the second is entry 010.

**015 is the entry the whole attestation layer exists for.** `valid signature evidence != authorized signer`: the signature verified locally and the signer was never approved.

**019 is refused rather than evaluated.** `the_dangling_edge_entry_is_refused_and_not_silently_dropped` asserts the refusal names which end of the edge was missing. A silently dropped edge is a dependency that stops being checked, which looks exactly like a dependency that was never there.

**040 guards the deduplication.** The same edge from two documents must stay one edge, or an agreeing dependency would read as a duplicate and the graph would grow with every document describing it.
