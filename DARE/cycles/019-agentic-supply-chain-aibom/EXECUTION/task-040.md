# task-040 — Build capability/model/dataset/tool/MCP SUPPLY-LAB paired corpus

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-41, AC-42, AC-43, AC-44, AC-46, AC-66, AC-67

## Evidence

`src/corpus.rs` (the forty entries) and `crates/dare-supply-chain-security/tests/supply_lab.rs` (the harness contract).

## The split that makes the corpus worth having

An entry records a **class** — `CONTROL`, `ATTACK`, `REFUSAL`, `GAP` — and never a verdict. There is no `expected_verdict`, no `expected_findings`, no `is_secure`. `no_entry_declares_an_outcome_anywhere_in_its_evidence` asserts none of those strings reaches the evaluator from any of the forty bundles.

The expectation lives in the harness contract instead, asserted once per class rather than per fixture:

- **ATTACK** — the declared invariant must report `FAIL`, and every violation must cite deciding evidence.
- **CONTROL** — nothing may `FAIL`, and the declared invariant must reach `PASS`.
- **REFUSAL** — the bundle must be refused before evaluation, and the refusal must not echo what it refused.
- **GAP** — the declared invariant must be `INCONCLUSIVE`: never `PASS`, and never `FAIL` either, because thin evidence is not a finding.

## Entries 020–029

| Entry | Class | What it stages |
| --- | --- | --- |
| 020 | control | the observed capability set is the approved one |
| 021 | attack | a component gained a capability since approval |
| 022 | gap | only one side of the capability comparison exists |
| 023 | control | the model derives from the approved base **and its approved build** |
| 024 | attack | the base model substituted while the model's name stayed the same |
| 025 | gap | no lineage edge recorded under an approved expectation |
| 026 | control | the training dataset is the approved one |
| 027 | attack | the training dataset substituted under an approved identity |
| 028 | control | an MCP server carrying package-grade provenance evidence |
| 029 | attack | a component present that the deployment never declared |

**AC-41/AC-42/AC-44 — each dimension has all three answers.** Drift has 020/021/022; lineage has 023/024/025; dataset provenance has 026/027 plus the undecidable path exercised in `dataset.rs`.

**AC-43 — 024 is the entry the property exists for.** The model's own name is unchanged and only what it derives from moved, which is why the expectation is a component id rather than a name.

**AC-46 — 028 is the boundary with Cycle 014.** An MCP server carries a digest, provenance and an attestation exactly as a package does, and the projection that describes it has no field for whether the tool may be invoked.

**029 closed a real gap.** Nothing in the twelve invariants reported a component that was observed and never declared: dependency integrity covers inserted *edges*, not inserted *components*. Source trust now reports it, because a component the deployment never declared has no approved source by construction. The check fires only where a declared inventory exists to compare against — without one, an undeclared component is every component and the finding would be noise.
