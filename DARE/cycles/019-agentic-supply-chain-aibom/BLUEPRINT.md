# Cycle 019 — Blueprint

## Target architecture

Introduce an additive crate, expected name `crates/dare-supply-chain-security`, plus additive Agentic registry/profile/CLI/product/CI integration.

Execution flow:

```text
CycloneDX / SPDX / DARE manifest / local provenance-attestation evidence
        ↓
Raw byte admission + schema/version validation
        ↓
Hostile/secret/executable/remote-action refusal
        ↓
Component + relationship admission bounds
        ↓
Format-specific parser
        ↓
Canonical normalized component model
        ↓
Canonical relationship graph
        ↓
Source/trust + provenance + attestation binding
        ↓
Model/dataset lineage + capability projection
        ↓
Deterministic 12-invariant evaluation
        ↓
Cross-invariant concrete FAIL aggregation
        ↓
Cycle 001 evidence bridge + Cycle 006 coverage
        ↓
PASS / FAIL / INCONCLUSIVE / ERROR
```

## Modules

Suggested crate modules:

- `source.rs` — closed component/source/trust/status enums;
- `schema.rs` — compiled-in DARE schemas/version contracts;
- `component.rs` — normalized component model;
- `identity.rs` — canonical identity and immutable digest rules;
- `relationship.rs` — closed edge model and graph validation;
- `cyclonedx.rs` — bounded CycloneDX 1.7 JSON importer;
- `spdx.rs` — bounded SPDX 3.0.1 importer;
- `manifest.rs` — DARE-native expectation manifest;
- `normalize.rs` — format-independent semantic normalization;
- `provenance.rs` — local provenance subject/builder binding;
- `attestation.rs` — local attestation/signature evidence binding;
- `model_lineage.rs`;
- `dataset.rs`;
- `capability.rs` — existing capability-drift property evidence;
- `observation.rs` — closed normalized observations;
- `coverage.rs` — invariant-specific positive PASS contracts;
- `invariant.rs` — deterministic 12-invariant registry/evaluators;
- `budget.rs` — byte/object/graph/run-wide admission ledger;
- `replay.rs`;
- `simulated.rs`;
- `local_synthetic.rs`;
- `result.rs` — aggregation and bounded result artifacts;
- `evidence_bridge.rs` — Cycle 001 integration;
- `compat.rs` — Cycle 006/012/014/015/018 reuse assertions.

## Expected artifact trees

- `schemas/supply-chain-security/v1/`
- `corpus/supply-chain-security/v1/`
- `fixtures/supply-chain-security/`
- `standards/supply-chain-security/2026/`
- `profiles/agentic-supply-chain-security-2026.json`
- `book/en/src/concepts/agentic-supply-chain-security.md`
- `book/pt/src/concepts/agentic-supply-chain-security.md`
- `book/en/src/reference/extending-supply-chain-security.md`
- `book/pt/src/reference/extending-supply-chain-security.md`

## Registry changes

Preserve:

- `AGENTIC_SUPPLY_CHAIN` RiskFamily;
- `AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE`;
- `AGENT.SUPPLY_CHAIN.CAPABILITY_DRIFT`.

Add exactly eight properties frozen in `DESIGN.md`.

No `AGENT.SUPPLY.*` parallel namespace.

## Parser boundary

Importers are data parsers only. They may not:

- fetch URLs;
- resolve registries;
- clone repositories;
- pull OCI images;
- download models/packages;
- invoke shell/processes;
- load plugins/models;
- validate remote certificates/transparency logs.

Unknown fields remain non-authoritative. Unknown authority-bearing structures are refused when safe interpretation is impossible.

## Admission boundary

Budget order is frozen:

```text
raw input
→ byte admission
→ parse/schema
→ component/relationship admission
→ normalized object admission
→ persisted evidence admission
→ invariant evaluation
```

No over-budget object may produce deciding normalized/persisted evidence.

## Canonical identity boundary

Canonicalization must bind component semantics independently of input format. Equivalent CycloneDX/SPDX fixtures must produce equivalent normalized component/edge digests.

Mutable reference, name or version cannot substitute for immutable digest evidence where the selected property requires artifact identity.

## Trust boundary

Imported publisher/supplier/builder/signer strings are claims. Trust comes only from local approved policy evidence and deterministic binding.

`verification_status=VALID` is evidence about verification, not proof that the signer/builder is authorized.

## Compatibility rules

1. Do not duplicate Cycle 001 evidence/verdict/redaction.
2. Do not change Cycle 006 applicability/coverage math.
3. Reuse Cycle 012 RiskFamily and existing property IDs.
4. Do not duplicate Cycle 014 runtime tool authorization/misuse semantics.
5. Reuse Cycle 015 authoritative identity/trust distinctions.
6. Preserve Cycle 018 cross-invariant concrete FAIL aggregation semantics.
7. Enforce admission before normalization/persistence for hard bounds.
8. Do not implement Cycle 020 A2A protocol security.
9. Do not implement Cycle 023 attack-path graph semantics; Cycle 019 produces a dependency graph suitable as later input.
10. No external egress, product state changes, arbitrary shell or artifact execution.

## Corpus design

Create `SUPPLY-LAB-001..040` with at least 36 mandatory scenarios and recommended controls 37–40. Use paired positive/negative fixtures and explicit missing-evidence INCONCLUSIVE scenarios.

Fixture sources should include native DARE scenarios plus representative bounded CycloneDX/SPDX documents. Cross-format equivalence tests must compare normalized semantics.

## Profile and coverage

Create `profiles/agentic-supply-chain-security-2026.json` containing all ten supply-chain properties with explicit REQUIRED/CONDITIONAL levels.

Do not silently rewrite `agentic-security-baseline-2026`; any additive compatibility change requires a regression proving pre-existing requirement behavior is unchanged.

## CLI

Primary command:

`dare-agent-security validate supply-chain`

Optional inventory command is allowed only if it calls the same parser/normalizer and does not create a second identity model.

CLI must not expose network, token, credential, private-key, command, download or pull flags.

## Outputs

- `agentic-bom.cdx.json`
- `supply-chain-result.json`
- `supply-chain-components.json`
- `supply-chain-relationships.json`
- `supply-chain-evidence.json`
- `supply-chain-findings.json`
- `summary.md`

All result text is bounded and evidence-specific.

## CI strategy

Dedicated job `supply-chain-security-2026` must cover:

- schemas/version rejection;
- CycloneDX/SPDX import and semantic equivalence;
- 12 invariant directions;
- positive PASS requirements;
- missing-evidence INCONCLUSIVE;
- provenance/attestation/signer-builder trust binding;
- dependency/capability/model/dataset semantics;
- multi-violation aggregation;
- admission-boundary regressions;
- hostile secret/executable/remote-fetch/path/bidi/graph-bomb fixtures;
- registry/profile/coverage compatibility;
- Cycle 012–018 regressions;
- MCP baseline;
- full workspace;
- EN/PT docs.

Before PR, execute:

`python scripts/run-ci-job-locally.py .github/workflows/ci.yml supply-chain-security-2026`

## Final proof

Execution must end with `REGRESSION.md` and `PROOF.md`. `PROOF.md` maps all 85 ACs to executed evidence. LLM review or code existence alone cannot satisfy an AC.