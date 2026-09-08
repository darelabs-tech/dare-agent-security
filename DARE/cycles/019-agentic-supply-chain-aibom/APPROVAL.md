# Cycle 019 — Product Owner Approval

**Status:** APPROVED FOR EXECUTION  
**Cycle:** 019 — Agentic Supply Chain Security & AI-BOM  
**Approved at:** 2026-09-08  
**Base:** `main @ 83fee819ef07f29a8d27cedd95db809b34829fd9`  
**Planning head:** `ba736ee3d60726cc174a9832df5a5682a5384a0b`  
**Branch:** `agent/cycle-019-agentic-supply-chain-aibom`

## Approval

The Product Owner explicitly approves all frozen planning artifacts, all 85 acceptance criteria, and all 53 execution tasks for Cycle 019.

Approved artifacts:

- `EVALUATION.md`
- `DESIGN.md`
- `BLUEPRINT.md`
- `TASKS.md`
- `dare-dag.yaml`

Execution may proceed without intermediate Product Owner approval while remaining strictly inside the approved scope, compatibility contracts and safety boundary.

## Authorized scope

Implement a deterministic, evidence-first Agentic Supply Chain Security & AI-BOM engine using only `STATIC`, `REPLAY`, `SIMULATED`, and `LOCAL_SYNTHETIC` modes.

Authorized surfaces include:

- bounded local CycloneDX 1.7 JSON import;
- bounded local SPDX 3.0.1 JSON import;
- DARE-native Agentic Supply Chain Manifest;
- normalized typed component identities and immutable digest binding;
- typed dependency/relationship graph;
- local source/publisher/builder/signer trust evidence;
- local provenance subject/artifact/builder binding;
- local attestation/signature evidence binding;
- model lineage;
- dataset provenance/lineage within supply-chain scope;
- tool/skill/plugin/MCP-server component provenance;
- existing capability-drift property evaluation;
- deterministic 12-invariant engine;
- independent same-trial concrete FAIL aggregation;
- hard admission budgets before normalized/persisted deciding evidence;
- Agentic registry/profile/coverage integration;
- bounded CLI/reporting;
- SUPPLY-LAB corpus;
- documentation and CI.

## Frozen registry contracts

Cycle 019 MUST reuse the existing:

- RiskFamily `AGENTIC_SUPPLY_CHAIN`;
- `AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE`;
- `AGENT.SUPPLY_CHAIN.CAPABILITY_DRIFT`.

Exactly eight additive property IDs are approved:

- `AGENT.SUPPLY_CHAIN.COMPONENT_IDENTITY`
- `AGENT.SUPPLY_CHAIN.ARTIFACT_INTEGRITY`
- `AGENT.SUPPLY_CHAIN.SOURCE_TRUST`
- `AGENT.SUPPLY_CHAIN.ATTESTATION_BINDING`
- `AGENT.SUPPLY_CHAIN.DEPENDENCY_INTEGRITY`
- `AGENT.SUPPLY_CHAIN.MODEL_LINEAGE`
- `AGENT.SUPPLY_CHAIN.DATASET_PROVENANCE`
- `AGENT.SUPPLY_CHAIN.BOM_COMPLETENESS`

No parallel `AGENT.SUPPLY.*` namespace is authorized.

## Required reuse

- Cycle 001 verdict/evidence/redaction contracts;
- Cycle 006 applicability/coverage denominator semantics unchanged;
- Cycle 009 local-synthetic safety concepts;
- Cycle 012 Agentic Registry and existing supply-chain RiskFamily/property IDs;
- Cycle 014 tool semantics without duplicating runtime authorization/misuse;
- Cycle 015 authoritative identity/trust distinctions;
- Cycle 018 independent cross-invariant concrete FAIL aggregation and admission-before-normalization lessons.

## Security invariants

The approved initial invariant set is exactly 12:

1. `COMPONENT_PROVENANCE_SUFFICIENT`
2. `EXTERNAL_CAPABILITY_DRIFT_NOT_OBSERVED`
3. `COMPONENT_IDENTITY_UNAMBIGUOUS`
4. `ARTIFACT_DIGEST_BOUND_TO_COMPONENT`
5. `MUTABLE_REFERENCE_NOT_USED_AS_IMMUTABLE_IDENTITY`
6. `COMPONENT_SOURCE_TRUST_PRESERVED`
7. `PROVENANCE_SUBJECT_AND_BUILDER_BOUND`
8. `ATTESTATION_SUBJECT_DIGEST_PRESERVED`
9. `DEPENDENCY_EDGE_INTEGRITY_PRESERVED`
10. `MODEL_LINEAGE_PRESERVED`
11. `DATASET_PROVENANCE_PRESERVED`
12. `BOM_REQUIRED_EVIDENCE_PRESENT`

PASS requires invariant-specific positive evidence. Missing deciding evidence on an applicable surface is `INCONCLUSIVE`, not PASS. A primary scenario invariant must never hide another concrete applicable FAIL visible in the same retained evidence.

## Safety authorization

Approved maximum product effects:

- product state changes: `0`;
- external egress bytes: `0`;
- registry/package/model/Git/OCI fetches: `0`;
- remote signature/attestation/transparency-log requests: `0`;
- artifact/model/code execution from imported evidence: `0`;
- real signing or attestation issuance: `0`;
- real credentials/private keys: `0`.

A URL or registry coordinate inside imported evidence is inert metadata only and never authorizes network access.

## Explicit exclusions

Not authorized:

- A2A protocol/auth/message security (Cycle 020);
- multi-turn adaptive adversarial execution (Cycle 021);
- remote authorized validation (Cycle 022);
- attack-path construction (Cycle 023);
- blast-radius analysis (Cycle 024);
- runtime OpenTelemetry security (Cycle 025);
- remote package/registry/model/container/Git lookup;
- vulnerability database synchronization or exploitation;
- malware/model/arbitrary artifact execution;
- unsafe object/model deserialization;
- license-compliance decisions;
- PII/copyright/bias/fairness dataset analysis;
- external-system remediation or publication;
- arbitrary shell/callback/executable hooks.

## Standards status discipline

- OWASP Agentic Top 10 2026 ASI04: approved risk taxonomy mapping.
- CycloneDX 1.7 / ECMA-424 2nd Edition: approved current interchange baseline.
- SPDX 3.0.1: approved current supported subset baseline.
- SLSA 1.2: approved provenance semantic reference.
- in-toto Attestation Framework v1.2: approved local attestation semantic reference.
- Sigstore/Cosign: informative/local-evidence model only.
- CycloneDX v2.0/TEL: FUTURE and not a mandatory PASS requirement.

## Release gate

Before a PR may be opened:

1. tasks 001–053 complete;
2. all 85 acceptance criteria mapped to executed evidence;
3. `cargo fmt --all --check` green;
4. `cargo clippy --workspace --all-targets -- -D warnings` green;
5. `cargo test --workspace` green;
6. `cargo audit` resolved under project policy;
7. Cycle 012/013/014/015/016/017/018 and MCP/coverage regressions green;
8. English and Portuguese mdBook builds green;
9. `python scripts/run-ci-job-locally.py .github/workflows/ci.yml supply-chain-security-2026` passes by executing the real workflow job;
10. `REGRESSION.md` complete;
11. `PROOF.md` maps 85/85 ACs to executed evidence;
12. final branch head pushed before PR;
13. PR opened once, preserving the repository's PR-open-only workflow trigger;
14. if the branch changes after PR creation, that PR CI is stale and must not be used as release evidence.
