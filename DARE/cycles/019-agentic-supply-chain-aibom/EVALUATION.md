# Cycle 019 — Evaluation

**Title:** Agentic Supply Chain Security & AI-BOM  
**Status:** READY FOR REVIEW  
**Approval:** PENDING  
**Baseline:** `main @ 83fee819ef07f29a8d27cedd95db809b34829fd9`

## 1. Problem

DARE Agent Security already has an Agentic Security Registry and an `AGENTIC_SUPPLY_CHAIN` risk family from Cycle 012, with two existing properties: `AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE` and `AGENT.SUPPLY_CHAIN.CAPABILITY_DRIFT`. The product, however, does not yet have a dedicated deterministic engine that can turn local SBOM/AI-BOM/manifests/attestations into security evidence about the actual components that form an agentic system.

The missing capability is not merely inventory generation. Existing BOM standards can describe software, services, AI models, datasets and dependency relationships. Cycle 019 must answer a different question: whether local evidence proves that the component identity, artifact integrity, source, provenance, attestation binding, dependency graph, model lineage and dataset lineage remained consistent with the approved agentic system under assessment.

Cycle 019 therefore builds a security validation layer above imported BOM and manifest evidence. It may normalize CycloneDX, SPDX and a bounded DARE-native manifest, but it must never equate a complete inventory with a trustworthy supply chain.

## 2. Security question

Given a bounded local static, replayed, simulated or local-synthetic description of an agentic system, can DARE deterministically prove whether:

- each security-relevant component has an unambiguous canonical identity;
- immutable artifact digests remain bound to the intended component;
- mutable references are not treated as immutable identity;
- component source/publisher/registry trust matches recorded policy evidence;
- provenance subject and builder identity remain bound to the assessed artifact;
- attestations remain bound to the correct subject digest;
- declared and observed dependency relationships agree;
- external capability changes are detectable rather than silently accepted;
- model lineage remains bound to the expected base/training chain;
- dataset provenance remains bound to the expected dataset identity;
- required BOM evidence is present for the applicable component type;
- multiple independent violations visible in one retained evidence set are all reported.

## 3. Current standards baseline

The standards snapshot for Cycle 019 was re-verified on 2026-09-08.

### Current / stable inputs

- **OWASP Top 10 for Agentic Applications 2026** — risk taxonomy/context, especially `ASI04 Agentic Supply Chain Vulnerabilities`; it is not a substitute for deterministic evidence.
- **CycloneDX 1.7** — current stable CycloneDX BOM specification; used as the primary BOM interchange baseline for Cycle 019.
- **ECMA-424, 2nd Edition** — standardization basis associated with CycloneDX 1.7.
- **SPDX 3.0.1** — current SPDX specification baseline for this cycle, including AI and Dataset profiles and relationship/provenance/integrity concepts.
- **SLSA 1.2** — current Approved SLSA specification; provenance is consumed as local evidence and checked against expectations rather than treated as trust by presence alone.
- **in-toto Attestation Framework v1.2** — current attestation framework baseline for statement/subject/predicate/envelope/bundle semantics where local attestation evidence is consumed.

### Informative tooling

- **Sigstore/Cosign** — informative model for signature/attestation verification evidence and identity expectations. Cycle 019 does not contact Sigstore infrastructure, Fulcio, Rekor or OCI registries.

### Future, not baseline

- **CycloneDX Transparency Exchange Language / v2.0** is presented by the CycloneDX project as future/coming in 2026 at the planning date. It is not a mandatory Cycle 019 PASS requirement. The internal model should avoid choices that make later v2.0 support impossible, but no v2.0 conformance claim is authorized.

## 4. Existing implementation to reuse

### Cycle 001 — evidence and verdict contracts

Reuse:

- `PASS`, `FAIL`, `INCONCLUSIVE`, `ERROR`;
- stable evidence digests;
- redaction-before-persistence;
- bounded product wording;
- evidence-first reporting.

### Cycle 006 — applicability and denominator semantics

Preserve exactly:

`APPLICABLE without verdict -> NOT_TESTED`

`BLOCKED never becomes NOT_APPLICABLE`

Missing required evidence on an applicable supply-chain surface must not be converted into `NOT_APPLICABLE` merely because the control or evidence is absent.

### Cycle 009 — local-synthetic safety

Reuse hard-bound and local-synthetic safety concepts. Cycle 019 has zero production state change and zero external egress.

### Cycle 012 — Agentic Registry

Reuse the existing `AGENTIC_SUPPLY_CHAIN` RiskFamily and preserve the existing supply-chain property IDs:

- `AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE`
- `AGENT.SUPPLY_CHAIN.CAPABILITY_DRIFT`

Do not create a parallel `AGENT.SUPPLY.*` namespace and do not create a second supply-chain RiskFamily.

### Cycle 014 — tool security

Reuse tool/skill/MCP component concepts where useful, but do not duplicate tool misuse/authorization evaluators. Cycle 019 evaluates component identity/provenance/integrity, not runtime tool authorization.

### Cycle 015 — identity/trust concepts

Reuse authoritative identity/trust distinctions where publisher, signer, builder or supplier identity is represented. A self-asserted publisher string is metadata, not authenticated authority.

### Cycle 018 — aggregation and budget lessons

Reuse these security lessons:

- a primary coverage invariant must not hide another concrete violation visible in the same retained evidence;
- all applicable concrete `FAIL`s from the retained evidence set must be preserved;
- budget admission must happen before normalization/persistence of over-budget material;
- evidence cannot declare its own verdict.

## 5. In scope

- local CycloneDX 1.7 JSON ingestion;
- local SPDX 3.0.1 JSON ingestion for the supported Core/Software/AI/Dataset relationship subset required by this cycle;
- bounded DARE-native Agentic Supply Chain Manifest where external formats cannot express a required local security expectation cleanly;
- typed normalized agentic component model;
- typed relationship/dependency graph;
- canonical identity and digest binding;
- source/publisher/registry trust evidence;
- local provenance evidence;
- local in-toto/SLSA-style attestation subject/builder evidence;
- local signature verification evidence as a recorded fact plus signer identity/trust expectations, without remote verification;
- model/base/fine-tuning lineage;
- dataset identity/provenance/lineage;
- tool/skill/plugin/MCP-server component provenance;
- declared-versus-observed dependency comparison;
- capability drift evidence;
- BOM completeness as invariant-specific required evidence, not a universal security score;
- hostile parser/refusal behavior;
- registry/profile/coverage/CLI/reporting/CI/docs integration;
- deterministic local corpus and cross-format semantic-equivalence tests.

## 6. Component classes

The normalized model must support at least:

- `AGENT`
- `MODEL`
- `EMBEDDING_MODEL`
- `DATASET`
- `FRAMEWORK`
- `TOOL`
- `SKILL_PLUGIN`
- `MCP_SERVER`
- `SERVICE_API`
- `PACKAGE`
- `CONTAINER_IMAGE`
- `PROMPT_POLICY_ASSET`
- `GUARDRAIL`
- `EXTERNAL_AGENT`

`EXTERNAL_AGENT` is inventory/supply-chain evidence only in Cycle 019. Authentication, message security and authorization between agents remain Cycle 020.

## 7. Key design distinctions

Cycle 019 must preserve these distinctions:

`inventory != trust`

`component name != component identity`

`version string != immutable artifact`

`digest presence != provenance`

`valid signature evidence != authorized signer`

`provenance presence != trusted provenance`

`complete AI-BOM != secure supply chain`

`declared dependency != observed dependency`

`same name/version != same artifact`

`component URL != authorization to fetch`

`external agent inventory != A2A authorization`

`BOM metadata != executable instruction`

## 8. Safety boundary

Cycle 019 is local and deterministic.

Allowed execution modes:

- `STATIC`
- `REPLAY`
- `SIMULATED`
- `LOCAL_SYNTHETIC`

Hard safety properties:

- production state changes: `0`;
- external egress: `0`;
- registry fetches: `0`;
- package/model/container downloads: `0`;
- remote attestation fetches: `0`;
- remote signature/transparency-log requests: `0`;
- code/model execution from imported artifacts: `0`;
- real signing/attestation issuance: `0`.

Any URL, registry coordinate, package URL, Git URL, OCI reference, model URL or attestation URL inside an imported document is data. It never grants permission to contact that location.

## 9. Verdict semantics

- `PASS`: positive invariant-specific evidence exists and the applicable invariant held for the tested component/relationship.
- `FAIL`: retained evidence deterministically proves a supply-chain boundary violation.
- `INCONCLUSIVE`: the surface is applicable but evidence required to decide the invariant is absent or insufficient.
- `ERROR`: the harness/parser/normalizer could not complete the evaluation under the approved contract.
- parser/safety refusal remains distinct from a security `FAIL`.

No absence-only PASS is allowed. No BOM, manifest, provenance document or attestation may provide an `expected_verdict`, `should_fail`, `is_secure` or equivalent authority field.

## 10. Proposed property expansion

Cycle 019 preserves the two existing properties and proposes eight additive properties under the existing namespace, for a Cycle 019 supply-chain set of ten:

Existing:

1. `AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE`
2. `AGENT.SUPPLY_CHAIN.CAPABILITY_DRIFT`

Additive candidates to freeze in DESIGN:

3. `AGENT.SUPPLY_CHAIN.COMPONENT_IDENTITY`
4. `AGENT.SUPPLY_CHAIN.ARTIFACT_INTEGRITY`
5. `AGENT.SUPPLY_CHAIN.SOURCE_TRUST`
6. `AGENT.SUPPLY_CHAIN.ATTESTATION_BINDING`
7. `AGENT.SUPPLY_CHAIN.DEPENDENCY_INTEGRITY`
8. `AGENT.SUPPLY_CHAIN.MODEL_LINEAGE`
9. `AGENT.SUPPLY_CHAIN.DATASET_PROVENANCE`
10. `AGENT.SUPPLY_CHAIN.BOM_COMPLETENESS`

No existing property ID may be renamed, removed or weakened.

## 11. Out of scope

- Agent-to-Agent protocol/message/authentication security — Cycle 020;
- adaptive multi-turn adversarial execution — Cycle 021;
- remote authorized dynamic validation — Cycle 022;
- automatic attack-graph construction — Cycle 023;
- blast-radius analysis — Cycle 024;
- runtime OpenTelemetry security — Cycle 025;
- remote package, Git, OCI, model-hub or registry lookup;
- CVE database synchronization;
- vulnerability exploitation;
- malware execution or sandboxing;
- arbitrary artifact execution;
- model inference;
- unsafe pickle/model deserialization;
- real signing, key management or attestation issuance;
- license-compliance verdicts;
- full data-governance, copyright, privacy, bias or fairness analysis;
- production repository/package publication;
- automatic remediation that mutates external systems.

## 12. Product boundary

Cycle 019 must not position DARE as a replacement for Syft, cdxgen, CycloneDX tooling, SPDX tooling, SLSA tooling or Sigstore. Those ecosystems can produce or transport inventory/provenance evidence.

DARE's value is the deterministic security decision layer that consumes bounded evidence and evaluates whether the agentic component graph preserves approved identity, integrity, source, provenance, attestation and lineage relationships.

## 13. Residual risks after Cycle 019

Even a clean Cycle 019 result will not prove:

- that a remote registry currently serves the same artifact;
- that a production package manager resolves the same dependency graph;
- that a real transparency log contains the recorded entry;
- that a remote signature service or certificate chain is currently valid;
- that production runtime loading matches the supplied local evidence;
- that a component is free of vulnerabilities or malicious behavior;
- that inter-agent communication is authenticated/authorized;
- that compromise cannot propagate through the graph.

Those require later runtime, A2A, attack-graph, blast-radius or deployment-specific validation.