# Cycle 019 — Design

**Status:** READY FOR REVIEW  
**Approval:** PENDING  
**Baseline:** `main @ 83fee819ef07f29a8d27cedd95db809b34829fd9`

## 1. Objective

Implement a deterministic, evidence-first Agentic Supply Chain Security & AI-BOM engine that consumes bounded local BOM/manifest/provenance/attestation evidence, normalizes it into a closed component graph, and evaluates whether component identity, integrity, source trust, provenance, attestation, dependency relationships, model lineage and dataset provenance remain bound to the approved agentic system.

The engine is a security decision layer, not a generic SBOM crawler and not a remote package-verification service.

## 2. Core principles

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

## 3. Risk family and additive properties

Reuse the existing Cycle 012 RiskFamily:

`AGENTIC_SUPPLY_CHAIN`

Do not create another RiskFamily.

Preserve existing properties byte-for-byte except additive standards/evidence metadata changes proven backward-compatible:

1. `AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE`
2. `AGENT.SUPPLY_CHAIN.CAPABILITY_DRIFT`

Add exactly these eight Cycle 019 properties:

3. `AGENT.SUPPLY_CHAIN.COMPONENT_IDENTITY`
4. `AGENT.SUPPLY_CHAIN.ARTIFACT_INTEGRITY`
5. `AGENT.SUPPLY_CHAIN.SOURCE_TRUST`
6. `AGENT.SUPPLY_CHAIN.ATTESTATION_BINDING`
7. `AGENT.SUPPLY_CHAIN.DEPENDENCY_INTEGRITY`
8. `AGENT.SUPPLY_CHAIN.MODEL_LINEAGE`
9. `AGENT.SUPPLY_CHAIN.DATASET_PROVENANCE`
10. `AGENT.SUPPLY_CHAIN.BOM_COMPLETENESS`

The existing `CAPABILITY_DRIFT` property remains the security property for externally supplied capability changes. Do not create a duplicate drift property.

## 4. Standards provenance

Every Cycle 019 property must carry versioned provenance with status.

### NORMATIVE / FINAL baseline

- OWASP Agentic Top 10 2026, `ASI04 Agentic Supply Chain Vulnerabilities`, as risk taxonomy/context.
- CycloneDX 1.7 / ECMA-424 2nd Edition for supported CycloneDX interchange semantics.
- SPDX 3.0.1 for the supported Core/Software/AI/Dataset subset used by the engine.
- SLSA 1.2 for local provenance semantics where represented.
- in-toto Attestation Framework v1.2 for local statement/subject/predicate/envelope semantics where represented.

### INFORMATIVE

- Sigstore/Cosign verification concepts for local signature/attestation evidence and signer identity expectations.

### FUTURE

- CycloneDX v2.0 / Transparency Exchange Language until a stable released specification is re-verified during a later cycle.

No future or informative source becomes a mandatory PASS condition unless explicitly frozen in a later approved cycle.

## 5. Applicability predicates

Reuse closed Cycle 012 predicates where sufficient and add only bounded predicates needed by Cycle 019.

Required candidates:

- `agent_present`
- `external_components_present`
- `supply_chain_bom_present`
- `component_digest_present`
- `source_trust_policy_present`
- `provenance_present`
- `attestation_present`
- `dependency_graph_present`
- `model_component_present`
- `dataset_component_present`
- `declared_observed_components_present`

Rules:

- target-shape absence may make a property `NOT_APPLICABLE`;
- missing evidence/control on an applicable surface does not make it `NOT_APPLICABLE`;
- missing deciding evidence yields `INCONCLUSIVE` unless the absence itself deterministically violates an approved mandatory control;
- `BLOCKED` never becomes `NOT_APPLICABLE`;
- APPLICABLE without verdict remains `NOT_TESTED` at the coverage layer.

## 6. Typed component model

Define a closed `AgenticComponent` model with at least:

- `component_id` — canonical local identifier;
- `component_type`;
- `name`;
- optional `version`;
- zero or more normalized immutable digests;
- optional package coordinates (`purl`, CPE-like identifiers only if already present; no lookup);
- optional supplier/publisher identity reference;
- optional source/registry reference;
- trust classification derived from policy evidence, never self-declared authority;
- optional provenance references;
- optional attestation references;
- optional license inventory metadata;
- evidence-source references and stable evidence digests.

Closed component types:

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

No arbitrary executable component handler is allowed.

## 7. Canonical identity

Canonical identity is a deterministic projection of approved identifiers and, where required, immutable digest evidence.

Rules:

- name alone is never sufficient for immutable identity;
- name + version alone is never sufficient when an immutable artifact is expected;
- mutable references such as tags (`latest`, floating branches, unconstrained ranges) cannot satisfy an immutable identity invariant by themselves;
- digest algorithms are allowlisted;
- malformed or ambiguous digest syntax is refused;
- duplicate canonical IDs that resolve to conflicting semantics fail closed;
- canonicalization must be format-independent so equivalent CycloneDX/SPDX representations can normalize to the same semantic identity.

## 8. Relationship graph

Define a closed relationship enum with at least:

- `DEPENDS_ON`
- `USES`
- `CALLS`
- `LOADS`
- `PROVIDED_BY`
- `BUILT_FROM`
- `TRAINED_FROM`
- `FINE_TUNED_FROM`
- `EMBEDS_WITH`
- `EXPOSES_TOOL`
- `CONNECTS_TO`
- `ATTESTED_BY`
- `SIGNED_BY`

Each edge records:

- stable edge id/digest;
- source component id;
- target component id;
- relation type;
- source evidence reference;
- optional policy expectation reference;
- declared/observed classification.

Dangling endpoints are invalid. Relationship text from an imported BOM cannot invent new relation types.

## 9. Source and trust model

Source, registry, supplier, publisher, builder and signer identity are separate concepts.

Trust is represented by bounded policy evidence such as:

- explicit approved identity id/digest;
- approved source/registry id;
- approved builder id;
- approved signer id;
- trust class from a local policy document.

A component or BOM claiming `trusted=true` does not establish trust.

No network lookup, certificate fetch or registry query occurs.

## 10. Input formats

### CycloneDX 1.7 JSON

Support a bounded subset sufficient for:

- components;
- services when relevant as component references;
- dependencies/relationships;
- hashes;
- supplier/publisher metadata;
- AI/ML model/dataset evidence represented by the specification;
- external references as inert metadata only.

### SPDX 3.0.1 JSON

Support the bounded Core/Software/AI/Dataset subset required for:

- elements;
- packages/AI packages/datasets as relevant;
- relationships;
- integrity/provenance references available in the local document.

### DARE Agentic Supply Chain Manifest

A closed DARE-native schema may supply local security expectations not cleanly expressible by imported BOMs, including:

- approved component identity/digest;
- approved source/publisher/builder/signer identities;
- expected graph edges;
- declared vs observed component sets;
- model/dataset lineage expectations;
- trusted local attestation/provenance references.

The DARE manifest cannot declare a verdict.

## 11. Normalization

All supported inputs normalize into the same internal model before evaluation.

Required flow:

`raw bytes -> byte admission -> parser/schema -> object-count admission -> normalization -> graph admission -> evidence persistence -> invariant evaluation`

Critical rule from Cycle 018:

Over-budget material must be rejected before it can create normalized or persisted deciding evidence.

Cross-format equality is semantic, never raw JSON equality.

## 12. Provenance model

Define closed local provenance evidence with at least:

- provenance id;
- subject component reference;
- subject digest(s);
- provenance type/source;
- builder identity reference;
- build invocation/environment identifiers only as bounded metadata;
- source material references/digests where present;
- timestamp/status metadata only if supplied as local evidence;
- evidence digest.

`provenance_present == true` never establishes trust.

The evaluator independently binds:

- provenance subject -> component;
- subject digest -> artifact digest;
- builder -> approved builder policy where applicable.

## 13. Attestation and signature evidence

Define closed local attestation/signature evidence:

- statement/envelope id;
- subject reference;
- subject digest;
- predicate type;
- predicate digest/reference;
- local verification status enum;
- signer identity reference when present;
- evidence digest.

Rules:

- verification status is evidence, not authority for signer trust;
- valid signature evidence with an unapproved signer may still `FAIL SOURCE_TRUST`/`ATTESTATION_BINDING` as applicable;
- an attestation for artifact B cannot satisfy artifact A;
- no Fulcio/Rekor/OCI/network calls;
- no private keys or signing operations.

## 14. Model lineage

Model lineage uses component identities/digests plus typed edges:

- `FINE_TUNED_FROM`
- `TRAINED_FROM`
- `BUILT_FROM`

Required security semantics:

- expected base model identity/digest must match the normalized lineage edge;
- an observed substituted base model deterministically fails;
- missing lineage evidence on an applicable model surface is `INCONCLUSIVE`, not PASS;
- model name/repository name alone cannot prove lineage.

## 15. Dataset provenance

Dataset security scope is limited to supply-chain concerns:

- identity;
- digest/integrity;
- source/provenance;
- relationship to model/training lineage;
- substitution detection.

Do not implement privacy, PII, copyright, license-compliance, fairness or bias decisions in this cycle.

## 16. Tool/skill/plugin/MCP component provenance

Tools, skills/plugins and MCP servers are represented as supply-chain components.

Cycle 019 evaluates:

- identity;
- digest/version binding;
- source/provenance;
- declared/observed inclusion;
- dependency relationship;
- capability drift evidence when the imported/local manifest provides capability projections.

Runtime authorization/tool misuse remains Cycle 014. MCP auth remains Cycle 018.

## 17. Capability drift

Reuse `AGENT.SUPPLY_CHAIN.CAPABILITY_DRIFT`.

A closed optional capability projection may include bounded semantics such as:

- tool names/ids;
- resource/prompt identifiers;
- declared component capabilities;
- approved capability-set digest;
- observed capability-set digest.

A newly introduced capability or changed capability-set digest is a deterministic violation when both approved and observed evidence are present and semantically differ.

Missing observed capability evidence on an applicable drift assessment is `INCONCLUSIVE`.

## 18. Normalized observations

Define a closed observation model including at least:

- `BOM_DOCUMENT_CONTEXT`
- `COMPONENT_CONTEXT`
- `COMPONENT_DIGEST_CONTEXT`
- `SOURCE_TRUST_CONTEXT`
- `PROVENANCE_CONTEXT`
- `ATTESTATION_CONTEXT`
- `RELATIONSHIP_CONTEXT`
- `CAPABILITY_CONTEXT`
- `MODEL_LINEAGE_CONTEXT`
- `DATASET_PROVENANCE_CONTEXT`
- `DECLARED_OBSERVED_COMPONENT_CONTEXT`
- `HARNESS_ERROR`

Adapters/importers cannot assert final verdict.

## 19. Deterministic invariants

Implement exactly these initial 12 invariants unless Review documents an approved pre-execution correction:

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

Property mapping:

- invariants 1 and 7 -> `COMPONENT_PROVENANCE`;
- invariant 2 -> `CAPABILITY_DRIFT`;
- invariants 3 and 5 -> `COMPONENT_IDENTITY`;
- invariant 4 -> `ARTIFACT_INTEGRITY`;
- invariant 6 -> `SOURCE_TRUST`;
- invariant 8 -> `ATTESTATION_BINDING`;
- invariant 9 -> `DEPENDENCY_INTEGRITY`;
- invariant 10 -> `MODEL_LINEAGE`;
- invariant 11 -> `DATASET_PROVENANCE`;
- invariant 12 -> `BOM_COMPLETENESS`.

## 20. Positive PASS contracts

PASS is invariant-specific and requires positive deciding evidence.

Examples:

- identity PASS requires enough identifiers/digests to prove canonical uniqueness;
- artifact integrity PASS requires expected and observed immutable digest evidence where immutable identity is applicable;
- source trust PASS requires component source identity plus explicit local approved trust evidence;
- provenance PASS requires subject binding and, where policy requires it, builder binding;
- attestation PASS requires subject digest binding plus sufficient local verification evidence;
- dependency integrity PASS requires expected and observed edges;
- model lineage PASS requires expected and observed lineage projections;
- dataset provenance PASS requires expected and observed dataset provenance/identity projections;
- completeness PASS requires a closed component-type-specific evidence requirement set.

Missing deciding channels -> `INCONCLUSIVE`, never PASS.

## 21. Independent violation aggregation

A scenario selects a primary property/invariant for coverage, but the retained evidence set is evaluated across every applicable invariant.

Concrete `FAIL`s from all applicable evaluators are retained for the same trial/run.

Secondary `PASS`, `INCONCLUSIVE` or `ERROR` outcomes do not automatically poison the primary result. Aggregate precedence and property coverage must be deterministic and documented.

`stop_on_first_fail` may stop later trials only after every concrete same-trial violation has been retained.

## 22. Scenario / corpus authority boundary

A scenario may describe:

- approved/expected components;
- observed components;
- approved/observed relationships;
- source/trust expectations;
- local BOM/provenance/attestation fixture references;
- reference behavior used to stage a synthetic harness.

It may not contain:

- expected verdict;
- expected finding list;
- `is_secure`/`should_fail`;
- evaluator override;
- arbitrary executable hook.

The evaluator is the only verdict authority.

## 23. Modes

Only:

- `STATIC`
- `REPLAY`
- `SIMULATED`
- `LOCAL_SYNTHETIC`

No remote registry/package/model/Git/OCI/signature/attestation mode.

## 24. Hard bounds

Freeze the following v1 bounds:

- `hard_max_bom_bytes`: 16,777,216
- `hard_max_components`: 2,048
- `hard_max_relationships`: 8,192
- `hard_max_dependency_depth`: 64
- `hard_max_attestations_per_component`: 16
- `hard_max_provenance_records_per_component`: 16
- `hard_max_hashes_per_component`: 8
- `hard_max_identifiers_per_component`: 16
- `hard_max_metadata_bytes_per_component`: 32,768
- `hard_max_capabilities_per_component`: 256
- `hard_max_trials`: 10
- `default_trials`: 3
- `max_output_bytes_per_trial`: 1,048,576
- `max_total_output_bytes`: 8,388,608
- `max_state_changes`: 0
- `external_egress_bytes`: 0

No upward clamping. Over-limit input is refused/error before over-budget evidence is normalized or persisted. Run-wide limits cannot reset per component/trial.

## 25. Parser and hostile-input safety

Refuse or sanitize before persistence:

- path traversal;
- bidi/control-character spoofing;
- duplicate conflicting canonical ids;
- malformed/unsupported digests;
- dangling relationship references;
- oversized/deep/fan-out graph bombs;
- arbitrary embedded blobs beyond bounds;
- raw credentials, API keys, bearer tokens, cookies, private keys;
- executable/callback/command fields;
- remote-fetch instructions treated as actions;
- unknown authority-bearing extension fields;
- expected-verdict fields;
- unsafe serialized model/object payloads;
- unsupported BOM versions that would require guesswork.

External references are inert metadata only.

## 26. Minimum SUPPLY-LAB corpus

Create at least 36 scenarios:

1. canonical component identity PASS
2. ambiguous duplicate identity FAIL
3. immutable digest binding PASS
4. digest substitution FAIL
5. mutable reference plus immutable digest PASS
6. mutable reference used as identity FAIL
7. approved source/publisher PASS
8. source/publisher substitution FAIL
9. provenance subject+builder bound PASS
10. wrong provenance subject FAIL
11. unauthorized builder FAIL
12. missing required provenance INCONCLUSIVE
13. attestation subject digest bound PASS
14. wrong attestation subject digest FAIL
15. valid signature evidence but unapproved signer FAIL
16. expected dependency graph PASS
17. unexpected dependency edge FAIL
18. missing expected dependency edge FAIL
19. dangling dependency REFUSE
20. unchanged capability projection PASS
21. capability drift FAIL
22. missing observed capability evidence INCONCLUSIVE
23. model lineage PASS
24. base-model substitution FAIL
25. missing model lineage INCONCLUSIVE
26. dataset provenance PASS
27. dataset substitution FAIL
28. tool/skill/MCP component provenance PASS
29. undeclared external component FAIL
30. CycloneDX normalized import PASS
31. SPDX normalized import PASS
32. CycloneDX/SPDX semantic equivalence PASS
33. unsupported BOM version REFUSE
34. hostile secret/executable/remote-fetch field REFUSE
35. oversized/deep graph REFUSE
36. multiple independent violations retained

Recommended additional controls:

37. benign BOM with optional metadata omissions that do not affect selected invariant PASS
38. conflicting cross-document identity FAIL
39. malformed digest REFUSE
40. repeated equivalent edge deduplication remains deterministic PASS

## 27. Reuse contracts

- Cycle 001 owns verdict/evidence/redaction vocabulary.
- Cycle 006 owns applicability and denominator semantics.
- Cycle 009 owns local-synthetic safety concepts.
- Cycle 012 owns Agentic registry/RiskFamily schema.
- Cycle 014 owns runtime tool misuse/authorization semantics.
- Cycle 015 owns authoritative principal/trust identity concepts.
- Cycle 018 provides cross-invariant aggregation and admission-before-normalization lessons.
- Cycle 020 owns A2A protocol security.
- Cycle 023 will consume supply-chain relationships for attack-graph construction; Cycle 019 must not implement attack-path reasoning.

## 28. Profile

Add `profiles/agentic-supply-chain-security-2026.json` selecting the ten supply-chain properties.

Preserve `agentic-security-baseline-2026` semantics and the existing requirement for `AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE` unless an explicitly backward-compatible additive inclusion is proven.

Do not change Cycle 006 denominator math.

## 29. CLI

Add primary command:

`dare-agent-security validate supply-chain`

Allowed local flags may include:

- `--bom`
- `--format cyclonedx|spdx|dare`
- `--manifest`
- `--attestation`
- `--policy`
- `--mode static|replay|simulated|local-synthetic`
- `--trials`
- `--output-dir`
- `--json`

Optional secondary inventory command may be added only if it reuses the same normalizer:

`dare-agent-security inventory ai-bom`

Prohibited surfaces include:

- `--url`
- `--registry-url`
- `--github`
- `--huggingface`
- `--npm`
- `--pypi`
- `--oci`
- `--download`
- `--pull`
- `--remote`
- `--token`
- `--credential`
- `--private-key`
- `--command`

## 30. Outputs

Expected artifacts:

- `agentic-bom.cdx.json`
- `supply-chain-result.json`
- `supply-chain-components.json`
- `supply-chain-relationships.json`
- `supply-chain-evidence.json`
- `supply-chain-findings.json`
- `summary.md`

Approved bounded PASS wording:

`No agentic supply-chain invariant violation was observed for the tested components and dependency relationships under the recorded evidence.`

Never emit universal wording such as `Supply Chain Secure`, `AI-BOM Secure` or `Agent Secure`.

## 31. CI

Add dedicated job:

`supply-chain-security-2026`

Do not change the repository's PR-open-only trigger.

Before PR creation execute the real workflow job locally:

`python scripts/run-ci-job-locally.py .github/workflows/ci.yml supply-chain-security-2026`

Mandatory regression surfaces:

- Cycle 012 registry/coverage;
- Cycle 013 prompt injection;
- Cycle 014 tool security;
- Cycle 015 identity security;
- Cycle 016 memory security;
- Cycle 017 RAG security;
- Cycle 018 MCP auth security;
- MCP baseline;
- full Rust workspace;
- EN/PT docs.

## 32. Documentation

Add EN/PT concepts and reference documentation covering:

- AI-BOM vs security validation;
- supported input subsets;
- component identity/digest semantics;
- provenance/attestation trust boundary;
- offline/no-fetch guarantee;
- model/dataset lineage;
- relationship to Cycles 020/022/023/024;
- extension guidance without arbitrary parser/executor hooks.

## 33. Acceptance criteria

Every criterion must map to concrete executed evidence in `PROOF.md` during Execute.

AC-01 baseline is pinned to `83fee819ef07f29a8d27cedd95db809b34829fd9`.  
AC-02 existing `AGENTIC_SUPPLY_CHAIN` RiskFamily is reused, not duplicated.  
AC-03 existing `COMPONENT_PROVENANCE` property id remains unchanged.  
AC-04 existing `CAPABILITY_DRIFT` property id remains unchanged.  
AC-05 exactly eight additive Cycle 019 supply-chain properties are added.  
AC-06 no parallel `AGENT.SUPPLY.*` namespace is introduced.  
AC-07 OWASP ASI04 mapping is retained with explicit version/status provenance.  
AC-08 CycloneDX 1.7 support is bounded and version-validated.  
AC-09 SPDX 3.0.1 support is bounded and version-validated.  
AC-10 SLSA provenance status/version is recorded.  
AC-11 in-toto attestation status/version is recorded.  
AC-12 Sigstore/Cosign remains informative/local-evidence only.  
AC-13 future CycloneDX v2.0 is not a baseline PASS requirement.  
AC-14 applicability preserves Cycle 006 NOT_TESTED/NOT_APPLICABLE semantics.  
AC-15 typed component schema is closed.  
AC-16 all 14 approved component classes are represented.  
AC-17 canonical identity does not treat name alone as immutable identity.  
AC-18 name+version alone cannot satisfy immutable artifact identity where digest is required.  
AC-19 mutable references cannot satisfy immutable identity by themselves.  
AC-20 digest algorithm set is allowlisted and malformed digests fail closed.  
AC-21 duplicate conflicting canonical identities fail closed.  
AC-22 typed relationship graph uses a closed relation enum.  
AC-23 dangling relationship endpoints fail closed.  
AC-24 CycloneDX normalizes into the internal model.  
AC-25 SPDX normalizes into the same internal model.  
AC-26 semantically equivalent CycloneDX/SPDX fixtures normalize equivalently.  
AC-27 DARE manifest can express approved identity/trust/relationship expectations without verdict authority.  
AC-28 BOM/manifest/provenance/attestation documents cannot declare final verdict.  
AC-29 raw-byte budget is enforced before parse/normalization persistence.  
AC-30 component/relationship budgets are admission boundaries before persisted deciding evidence.  
AC-31 provenance subject is bound to the assessed component.  
AC-32 provenance subject digest is bound to artifact digest.  
AC-33 builder trust is evaluated independently from provenance presence.  
AC-34 attestation subject digest is bound to the assessed artifact.  
AC-35 local signature verification status does not imply signer trust.  
AC-36 unapproved signer evidence can deterministically fail the applicable trust invariant.  
AC-37 no Fulcio/Rekor/OCI/remote signature requests occur.  
AC-38 expected/observed dependency edges have deterministic PASS and FAIL tests.  
AC-39 unexpected dependency insertion is detected.  
AC-40 missing expected dependency is detected.  
AC-41 existing capability-drift property has PASS/FAIL/INCONCLUSIVE tests.  
AC-42 model lineage has PASS/FAIL/INCONCLUSIVE tests.  
AC-43 model name alone cannot prove base-model lineage.  
AC-44 dataset provenance has PASS/FAIL tests.  
AC-45 dataset scope does not expand into PII/copyright/fairness decisions.  
AC-46 tool/skill/plugin/MCP components participate in supply-chain provenance without duplicating Cycle 014 authorization.  
AC-47 external-agent component inventory does not implement Cycle 020 A2A security.  
AC-48 normalized observations are closed and adapters cannot assert final verdict.  
AC-49 exactly 12 initial invariants are implemented unless an approved pre-execution Review correction is recorded.  
AC-50 PASS requires positive invariant-specific evidence.  
AC-51 missing deciding evidence on an applicable invariant yields INCONCLUSIVE, not PASS.  
AC-52 primary invariant selection cannot hide another concrete applicable FAIL.  
AC-53 all same-trial concrete FAILs are retained before stop-on-first-fail.  
AC-54 secondary PASS/INCONCLUSIVE/ERROR outcomes do not automatically erase primary semantics.  
AC-55 only STATIC/REPLAY/SIMULATED/LOCAL_SYNTHETIC modes exist.  
AC-56 external egress budget is zero.  
AC-57 state-change budget is zero.  
AC-58 no registry/package/model/container/Git remote fetch path exists.  
AC-59 external references are inert metadata and never implicit fetch authorization.  
AC-60 no artifact/model/code execution occurs from imported BOM content.  
AC-61 hostile secret fields are refused/redacted before persistence.  
AC-62 executable/callback/command fields are refused.  
AC-63 path traversal and bidi/control spoofing are refused.  
AC-64 oversized/deep/fan-out graph inputs fail closed.  
AC-65 run-wide hard limits cannot reset per component/trial.  
AC-66 at least 36 SUPPLY-LAB scenarios exist.  
AC-67 secure/vulnerable pairs cover identity, integrity, source, provenance, attestation, dependency, drift, model and dataset dimensions.  
AC-68 multi-violation corpus proves independent finding retention.  
AC-69 hostile fixtures prove parser/refusal behavior without product state change or egress.  
AC-70 `agentic-supply-chain-security-2026` profile is additive.  
AC-71 existing agentic baseline profile semantics remain backward-compatible.  
AC-72 Cycle 006 denominator semantics remain unchanged.  
AC-73 `validate supply-chain` exists with local-safe flags only.  
AC-74 prohibited remote/credential/executable flags do not exist.  
AC-75 output artifacts use bounded wording and retain standards/evidence provenance.  
AC-76 `supply-chain-security-2026` CI job exists without changing PR-open-only trigger.  
AC-77 actual local execution of the real CI job is recorded before PR creation.  
AC-78 Cycle 012/013/014/015/016/017/018 regressions pass.  
AC-79 MCP baseline and coverage regressions pass.  
AC-80 workspace fmt/clippy/test/audit pass.  
AC-81 EN/PT documentation builds pass.  
AC-82 generated fixtures/assets are reproducible if generators are introduced.  
AC-83 no real credentials, private keys, customer identifiers or live registry endpoints exist in fixtures/artifacts.  
AC-84 `REGRESSION.md` records exact execution evidence.  
AC-85 `PROOF.md` maps all 85 criteria to executed evidence.