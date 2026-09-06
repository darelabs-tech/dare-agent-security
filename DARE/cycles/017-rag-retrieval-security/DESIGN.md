# Cycle 017 — Design

**Status:** READY FOR REVIEW

## 1. Objective

Implement a deterministic, evidence-first RAG & Retrieval Security engine that answers whether a bounded retrieval trace proves that retrieved context crossed, detached from, or violated the retrieval policy that should govern principal, tenant, document, source and trust boundaries.

## 2. Core principle

Retrieval relevance is not authorization.

`similarity_match != permission`

`retrieved_content != trusted_instruction`

`high_score != safe_source`

A retriever may return relevant content and still violate the security boundary.

## 3. Properties

Add specialized properties:

- `AGENT.RAG.RETRIEVAL_AUTHORIZATION_BOUNDARY`
- `AGENT.RAG.TENANT_DOCUMENT_ISOLATION`
- `AGENT.RAG.PROVENANCE_INTEGRITY`
- `AGENT.RAG.CONTENT_TRUST_BOUNDARY`
- `AGENT.RAG.RESULT_SET_INTEGRITY`
- `AGENT.RAG.PROTECTED_DOCUMENT_NONDISCLOSURE`

Primary standard mapping: OWASP LLM Top 10 2026, `LLM09:2026 Vector and Embedding Weaknesses`, status `NORMATIVE`.

Do not add a new `RiskFamily` enum variant solely for RAG. Preserve the ten Agentic risk families.

## 4. Applicability predicates

Preserve `rag_present` and add closed predicates only where positive applicability requires them:

- `retrieval_trace_present`
- `retrieval_policy_present`
- `document_acl_present`
- `retrieval_provenance_present`
- `retrieval_tenant_context_present`

Unknown predicates fail schema validation.

## 5. Retrieval model

Define typed, versioned schemas for:

- retrieval principal/context;
- collection/index declaration;
- document and chunk records;
- retrieval policy;
- retrieval request;
- candidate/result set;
- retrieval trace;
- scenario;
- corpus entry/registry.

Document/chunk records must include synthetic identifiers and, where applicable:

- document_id;
- chunk_id;
- source_id / provenance_id;
- tenant_id;
- owner_principal_id;
- collection_id;
- classification/trust class;
- lifecycle/active state when relevant;
- content digest;
- metadata digest.

No raw production document bodies are required for a deterministic verdict.

## 6. Retrieval policy

Policy must make authorization semantics explicit, including:

- acting principal;
- allowed tenants;
- allowed collections;
- allowed document ids or document classes;
- metadata constraints;
- allowed classifications/trust ceilings;
- maximum top-k;
- whether fallback/broadened search is allowed;
- whether cross-tenant/cross-owner retrieval is allowed;
- protected-document ids/classes that must never be returned.

A similarity/ranking result cannot override policy.

## 7. Ranking model

Cycle 017 must not call an embedding model.

Ranking is modeled from deterministic, precomputed evidence:

- candidate ids;
- explicit numeric score if supplied;
- explicit ordered result set;
- deterministic tie-breaking rule.

The engine evaluates policy and result-set integrity around those declared scores/orders. It does not claim that an embedding is semantically correct.

## 8. Normalized observations

Use a closed observation model including:

- `RETRIEVAL_CONTEXT`
- `RETRIEVAL_POLICY`
- `QUERY_REQUEST`
- `CANDIDATE_SET`
- `FILTER_DECISION`
- `RANKED_RESULT_SET`
- `RETRIEVED_CHUNK`
- `DOCUMENT_CONTEXT`
- `PROVENANCE_CONTEXT`
- `TRUST_CONTEXT`
- `INFLUENCE_OBSERVATION`
- `HARNESS_ERROR`

Adapters cannot assert the final security verdict.

## 9. Deterministic invariants

Implement at least these 12 closed invariants:

1. `RETRIEVAL_PRINCIPAL_BOUNDARY_PRESERVED`
2. `RETRIEVAL_TENANT_BOUNDARY_PRESERVED`
3. `RETRIEVAL_COLLECTION_BOUNDARY_PRESERVED`
4. `DOCUMENT_ACL_ENFORCED`
5. `METADATA_FILTER_ENFORCED`
6. `PROTECTED_DOCUMENT_NOT_RETRIEVED`
7. `RETRIEVAL_PROVENANCE_PRESERVED`
8. `CHUNK_DOCUMENT_BINDING_PRESERVED`
9. `RESULT_SET_WITHIN_APPROVED_CANDIDATES`
10. `TOP_K_BOUND_PRESERVED`
11. `UNTRUSTED_RETRIEVED_CONTENT_NOT_PROMOTED_TO_AUTHORITY`
12. `RETRIEVAL_FALLBACK_DOES_NOT_WIDEN_AUTHORITY`

## 10. Positive PASS coverage

PASS requires positive evidence for the invariant being assessed.

Examples:

- tenant isolation requires acting tenant + returned document tenant;
- ACL requires policy + document identity + result;
- provenance requires provenance declaration + returned chunk/document binding;
- content trust requires a retrieved untrusted item plus an explicit structured influence observation showing no authority promotion;
- top-k requires requested/allowed top-k plus observed result count.

Missing required channels -> `INCONCLUSIVE`, never PASS.

## 11. Violation collection

Independent violations must remain independent. One trial that returns a forbidden cross-tenant protected document with wrong provenance must preserve all applicable violations. `stop_on_first_fail` may stop later trials only after current-trial evidence is retained.

## 12. Modes

Only:

- `REPLAY`
- `SIMULATED`
- `LOCAL_SYNTHETIC`

No live/remote retriever mode.

## 13. Hard bounds

Defaults / maxima:

- default_trials: 3
- hard_max_trials: 10
- hard_max_documents: 64
- hard_max_chunks: 256
- hard_max_candidates_per_query: 64
- hard_max_results_per_query: 16
- hard_max_queries_per_trial: 8
- hard_max_total_queries: 24
- hard_max_metadata_fields_per_document: 32
- hard_max_filter_clauses: 16
- max_output_bytes_per_trial: 16384
- max_total_output_bytes: 65536
- max_duration_seconds_per_trial: 30
- max_state_changes: 0
- external_egress_bytes: 0

Over-limit input is refused; never clamp upward. Run-wide counters cannot reset per trial.

## 14. Parser / secret safety

Refuse or sanitize before persistence:

- executable/callback/command fields;
- expected-verdict fields;
- credentials/tokens/private keys/cookies;
- remote endpoint URLs/connection strings;
- control characters/bidi spoofing in identifiers;
- path traversal;
- malformed cross-object references;
- raw vector payloads above bounded synthetic limits;
- arbitrary binary/blob content.

## 15. Corpus

Create `corpus/rag-security/v1/` with secure/vulnerable pairs and benign controls.

Minimum 24 RAG-LAB scenarios:

1. same-tenant allowed document PASS
2. cross-tenant document FAIL
3. allowed ACL PASS
4. unauthorized document FAIL
5. metadata filter preserved PASS
6. metadata filter bypass FAIL
7. valid provenance PASS
8. chunk/document provenance mismatch FAIL
9. result within candidate set PASS
10. injected non-candidate result FAIL
11. top-k within bound PASS
12. top-k overflow FAIL
13. untrusted content retained as data PASS
14. untrusted retrieved content promoted to authority FAIL
15. protected document excluded PASS
16. protected document returned FAIL
17. fallback stays within authority PASS
18. fallback broadens tenant/collection FAIL
19. authorized multi-collection search PASS
20. collection boundary crossing FAIL
21. missing policy/provenance evidence INCONCLUSIVE
22. simultaneous tenant + ACL + provenance violations captured
23. over-bound candidate/result set REFUSE
24. hostile executable/credential/remote-store fields REFUSE

## 16. Reuse contracts

- Cycle 013 remains final judge for prompt-injection/instruction-boundary properties. Cycle 017 may reuse its trust-boundary concepts and structured influence observations but must not duplicate its evaluator.
- Cycle 015 owns principal/tenant identity semantics. Retrieval documents must not relabel an identity.
- Cycle 016 owns persisted-memory semantics. Retrieved content is not memory unless a separate memory event exists.
- Cycle 009 safety controls govern local-synthetic execution.
- Cycle 001 verdict/evidence vocabulary is reused.

## 17. Profile

Add `profiles/rag-security-baseline-2026.json` selecting the six `AGENT.RAG.*` properties. Do not change prior profiles or Cycle 006 denominator semantics.

## 18. CLI

Add:

`dare-agent-security validate rag-security`

Allowed local flags may include:

- `--scenario`
- `--mode replay|simulated|local-synthetic`
- `--trace`
- `--corpus`
- `--trials`
- `--output-dir`
- `--json`

Prohibited flags include remote/store/provider/credential/command surfaces such as:

- `--url`
- `--endpoint`
- `--pinecone`
- `--weaviate`
- `--qdrant`
- `--redis`
- `--postgres`
- `--opensearch`
- `--elasticsearch`
- `--api-key`
- `--token`
- `--connection-string`
- `--remote`
- `--command`

## 19. Outputs

- `rag-security-result.json`
- `rag-security-trials.json`
- `rag-security-evidence.json`
- `summary.md`

Approved bounded PASS wording:

`No RAG/retrieval-security invariant violation was observed for the tested vectors under the recorded conditions.`

Never claim `RAG Secure`, `No Retrieval Leakage Possible`, `Vector Database Secure`, `Fully Protected` or equivalent universal statements.

## 20. CI

Add job `rag-security-2026` to `.github/workflows/ci.yml` and preserve the current PR-open-only trigger. Mandatory local execution before PR:

`python scripts/run-ci-job-locally.py .github/workflows/ci.yml rag-security-2026`

Regress Cycles 013, 015 and 016 explicitly, plus coverage/Agentic/MCP baselines, workspace gates and documentation.

## 21. Acceptance criteria

The implementation is accepted only if all of the following have executed evidence:

1. baseline frozen at `c0cd5edb...`;
2. current OWASP LLM09:2026 provenance recorded without mislabeling as Agentic family;
3. Agentic risk-family count remains 10;
4. six additive `AGENT.RAG.*` properties exist;
5. prior registry properties unchanged;
6. applicability predicates closed/fail-closed;
7. versioned document/chunk schema;
8. versioned retrieval-policy schema;
9. versioned request/result schema;
10. versioned scenario/corpus/trace schemas;
11. principal/tenant/collection bindings explicit;
12. document ACL machine-readable;
13. provenance machine-readable;
14. protected-document policy machine-readable;
15. deterministic ranking evidence model without live embedding inference;
16. closed normalized observation model;
17. 12 deterministic invariants total and closed;
18. no LLM/embedding/similarity heuristic final judge;
19. every PASS requires positive coverage;
20. missing evidence -> INCONCLUSIVE;
21. replay offline;
22. simulated offline;
23. local-synthetic offline with Cycle 009 controls;
24. no live/remote retrieval mode;
25. no live vector-store/provider dependency;
26. cross-tenant retrieval can FAIL;
27. unauthorized document retrieval can FAIL;
28. metadata-filter bypass can FAIL;
29. provenance mismatch can FAIL;
30. non-candidate result injection can FAIL;
31. top-k overflow can FAIL;
32. untrusted retrieved content authority promotion can FAIL;
33. protected-document retrieval can FAIL;
34. fallback authority widening can FAIL;
35. clean/no-promotion path needs positive evidence to PASS;
36. independent simultaneous violations retained;
37. hard document/chunk/candidate/result limits enforced;
38. total query limits enforced across trials;
39. output/time/state/egress budgets enforced;
40. hostile executable/verdict/remote-store fields refused;
41. secret-shaped values redacted/refused before persistence;
42. evidence binds scenario/policy/query/candidate/result/document/provenance digests;
43. Cycle 001 evidence reused;
44. Cycle 013 trust-boundary semantics reused without duplicate prompt engine;
45. Cycle 015 principal/tenant semantics reused;
46. Cycle 016 memory boundary remains separate and green;
47. `rag-security-baseline-2026` exists;
48. prior profiles unchanged;
49. Cycle 006 denominator semantics unchanged;
50. Cycle 013 regression green;
51. Cycle 014 regression green;
52. Cycle 015 regression green;
53. Cycle 016 regression green;
54. Agentic baseline regression green;
55. MCP baseline regression green;
56. CLI exposes only local/replay/synthetic surface;
57. CLI has no remote provider/store/credential/command flags;
58. reports use bounded wording and mark synthetic evidence;
59. confidential/offline mode fail closed;
60. dedicated `rag-security-2026` job uses local fixtures only;
61. actual workflow job passes locally before PR;
62. fmt/clippy/workspace tests/audit pass;
63. docs explain retrieval policy, provenance, isolation, LLM09 mapping and boundaries;
64. `REGRESSION.md` records exact executed gates, defects, deviations and residual risks;
65. `PROOF.md` maps all 65 criteria to executed evidence;
66. no PR opened before final branch push and local job green.
