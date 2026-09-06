# Cycle 017 — Product Owner Approval

**Status:** APPROVED FOR EXECUTION  
**Cycle:** 017 — RAG & Retrieval Security  
**Approved at:** 2026-09-06  
**Base:** `main @ c0cd5edbb5a157d285b20177b7bd20a23b1811cc`  
**Planning head:** `aa6b6d5ed1d97564dbc76eb7a8236ad3007c4738`  
**Branch:** `agent/cycle-017-rag-retrieval-security`

## Approval

The Product Owner explicitly approves all frozen planning artifacts, all 66 acceptance criteria, and all 38 execution tasks for Cycle 017.

Approved artifacts:
- `EVALUATION.md`
- `DESIGN.md`
- `BLUEPRINT.md`
- `TASKS.md`
- `dare-dag.yaml`

Execution may proceed without intermediate approval while remaining inside the approved scope.

## Authorized scope

Implement deterministic, evidence-first RAG/retrieval security validation using only `REPLAY`, `SIMULATED`, and `LOCAL_SYNTHETIC` modes. Approved surfaces include retrieval authorization, tenant/principal/collection boundaries, document ACLs, metadata filters, document/chunk provenance, candidate/result-set integrity, top-k bounds, protected-document nondisclosure, fallback authority boundaries, retrieved-content trust handling, evidence integration, bounded CLI/reporting, profile/coverage integration, documentation, and CI.

## Required reuse

- Cycle 001 evidence/verdict contracts;
- Cycle 009 local-synthetic budgets/kill switch;
- Cycle 013 trust-boundary concepts without duplicating the prompt-injection evaluator;
- Cycle 015 principal/tenant identity semantics;
- Cycle 016 persisted-memory boundary, keeping retrieval distinct from memory;
- Cycle 006 coverage denominator semantics unchanged.

## Explicit exclusions

Not authorized:
- live/remote vector databases, retrievers, search engines, or providers;
- Pinecone, Weaviate, Qdrant, Redis, PostgreSQL, OpenSearch, Elasticsearch connections;
- production/customer documents;
- live embedding/model inference;
- OAuth/OIDC/JWT/JWKS/IdP/PDP/AuthZEN remote work (Cycle 018);
- arbitrary model-generated shell or callbacks;
- credentials or provider tokens beyond synthetic refusal/redaction fixtures;
- destructive, persistent, remote, or production state-changing actions.

## Security invariants

Retrieval relevance is not authorization. Similarity score, embedding output, LLM prose, or heuristic judgment may not be the final security judge. PASS requires invariant-specific positive evidence. Missing required evidence yields `INCONCLUSIVE`. Independent violations must remain independently observable.

## Release gate

Before a PR may be opened:
1. tasks 001–038 complete;
2. all 66 acceptance criteria mapped to executed evidence;
3. `cargo fmt --all --check` green;
4. `cargo clippy --workspace --all-targets -- -D warnings` green;
5. `cargo test --workspace` green;
6. `cargo audit` resolved under project policy;
7. Cycle 013/014/015/016 plus Agentic/MCP regressions green;
8. documentation builds green under repository policy;
9. `python scripts/run-ci-job-locally.py .github/workflows/ci.yml rag-security-2026` passes using the real YAML job;
10. `REGRESSION.md` and `PROOF.md` complete;
11. final branch head pushed before PR;
12. PR opened once, preserving the PR-open-only workflow trigger.
