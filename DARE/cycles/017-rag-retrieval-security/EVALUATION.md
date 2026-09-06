# Cycle 017 — Evaluation

**Cycle:** 017 — RAG & Retrieval Security  
**Status:** READY FOR REVIEW  
**Baseline:** `main @ c0cd5edbb5a157d285b20177b7bd20a23b1811cc`  
**Branch:** `agent/cycle-017-rag-retrieval-security`

## Problem

Cycle 016 deliberately stopped before retrieval. The current product can prove memory/context boundaries, but it does not yet prove whether a retrieval layer returns only authorized, correctly scoped, provenance-preserving context to an agent.

RAG introduces a distinct trust boundary: a query is transformed into a retrieval request; a retriever selects chunks/documents; metadata filters may narrow candidates; similarity/ranking selects results; the returned context may then influence the model. A system can therefore fail without any memory write at all.

## Security question

Can DARE deterministically prove, from local/synthetic/replayed retrieval traces, whether retrieved context remained within approved principal/tenant/document/source boundaries and whether untrusted or poisoned retrieved content remained data rather than silently becoming authority?

## In scope

- retrieval request and retrieval result modeling;
- document/chunk provenance;
- tenant, principal and collection/index isolation;
- metadata filter enforcement;
- document ACL / allowed-document-set semantics;
- chunk/document substitution and provenance mismatch;
- retrieval result contamination/poisoning;
- ranking/result-set integrity from precomputed scores or explicit ordered candidates;
- top-k and candidate-set bounds;
- retrieved-content trust boundary before agent influence;
- protected/canary document non-disclosure in synthetic fixtures;
- local replay, simulated and local-synthetic execution;
- evidence, CLI, profile, reporting, CI and regressions.

## Explicitly out of scope

- live vector databases or hosted RAG services;
- network calls to Pinecone, Weaviate, Qdrant, Elasticsearch/OpenSearch, pgvector, Redis, Chroma, Milvus or SaaS retrieval APIs;
- real embeddings or model inference as a security judge;
- embedding quality, hallucination quality, answer factuality or relevance benchmarking;
- prompt injection engine duplication (Cycle 013 remains authoritative for instruction-boundary evaluation);
- memory engine duplication (Cycle 016 remains authoritative for persisted-memory semantics);
- OAuth/OIDC/JWT/JWKS/IdP/PDP/AuthZEN and MCP auth hardening (Cycle 018);
- production documents, customer indices, credentials, secrets or destructive/state-changing operations.

## Standards snapshot

- OWASP Top 10 for LLM Applications 2026: **LLM09:2026 Vector and Embedding Weaknesses** is the primary risk context for this cycle.
- The 2026 guidance treats similarity search/retrieval as a trust boundary and calls out weaknesses including poisoned embeddings/data, cross-context leakage and insufficient authorization/isolation around vector/embedding systems.
- LLM01 Prompt Injection remains adjacent but not equivalent; Cycle 013 owns the prompt/instruction boundary.
- OWASP Agentic Top 10 2026 remains additive context only. Do not invent an 11th Agentic risk family for RAG.

## Design decision

Introduce specialized `AGENT.RAG.*` properties. Because `risk_family` is optional in coverage v2, RAG properties may remain outside the ten Agentic risk families while still carrying normative LLM09 provenance. The Agentic family count must remain 10.

## Reuse requirements

- Cycle 001 evidence/verdict vocabulary;
- Cycle 009 budgets and local-synthetic safety controls;
- Cycle 013 external-content trust-boundary semantics;
- Cycle 015 principal/tenant/resource conventions;
- Cycle 016 provenance/trust and cross-tenant concepts where compatible;
- Cycle 006 denominator semantics unchanged.

## Outcome

A local/offline RAG Security Validation Engine with bounded claims that can deterministically report PASS / FAIL / INCONCLUSIVE / ERROR for tested retrieval invariants without accessing a real vector store or using an LLM/embedding score as the final security judge.
