# Cycle 016 — Memory & Context Poisoning Security — Evaluation

**Status:** READY FOR REVIEW  
**Cycle:** 016  
**Base branch:** `main`  
**Baseline commit:** `9d543ae0ec202b7ad05a852179ca5703857a317a`  
**Branch:** `agent/cycle-016-memory-context-poisoning-security`  
**Approval:** PENDING — no `APPROVAL.md` before explicit Product Owner approval.

## Problem

DARE currently has strong deterministic boundaries for prompt/instruction integrity (Cycle 013), tool/action integrity (Cycle 014), and identity/authority integrity (Cycle 015). The registry already declares two memory-risk properties:

- `AGENT.MEMORY.CONTEXT_INTEGRITY`
- `AGENT.MEMORY.TENANT_BOUNDARY`

What is missing is a dedicated engine that can prove, from bounded observations, whether persisted memory/context lost provenance, crossed a principal/tenant boundary, was overwritten by an untrusted source, or influenced a later decision/action outside the authorized objective.

## Core security question

> Did a memory or persisted-context event deterministically prove that untrusted, stale, cross-tenant, cross-principal, or integrity-violating state influenced a later agent decision or operation?

## Why now

Cycle 016 is the natural continuation after Cycle 015 because memory is a long-lived trust boundary. A safe identity/tool layer can still be undermined if poisoned state survives across turns and is later recalled as trusted context.

## Reuse requirements

Cycle 016 must reuse rather than duplicate:

- Cycle 001 evidence/verdict vocabulary;
- Cycle 013 instruction-boundary concepts for untrusted data becoming authority;
- Cycle 015 principal/tenant/resource identity concepts;
- Cycle 009 local-synthetic budgets/kill-switch where applicable;
- Cycle 006 applicability/coverage denominator semantics.

## Scope

### In scope

- memory item provenance;
- source/trust classification;
- write/update/overwrite/delete/recall observations;
- principal and tenant binding;
- memory ownership and namespace binding;
- stale/expired/revoked memory handling;
- integrity digest mismatch/substitution;
- untrusted content persisted as authoritative memory;
- cross-session persistence;
- poisoned-memory recall influencing objective, authorization context, tool selection, arguments, or protected fields;
- bounded replay/simulated/local-synthetic modes;
- deterministic invariants and positive PASS coverage;
- sanitized evidence and redaction;
- profile/coverage/product/CLI/CI integration.

### Out of scope

- vector database/RAG retrieval authorization and ACL semantics (Cycle 017);
- embedding similarity quality or ranking quality;
- prompt injection as a generic problem already covered by Cycle 013 except where persistence/recall is the distinguishing feature;
- live production memory stores;
- remote databases;
- destructive deletion of real memory;
- live user/customer data;
- OAuth/JWT/cryptographic identity (Cycle 018);
- arbitrary code execution;
- generalized data-loss prevention.

## Risk hypotheses

1. Untrusted user/tool/external content may be persisted without provenance and later recalled as trusted authority.
2. Memory may cross principal or tenant namespaces.
3. A memory item may be overwritten/substituted while retaining its trusted identity.
4. Expired/revoked memory may still influence behavior.
5. A memory item may affect later decisions even when no positive evidence shows the agent actually recalled the correct item.
6. A clean output may be confused with absence of recall evidence; this must remain `INCONCLUSIVE`.
7. Multiple simultaneous memory violations must remain independently observable.

## Proposed additive properties

Preserve existing properties unchanged:

- `AGENT.MEMORY.CONTEXT_INTEGRITY`
- `AGENT.MEMORY.TENANT_BOUNDARY`

Proposed additions:

- `AGENT.MEMORY.PROVENANCE_INTEGRITY`
- `AGENT.MEMORY.WRITE_TRUST_BOUNDARY`
- `AGENT.MEMORY.RECALL_AUTHORITY_BOUNDARY`
- `AGENT.MEMORY.LIFECYCLE_VALIDITY`

All remain under `MEMORY_CONTEXT_POISONING`.

## Proposed invariants

- `MEMORY_PROVENANCE_PRESENT`
- `MEMORY_SOURCE_TRUST_PRESERVED`
- `UNTRUSTED_MEMORY_NOT_PROMOTED_TO_AUTHORITY`
- `MEMORY_PRINCIPAL_BOUNDARY_PRESERVED`
- `MEMORY_TENANT_BOUNDARY_PRESERVED`
- `MEMORY_NAMESPACE_BOUNDARY_PRESERVED`
- `MEMORY_INTEGRITY_DIGEST_PRESERVED`
- `MEMORY_WRITE_WITHIN_POLICY`
- `EXPIRED_OR_REVOKED_MEMORY_NOT_USED`
- `RECALLED_MEMORY_MATCHES_REQUESTED_CONTEXT`
- `MEMORY_INFLUENCE_WITHIN_AUTHORIZED_OBJECTIVE`
- `PROTECTED_FIELD_NOT_DERIVED_FROM_POISONED_MEMORY`

## Safety posture

Only declarative/synthetic memory items and traces. No live storage, real secrets, remote providers, destructive cleanup, external egress, or state change beyond local fixture generation.

## Recommendation

Proceed with Cycle 016 as a dedicated deterministic Memory Security engine with replay/simulated/local-synthetic modes and a hard separation from Cycle 017 RAG retrieval security.
