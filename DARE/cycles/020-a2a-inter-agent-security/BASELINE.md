# Cycle 020 — Baseline

**Cycle:** 020 — A2A / Inter-Agent Communication Security  
**Status:** PLANNING — AWAITING APPROVAL  
**Branch:** `agent/cycle-020-a2a-inter-agent-security`  
**Baseline:** `main @ d2bff1d3789074dffaae45a7ce57a3563daeb1ff`  
**Date frozen:** 2026-09-09

## Why this cycle exists

Cycle 019 intentionally stopped at external-agent inventory. It established that an external agent appearing in an AI-BOM is only an inventory fact and is not evidence that the peer is authenticated, authorized, trustworthy or safe to communicate with.

Cycle 020 owns that missing boundary.

The cycle converts OWASP Agentic Top 10 2026 **ASI07 — Insecure Inter-Agent Communication** into deterministic product behavior for A2A-style exchanges. It focuses on discovery, peer identity, protocol negotiation, authentication evidence, authorization, message/task binding, delegation/authority propagation, tenant/data scope, replay resistance, extensions and push-notification configuration.

## Repository state entering Cycle 020

The baseline already contains:

- the Cycle 012 Agentic registry and `INSECURE_INTER_AGENT_COMMUNICATION` risk family;
- the existing property IDs `AGENT.A2A.MESSAGE_AUTHENTICITY` and `AGENT.A2A.AUTHORITY_PROPAGATION`;
- Cycle 013 direct/indirect prompt-injection boundaries;
- Cycle 014 tool authorization and tool-output/metadata trust boundaries;
- Cycle 015 principal, delegation, privilege and tenant/resource-owner identity contracts;
- Cycle 016 memory/context integrity boundaries;
- Cycle 017 retrieval/RAG trust boundaries;
- Cycle 018 deterministic cross-invariant FAIL aggregation semantics;
- Cycle 019 external-agent inventory, supply-chain identity/provenance and offline evidence discipline;
- Cycle 001 evidence/verdict/redaction primitives;
- Cycle 006 applicability/coverage semantics;
- Cycle 009 bounded local synthetic execution concepts.

Cycle 020 must reuse those contracts rather than create competing identity, verdict, coverage, prompt-injection or authorization models.

## Standards/status snapshot

Planning is frozen against the following current references:

- OWASP Top 10 for Agentic Applications 2026 — ASI07 Insecure Inter-Agent Communication;
- Agent2Agent (A2A) Protocol Specification — latest released version 1.0.0;
- A2A Agent Card, supported interfaces, security schemes, task/message model, protocol version negotiation, extensions and push-notification security requirements;
- RFC 7515 JWS for Agent Card signature representation;
- RFC 8785 JSON Canonicalization Scheme for signed Agent Card canonicalization;
- standard HTTPS/TLS and OAuth/OIDC/API-key authentication concepts only as declared local evidence, never by live credential use.

This is a planning snapshot, not permission to fetch remote Agent Cards, keys, tokens, certificates, registries or endpoints during Cycle 020 execution.

## Frozen safety boundary

Cycle 020 is **local/offline only**.

Authorized execution surfaces:

- local Agent Card documents;
- local captured A2A request/response/task/message traces;
- local policy manifests;
- local identity/delegation evidence;
- local signature/authentication verification evidence already produced by an external trusted verifier or fixture harness;
- simulated and local-synthetic fixtures that never contact a real peer.

Explicitly prohibited:

- connecting to live A2A endpoints;
- downloading Agent Cards from `.well-known` or registries;
- obtaining OAuth/OIDC tokens;
- using API keys, bearer tokens, client secrets or private keys;
- performing real TLS handshakes or certificate validation;
- sending real A2A messages, task requests, cancellations or push notifications;
- testing real webhooks;
- following discovered URLs;
- arbitrary shell/process execution;
- target state changes;
- product state mutation outside repository/test artifacts.

A URL, endpoint, `jku`, issuer, token endpoint, webhook destination or Agent Card location inside imported evidence is inert metadata.

## Scope ownership

Cycle 020 owns:

- A2A discovery trust and Agent Card binding;
- peer identity evidence binding;
- declared authentication/security-requirement consistency;
- skill-level authorization evidence;
- message authenticity/integrity evidence;
- message semantic authority boundary for peer-controlled content;
- task/context/tenant correlation;
- authority/delegation non-amplification across agent hops;
- data-scope preservation across inter-agent exchange;
- replay/idempotency safety evidence;
- protocol/transport/version downgrade detection;
- extension declaration/use trust boundaries;
- push-notification configuration safety analysis;
- deterministic PASS/FAIL/INCONCLUSIVE/ERROR aggregation for the above.

## Explicitly deferred

Not authorized in Cycle 020:

- multi-turn adaptive trust-grooming/adversarial attack loops — Cycle 021;
- remote authorized validation against live A2A endpoints — Cycle 022;
- graph-wide attack-path construction across agents/tools/data — Cycle 023;
- generalized cascading-failure/retry amplification engine beyond the replay/idempotency boundary needed for A2A correctness;
- production credential acquisition or token exchange;
- cryptographic signing with real private keys;
- remote JWK/JWKS/JWS key retrieval;
- live SSRF validation of webhook destinations;
- tool-execution authorization already owned by Cycle 014;
- generalized principal/delegation semantics already owned by Cycle 015;
- generalized prompt injection already owned by Cycle 013.

## Core distinctions the implementation must preserve

```text
external agent listed          != trusted peer
discovered Agent Card          != authenticated identity
signed Agent Card              != authorized provider
TLS server identity            != agent-level authorization
declared security scheme       != successful authentication
successful authentication      != skill authorization
schema-valid message           != authentic message
authentic message              != authorized instruction
peer text/content              != privileged instruction
taskId match                   != principal/context match
delegation                     != privilege amplification
message retry                  != safe replay
protocol compatibility         != permission to downgrade
extension declaration          != extension authority
webhook URL                    != permission to connect
tenant routing value           != proof of tenant authorization
```

## Planning outcome

Cycle 020 should add one bounded offline A2A security engine, one additive profile, one CLI validation path, one A2A-LAB corpus, dedicated CI coverage, EN/PT documentation and exact proof artifacts.

No task is authorized until the user approves the Cycle 020 plan.