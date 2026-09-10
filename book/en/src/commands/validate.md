# `validate`

Power-user command group. Offline, deterministic validation harnesses — each
subcommand is what the product `assess` command orchestrates under the hood.

```bash
dare-agent-security validate <SUBCOMMAND> [OPTIONS]
```

## `validate coaz-integrity`

Built-in COAZ authorization-to-execution integrity vectors (Cycle 003,
synthetic fixtures only).

```bash
dare-agent-security validate coaz-integrity --all
dare-agent-security validate coaz-integrity --fixture COAZ-INTEGRITY-003 --json
dare-agent-security validate coaz-integrity --all --reference-mode vulnerable
```

`--all` / `--fixture <ID>` are mutually exclusive. `--reference-mode
vulnerable` proves stale-permit forwarding on mutation vectors using the
intentionally vulnerable reference PEP — it never accepts arbitrary URL/stdio
targets. See [`docs/coaz-integrity.md`](https://github.com/darelabs-tech/dare-agent-security/blob/main/docs/coaz-integrity.md).

## `validate coverage`

Evaluate an assessment profile against typed facts (Cycle 006). Does not
replace `discover` or `validate coaz-integrity`.

```bash
dare-agent-security validate coverage \
  --profile mcp-security-baseline \
  --facts fixtures/coverage/fixture-a-tools-static-roe.json \
  --output-dir .dare-agent-security/coverage \
  --json
```

`--profile` accepts a built-in profile id or a path to a profile JSON.
`--min-required-coverage` (0.0–1.0) and `--fail-on-required-blocked` gate the
exit code. See [Assessment Coverage](../concepts/assessment-coverage.md).

## `validate benchmark`

Offline benchmark corpus methodology runner (Cycle 007).

```bash
dare-agent-security validate benchmark \
  --corpus benchmark/corpus/pilot-methodology-v1/corpus-manifest.json \
  --output-dir .dare-agent-security/benchmark \
  --mode local-passive
```

The pilot corpus validates *methodology*, not ecosystem prevalence.
`AUTHORIZED_DYNAMIC` mode requires `--authorized-dynamic-roe` and is refused
without it.

## `validate attack-graph`

Build and validate a deterministic bounded Agent Attack Graph (Cycle 008).

```bash
dare-agent-security validate attack-graph \
  --facts fixtures/attack-graph/safe-read.json \
  --output-dir .dare-agent-security/attack-graph
```

`--max-depth` (default 8, hard limit 64) and `--max-paths` (default 64, hard
limit 10000) bound the analysis. Analysis only — no attack path is executed.
See [Attack Graph](../concepts/attack-graph.md).

## `validate adversarial`

Controlled, offline-first adversarial validation (Cycle 009).

```bash
dare-agent-security validate adversarial \
  --fixture fixtures/adversarial/confused-deputy.json \
  --mode local-synthetic \
  --output-dir .dare-agent-security/adversarial
```

Default mode is `plan-only`. `local-synthetic` is in-memory and offline.
`authorized-dynamic` requires a valid ROE; remote dynamic execution remains
disabled in the MVP. See [Validation Modes](../concepts/validation.md) and
[Adversarial Validation](../assessments/adversarial.md).

## `validate continuous`

Plan deterministic continuous security revalidation (Cycle 010).

```bash
dare-agent-security validate continuous \
  --fixture fixtures/continuous/unrelated-change.json \
  --mode plan-only \
  --output-dir .dare-agent-security/continuous
```

Offline and never grants `AUTHORIZED_DYNAMIC`; the Cycle 009 ROE requirement
still applies. See [Continuous Validation](../assessments/continuous.md).

## `validate identity-security`

Run bounded local identity, privilege and delegation validation (Cycle 015).

```bash
dare-agent-security validate identity-security   --scenario IDENTITY-LAB-001   --mode simulated   --output-dir .dare-agent-security/identity-security
```

Modes are `replay`, `simulated` and `local-synthetic`; all three are local and
offline. There is no `--url`, `--endpoint`, `--issuer`, `--jwks`, `--token`,
`--bearer`, `--client-secret`, `--api-key`, `--pdp-url`, `--authzen-url`,
`--remote` or `--command` flag, and no credential is read from the environment.

Operations are observed and never dispatched: no identity provider,
authorization server or resource is contacted, no token is parsed, and no real
tenant data is touched to demonstrate a boundary crossing. See
[Identity, Privilege and Delegation Validation](../concepts/identity-security.md).

## `validate memory-security`

Run bounded local memory and context poisoning validation (Cycle 016).

```bash
dare-agent-security validate memory-security   --scenario MEMORY-LAB-001   --mode simulated   --output-dir .dare-agent-security/memory-security
```

Modes are `replay`, `simulated` and `local-synthetic`; all three are local and
offline. There is no `--url`, `--redis`, `--postgres`, `--vector-db`,
`--pinecone`, `--qdrant`, `--provider`, `--token`, `--api-key`, `--remote` or
`--command` flag, and no connection string is read from the environment.

Memory is described from local synthetic fixtures and never persisted: no Redis,
PostgreSQL, vector database, SaaS memory service, remote MCP server, production
agent or customer memory is involved, and lifecycle is evaluated at the logical
time each scenario declares rather than against the machine's clock. See
[Memory and Context Poisoning Validation](../concepts/memory-security.md).

## `validate rag-security`

Run bounded local RAG and retrieval security validation (Cycle 017).

```bash
dare-agent-security validate rag-security   --scenario RAG-LAB-001   --mode simulated   --output-dir .dare-agent-security/rag-security
```

Modes are `replay`, `simulated` and `local-synthetic`; all three are local and
offline. There is no `--url`, `--endpoint`, `--pinecone`, `--weaviate`,
`--qdrant`, `--redis`, `--postgres`, `--opensearch`, `--elasticsearch`,
`--api-key`, `--token`, `--connection-string`, `--remote` or `--command` flag,
and no connection string is read from the environment.

Documents are described from local synthetic fixtures and are never indexed,
embedded or persisted: no Pinecone, Weaviate, Qdrant, Redis, PostgreSQL,
OpenSearch, Elasticsearch, SaaS retrieval API, remote MCP server, production
retriever or customer corpus is involved. No embedding is computed or compared,
and no score, ranking, similarity or reranker decides any verdict — retrieval
relevance is not authorization. See
[RAG and Retrieval Security Validation](../concepts/rag-security.md).

## `validate supply-chain`

Bounded local agentic supply-chain and AI-BOM validation (Cycle 019). Reads
local bill-of-materials, provenance and attestation documents and evaluates
twelve invariants over component identity, artifact integrity, source trust,
provenance and attestation binding, dependency-graph integrity, capability
drift, model lineage, dataset provenance and BOM completeness.

```bash
dare-agent-security validate supply-chain   --scenario SUPPLY-LAB-004   --mode simulated   --output-dir .dare-agent-security/supply-chain

dare-agent-security validate supply-chain   --scenario scenarios/production-bom.json   --mode static   --evidence-dir evidence/2026-q3   --output-dir .dare-agent-security/supply-chain
```

Modes are `static`, `replay`, `simulated` and `local-synthetic`; all four are
local and offline. There is no `--registry`, `--registry-url`, `--fetch`,
`--download`, `--resolve`, `--model-hub`, `--oci`, `--git`, `--rekor`,
`--fulcio`, `--transparency-log`, `--sign`, `--key`, `--private-key`,
`--token`, `--remote`, `--command` or `--extract` flag, and no credential is
read from the environment.

Under `--mode replay`, `--manifest` is required alongside `--capture`: a
recording may not supply the policy it is judged against, or it would approve
its own components, builders and signers.

No package registry, model hub, container registry, Git host, transparency log,
signing service, key server or vulnerability database is contacted; no signature
or attestation is issued; and no artifact, model, archive or code named in an
imported document is executed, loaded or extracted. A purl, download location or
repository inside a document is inert metadata — naming a location is not
authorization to fetch it. See
[Agentic Supply Chain and AI-BOM Validation](../concepts/supply-chain-security.md).

## `validate a2a`

Bounded local A2A and inter-agent communication validation (Cycle 020). Reads
local Agent Cards, captured exchanges, recorded verification results, delegation
records and local policy, and evaluates fourteen invariants over discovery
binding, peer identity, message authenticity, security requirements, skill
authorization, message authority, task and context binding, authority
propagation, tenant and data-scope boundaries, replay safety, protocol
negotiation, extension trust and push-notification scope.

```bash
dare-agent-security validate a2a   --scenario A2A-LAB-032   --mode simulated   --output-dir .dare-agent-security/a2a

dare-agent-security validate a2a   --scenario scenarios/production-peers.json   --mode static   --evidence-dir evidence/2026-q3   --output-dir .dare-agent-security/a2a
```

Modes are `static`, `replay`, `simulated` and `local-synthetic`; all four are
local and offline. `replay` analyses a capture that already exists — it never
re-sends traffic. There is no `--endpoint`, `--url`, `--token`, `--api-key`,
`--client-secret`, `--username`, `--password`, `--private-key`, `--certificate`,
`--login`, `--jwks-url`, `--webhook-test`, `--command`, `--shell`, `--download`
or `--fetch` flag, and no credential is read from the environment.

`--max-peers` and `--max-exchanges` only ever tighten: a value above the hard
maximum is clamped down to it, because a flag that could raise a hard bound is
not a limit.

Under `--mode replay`, `--policy` is required alongside `--capture`: a capture
may not supply the policy it is judged against, or a recorded run would declare
its own approvals.

No peer is contacted, no Agent Card is downloaded, no `.well-known` path or
registry is queried, no JWK, JWKS or `jku` is resolved, no OAuth, OIDC, bearer
or API-key credential is obtained or presented, no TLS handshake is performed,
no message is sent, no remote task is created or cancelled, and no callback is
invoked. An interface URL, issuer, token endpoint, key-set location or webhook
inside a document is inert metadata — naming a location is not permission to
connect to it. See
[A2A and Inter-Agent Communication Security](../concepts/a2a-security.md).

## Exit codes

Each subcommand has its own table — see [Exit Codes](../reference/exit-codes.md).
