# RAG and Retrieval Security Validation

DARE Agent Security can validate the authorization, isolation, provenance,
result-set integrity, content trust and protected nondisclosure of a
retrieval-augmented generation flow against explicit security invariants. This
page describes what that establishes and, just as importantly, what it does not.

## The question it answers

The engine answers one question:

> Did a controlled retrieval, filtering or ranking trace prove that returned
> context crossed a boundary it was never authorized to cross?

It is not a vector-database audit, an index security review, or a penetration
test against a live retriever. A document that reads alarmingly is not a
finding. A finding requires a deterministic fact that contradicts a stated
invariant.

## The relation everything rests on

```text
similarity_match  != permission
retrieved_content != trusted_instruction
high_score        != safe_source
```

**Retrieval relevance is not authorization.** A retriever can return exactly the
most relevant document in the index and still have violated a boundary.
Relevance is a property of the query; authorization is a property of the policy.
A document can be highly relevant and still lie outside the acting principal's
authority.

Three corollaries the corpus exists to state:

> **Ranking is not a grant.** Score, embedding, similarity and reranking are
> evidence about ordering. None of them may override policy.
>
> **Being in the candidate set is not being allowed.** A retriever considering a
> document says nothing about whether it may return it.
>
> **Returning is not authorizing.** Content that reached the context window is
> still untrusted content that happens to have reached the context window.

Untrusted documents are allowed to exist in a corpus, and are allowed to be
retrieved. Existing and being retrieved are not the violation. A `FAIL` requires
deterministic evidence that a boundary was crossed.

## Nothing is ever indexed, embedded or fetched

This is the boundary that matters most, so it is worth stating plainly.

A scenario may describe a retriever returning another tenant's document,
disclosing a restricted salary record, or broadening a failed search until it
reaches an unauthorized collection. All of it is **described from local
synthetic fixtures**. No Pinecone, Weaviate, Qdrant, Redis, PostgreSQL,
OpenSearch, Elasticsearch, Chroma, Milvus, SaaS retrieval API, remote MCP
server, HTTP provider, production retriever or customer corpus is involved. No
document is indexed, no embedding is computed or compared, no state changes, and
nothing leaves the process.

That is not a policy the code follows; it is a shape the code has. The engine
declares no database driver, HTTP client, vector-store SDK or embedding runtime
among its dependencies; the mode enum has no variant that could name a remote
target; the CLI has no `--url`, `--endpoint`, `--pinecone`, `--weaviate`,
`--qdrant`, `--redis`, `--postgres`, `--opensearch`, `--elasticsearch`,
`--api-key`, `--token`, `--connection-string`, `--remote` or `--command` flag,
and it reads no connection string from the environment.

Boundary crossings are proven from **declared, typed, synthetic facts** —
document ids, chunk ids, collections, tenants, owners, provenance, classification
levels, trust classes and content digests — never by performing the crossing.

## Nothing semantic is ever the judge

There is no model, no embedding, no cosine similarity, no reranker, no fuzzy
match and no prose heuristic anywhere in the verdict path, and no score
threshold that policy did not authorize.

Scores and orderings *are* accepted — as evidence about ordering, supplied by a
fixture or a trace. The engine reasons about the policy and the integrity around
those numbers. It never asks whether an embedding is semantically sensible,
because that question has no deterministic answer and a security verdict must
have one.

The protected-document fixture is staged at the top of the ranking on purpose.
It still fails, and the reported reason names the boundary and never the score.

## Six surfaces, reported separately

They are validated, counted and reported as six dimensions, and none ever
inherits another's result.

| Surface | What it is about |
|---|---|
| `RETRIEVAL_AUTHORIZATION` | Whether the search stayed inside the principal, collection and authority it was granted |
| `DOCUMENT_ISOLATION` | Whether returned documents respected the tenant boundary, the document ACL and mandatory metadata filters |
| `PROVENANCE` | Whether returned content kept machine-readable provenance and stayed bound to its own document |
| `RESULT_INTEGRITY` | Whether the result set came from approved candidates and respected the top-k ceiling |
| `CONTENT_TRUST` | Whether untrusted retrieved content was promoted into authority |
| `PROTECTED_NONDISCLOSURE` | Whether a protected document or class appeared in a result at all |

A run exercises one surface. The other five are reported as **not tested**,
never as passing.

## Isolation is several axes, kept distinct

Retrieval isolation is not one boundary, and collapsing any two of them is how a
crossing becomes invisible:

- the **acting principal** — who is searching, and who owns each document;
- the **tenant** — which customer boundary the corpus sits inside;
- the **collection** — which addressed partition the query was allowed to reach;
- the **document ACL** — which specific documents this principal may see;
- the **metadata filter** — which mandatory attributes a result must satisfy.

A document can be inside the acting tenant, inside an allowed collection, and
still be outside the allowed document set. Each axis is checked on its own, and
a violation on one is reported as a violation on that one.

Principal kinds are reused verbatim from Cycle 015 — `HUMAN`, `AGENT`,
`WORKLOAD`, `SERVICE` — rather than redefined.

## A relevant document that is not authorized still fails

The ACL check reads the corpus declaration. It does not depend on a document's
title, its description, how it reads, or where it ranked. A document that is the
best possible answer to the query and is not in the allowed set is a finding.

## A missing metadata field never satisfies a filter

If a mandatory filter constrains `department` and a document simply does not
carry `department`, it has not shown that it satisfies the clause — it has shown
nothing. Absence of metadata is never turned into a pass, including for negative
operators, because bypass-by-omission is the easiest filter bypass there is.

The filter invariant is checked on **two independent channels**: the retriever's
own admission decisions, and the corpus itself. The second exists because the
first is a self-report. A retriever that recorded honest decisions for the
documents it really filtered, and none at all for the one it smuggled in, would
satisfy the coverage contract and leave the smuggled document unchecked.

## Protected nondisclosure is independent of everything else

A protected document must not be returned even if it scored highest, was in the
candidate set, passed every metadata filter, and belongs to the acting tenant.
None of those discharge the protection. It is checked against the corpus
declaration rather than the observation, so a retriever cannot avoid the check
by describing the document differently.

## Fallback may never widen authority

"I found nothing, so I searched everything" is the failure this surface exists
to catch. A broadened retrieval may relax recall — more candidates, a lower
threshold, a larger k — and may never relax **authority**: not the tenant, not
the principal, not the collection set, not the ACL, not the classification
ceiling.

## Trust is ordered, so promotion is arithmetic

```text
UNTRUSTED < REFERENCE < TRUSTED_POLICY
```

Because the classes are ordered, "promotion" is an integer comparison rather
than a judgement call. Lowering trust is always allowed. Raising it above what
both the source kind and the policy ceiling permit is a violation, and the
effective ceiling is the lower of the two.

External and ingested content caps below policy authority however authoritative
it reads.

## Twelve invariants

Each is a deterministic comparison of typed fields.

| Invariant | Surface |
|---|---|
| `RETRIEVAL_PRINCIPAL_BOUNDARY_PRESERVED` | Retrieval authorization |
| `RETRIEVAL_COLLECTION_BOUNDARY_PRESERVED` | Retrieval authorization |
| `RETRIEVAL_FALLBACK_DOES_NOT_WIDEN_AUTHORITY` | Retrieval authorization |
| `RETRIEVAL_TENANT_BOUNDARY_PRESERVED` | Document isolation |
| `DOCUMENT_ACL_ENFORCED` | Document isolation |
| `METADATA_FILTER_ENFORCED` | Document isolation |
| `RETRIEVAL_PROVENANCE_PRESERVED` | Provenance |
| `CHUNK_DOCUMENT_BINDING_PRESERVED` | Provenance |
| `RESULT_SET_WITHIN_APPROVED_CANDIDATES` | Result integrity |
| `TOP_K_BOUND_PRESERVED` | Result integrity |
| `UNTRUSTED_RETRIEVED_CONTENT_NOT_PROMOTED_TO_AUTHORITY` | Content trust |
| `PROTECTED_DOCUMENT_NOT_RETRIEVED` | Protected nondisclosure |

## A chunk cannot claim a document it does not belong to

Normalization records both what the retriever *claimed* about a returned chunk
and what the declared corpus *binds* it to. A trace therefore cannot assert that
a chunk belonged to a trusted document; the corpus decides what a returned chunk
means, and a disagreement is the finding.

## Absence of evidence is not evidence of absence

Every invariant declares the observation channels it needs. If a run never
observed a policy, a query, a candidate set, a result set, a document context or
an influence — whichever that invariant requires — the verdict is
`INCONCLUSIVE`.

Six invariants additionally require an *exercise* channel: seeing a corpus
proves nothing about whether the retriever reached into it. A no-promotion
`PASS` therefore rests on a **recorded non-promotion observation** — the trust
class the content was treated as was compared and stayed within its ceiling —
not on the absence of a finding.

A `PASS` can never arise from a missing observation. An inconclusive result is
not a pass and is never reported as one.

## One violation never masks another

A single trial can return another tenant's document, rebind a chunk to a more
trusted one, and disclose a protected record, all at once. All of them are true,
and all of them are reported. Violations are collected as a list, both within one
invariant and across invariants; there is no first-match short circuit anywhere
in the evaluator, and `stop_on_first_fail` stops later *trials* only after the
current trial's evidence has been collected in full.

## Refusals are not verdicts

A refused scenario — an unknown document reference, an over-bound corpus, a
smuggled callback field, a credential-shaped value, a collection id that is
really a path, a trace naming a remote index — exits as a refusal and writes no
artifact. Refusing to run is not evidence that a boundary was crossed, and no
refusal message reads as `PASS`, `FAIL` or `INCONCLUSIVE`, echoes credential
material, or repeats a remote target back to the reader.

## Bounds are security boundaries

| Bound | Value |
|---|---|
| Default trials | 3 |
| Hard maximum trials | 10 |
| Documents per corpus | 64 |
| Chunks per corpus | 256 |
| Candidates per query | 64 |
| Results per query | 16 |
| Queries per trial | 8 |
| Queries per run | 24 |
| Metadata fields per document | 32 |
| Filter clauses | 16 |
| Retained bytes per trial | 16384 |
| Retained bytes per run | 65536 |
| Seconds per trial | 30 |
| State changes | 0 |
| External egress bytes | 0 |

A scenario or flag may request less. None can request more: an over-limit input
is **refused**, never clamped upward, and run totals never reset between trials.

## How it composes with earlier cycles

Cycle 017 borders on three engines that already exist, and it composes with them
rather than answering their questions a second time.

**Cycle 013** owns whether untrusted content acted as an instruction and remains
the final judge of it. Cycle 017 observes authority promotion structurally and
projects a retrieved document onto the Cycle 013 content channel it arrived
through; it does not re-derive "untrusted" and runs no second prompt-injection
evaluator.

**Cycle 015** owns whose identity an operation runs under. Cycle 017 re-exports
its principal kinds instead of defining parallel ones, and refuses to proceed
where the two models describe the same principal differently.

**Cycle 016** owns persisted memory. Retrieved content is **not** memory. It
becomes memory only through a separate, explicit memory event, which this cycle
neither produces nor records. A document appearing in a context window has been
retrieved; it has not been remembered.

## What this is not

Cycle 017 does not implement, and this capability cannot be made to perform:

- any connection to Pinecone, Weaviate, Qdrant, Redis, PostgreSQL, OpenSearch,
  Elasticsearch, a vector database, a search provider, a production retriever or
  a remote MCP server;
- embedding inference, similarity computation, reranking or any model call;
- reading a customer corpus or testing a production RAG system;
- judging whether retrieved content was *followed* as an instruction — that
  stays with Cycle 013;
- anything about persisted memory — that stays with Cycle 016;
- OAuth, OIDC, JWT verification, JWKS retrieval, token exchange, IdP or PDP
  integration, AuthZEN or MCP auth hardening.

The last of those belongs to Cycle 018. The distinction is not a formality: a
report covering retrieval boundaries says nothing about how a token was verified
before the search began, and every artifact this cycle produces states that
boundary so a reader holding one file cannot mistake the two.

## Standards

OWASP LLM Top 10 2026, and `LLM09:2026 Vector and Embedding Weaknesses` in
particular, are used as risk taxonomy and context.

LLM09 is an LLM Top 10 entry. It is **not** an Agentic risk family, and no
equivalence with ASI04, ASI06 or any other ASI category is claimed. The ten
Agentic risk families are unchanged by this cycle; the six `AGENT.RAG.*`
properties report under a `RETRIEVAL` category and carry no risk family.

Using a similar vocabulary is not conformance. DARE is not "LLM09 compliant" and
is not certified against any specification, and no artifact will say so.

## Reading a result

A `PASS` means exactly this:

> No RAG/retrieval-security invariant violation was observed for the tested
> vectors under the recorded conditions.

It does not mean RAG is secure, that leakage is impossible, that a vector
database is safe, or that no retrieval attack is possible. The wording in every
artifact is chosen to say what was tested rather than what is safe.
