# Memory and Context Poisoning Validation

DARE Agent Security can validate the provenance, trust, isolation, lifecycle and
decision influence of persisted agent memory against explicit security
invariants. This page describes what that establishes and, just as importantly,
what it does not.

## The question it answers

The engine answers one question:

> Did a controlled memory store, recall or decision trace prove that persisted
> memory crossed a boundary it was never authorized to cross?

It is not a memory-store audit, a database security review, or a penetration
test against a real cache. A memory item that reads alarmingly is not a finding.
A finding requires a deterministic fact that contradicts a stated invariant.

## The relation everything rests on

```text
stored_data != trusted_instruction
```

Persisting data records it and confers nothing. Trust is assigned by policy and
is never acquired by the act of being written, stored or recalled.

Three corollaries the corpus exists to state:

> **Availability is not authorization.** Memory being reachable by a recall does
> not authorize it to influence a protected decision.
>
> **Recall is not permission to influence.** Reading something back is a
> different event from letting it change what the agent does.
>
> **Storage is not promotion.** Untrusted content that has been persisted is
> still untrusted content that happens to be persisted.

Untrusted memory is allowed to exist. Existing is not the violation. A `FAIL`
requires deterministic evidence that it went beyond its authorized boundary.

## Nothing is ever persisted

This is the boundary that matters most, so it is worth stating plainly.

A scenario may describe an agent writing poisoned memory, recalling another
tenant's notes, or letting an expired item change a payment argument. All of it
is **described from local synthetic fixtures and never persisted**. No Redis,
PostgreSQL, Pinecone, Weaviate, Qdrant, SaaS memory service, remote MCP server,
HTTP provider, production agent or customer memory is involved. No state
changes, nothing is written to any store, and nothing leaves the process.

That is not a policy the code follows; it is a shape the code has. The engine
declares no database driver, HTTP client or vector-store SDK among its
dependencies; the mode enum has no variant that could name a remote target; the
CLI has no `--url`, `--redis`, `--postgres`, `--vector-db`, `--pinecone`,
`--qdrant`, `--provider`, `--token`, `--api-key`, `--remote` or `--command`
flag, and it reads no connection string from the environment.

Boundary crossings are proven from **declared, typed, synthetic facts** — memory
ids, owners, tenants, namespaces, provenance, trust classes and content digests
— never by performing the crossing.

## Five surfaces, reported separately

They are validated, counted and reported as five dimensions, and none ever
inherits another's result.

| Surface | What it is about |
|---|---|
| `PROVENANCE` | Whether memory carries machine-readable provenance before it influences anything |
| `TRUST_BOUNDARY` | Whether stored trust stayed within what the source allows, and whether content was substituted |
| `TENANT_PRINCIPAL` | Whether recall stayed inside the owning principal, tenant and namespace |
| `LIFECYCLE` | Whether expired or revoked memory reached a decision |
| `DECISION_INFLUENCE` | Whether recalled memory changed an objective, tool, argument or protected field |

A run exercises one surface. The other four are reported as **not tested**,
never as passing.

## Three isolation axes, kept distinct

Memory isolation is not one boundary but three, and collapsing any two of them
is how a crossing becomes invisible:

- the **owner principal** — whose memory this is;
- the **tenant** — which customer boundary it sits inside;
- the **namespace** — which partition of that tenant it belongs to.

Two items can share an owner and a tenant and still belong to namespaces that
must not see each other. Each axis is checked on its own, and a violation on one
is reported as a violation on that one.

Principal kinds are reused verbatim from Cycle 015 — `HUMAN`, `AGENT`,
`WORKLOAD`, `SERVICE` — rather than redefined. A `HUMAN` here means what it
means there, and memory security cannot silently reinterpret an identity or
reassign a tenant: where the two models describe the same principal, a
disagreement stops the run rather than being resolved in either direction.

## Trust is ordered, so promotion is arithmetic

```text
UNTRUSTED < CONSTRAINED < TRUSTED_POLICY
```

Because the classes are ordered, "promotion" is an integer comparison rather
than a judgement call. Lowering trust is always allowed. Raising it requires an
explicit, machine-readable policy grant that names the specific origin being
elevated.

Only `SYSTEM_AUTHORED` content can be policy-authoritative by default.
Everything else — user input, tool output, external content, agent-generated
text, imported context — caps at `CONSTRAINED` however trustworthy it looks.

## Twelve invariants

Each is a deterministic comparison of typed fields. There is no model in the
verdict path, no embedding, no cosine similarity, no fuzzy matching and no prose
heuristic.

| Invariant | Surface |
|---|---|
| `MEMORY_PROVENANCE_PRESENT` | Provenance |
| `MEMORY_SOURCE_TRUST_PRESERVED` | Trust boundary |
| `UNTRUSTED_MEMORY_NOT_PROMOTED_TO_AUTHORITY` | Trust boundary |
| `MEMORY_INTEGRITY_DIGEST_PRESERVED` | Trust boundary |
| `MEMORY_WRITE_WITHIN_POLICY` | Trust boundary |
| `MEMORY_PRINCIPAL_BOUNDARY_PRESERVED` | Tenant/principal |
| `MEMORY_TENANT_BOUNDARY_PRESERVED` | Tenant/principal |
| `MEMORY_NAMESPACE_BOUNDARY_PRESERVED` | Tenant/principal |
| `RECALLED_MEMORY_MATCHES_REQUESTED_CONTEXT` | Tenant/principal |
| `EXPIRED_OR_REVOKED_MEMORY_NOT_USED` | Lifecycle |
| `MEMORY_INFLUENCE_WITHIN_AUTHORIZED_OBJECTIVE` | Decision influence |
| `PROTECTED_FIELD_NOT_DERIVED_FROM_POISONED_MEMORY` | Decision influence |

## An authorized update is not a substitution

Both change stored content, so distinguishing them is the whole of the integrity
surface. The difference is recorded structurally rather than inferred: an
authorized update moves the item's version alongside its content digest; a
substitution moves the content while the item keeps its identity and version.

Legitimate memory updates are ordinary and must not read as poisoning. An engine
that flagged them would be switched off.

## Lifecycle uses logical time

Every scenario declares the logical instant it is evaluated at, and validity
windows are half-open: an item valid `[100, 500)` is usable at 499 and not at
500. Revocation dominates expiry, because an item withdrawn before its expiry is
withdrawn.

No verdict depends on the machine's clock. A run in January and the same run in
June produce the same result, which is what makes a recorded digest worth
anything.

## Absence of evidence is not evidence of absence

Every invariant declares the observation channels it needs. If a run never
observed a store snapshot, a write, an update, a recall or an influence —
whichever that invariant requires — the verdict is `INCONCLUSIVE`.

Four invariants additionally require an *exercise* channel: seeing a memory
store proves nothing about whether the agent reached into it. Recalling is not
the same as influencing, so influence invariants require an influence
observation rather than merely a recall.

A no-influence `PASS` therefore rests on a **recorded non-influence
observation** — the decision field was compared and did not change — not on the
absence of a finding. An inconclusive result is not a pass and is never reported
as one.

## One violation never masks another

A single trial can promote untrusted memory to policy authority, return another
tenant's item and substitute stored content, all at once. All three are true,
and all three are reported. Violations are collected as a list, both within one
invariant and across invariants; there is no first-match short circuit anywhere
in the evaluator.

Stopping at the first finding would report a smaller problem than the one
observed, and send an operator through three rounds that each looked like
progress.

## Refusals are not verdicts

A refused scenario — an unknown memory reference, an over-bound store, a
smuggled executable field, a credential-shaped value, a namespace that is really
a path — exits as a refusal and writes no artifact. Refusing to run is not
evidence that a boundary was crossed, and no refusal message reads as `PASS`,
`FAIL` or `INCONCLUSIVE`, echoes credential material, or repeats a remote target
back to the reader.

## Bounds are security boundaries

| Bound | Value |
|---|---|
| Default trials | 3 |
| Hard maximum trials | 10 |
| Memory items per store | 32 |
| Namespaces | 8 |
| Events per trial | 32 |
| Events per run | 96 |
| Recalled items per request | 8 |
| Content bytes per item | 8192 |
| Retained bytes per trial | 16384 |
| Retained bytes per run | 65536 |
| Seconds per trial | 30 |
| State changes | 0 |
| External egress bytes | 0 |

A scenario or flag may request less. None can request more: an over-limit input
is **refused**, never clamped upward, and run totals never reset between trials.

## How it composes with earlier cycles

Cycle 016 borders on two engines that already exist, and it composes with them
rather than answering their questions a second time.

**Cycle 013** owns whether untrusted content acted as an instruction. Cycle 016
does not re-derive "untrusted": a memory source maps onto the Cycle 013 content
channel it arrived through, and the composed view of a persisted item names
*both* the injection boundary it crossed on the way in and the memory write
boundary it crosses on the way into storage. Persistence adds a boundary and
discharges none.

**Cycle 015** owns whose identity an operation runs under. Cycle 016 re-exports
its principal kinds instead of defining parallel ones, and refuses to proceed
where the two models describe the same principal differently.

## What this is not

Cycle 016 does not implement, and this capability cannot be made to perform:

- retrieval-augmented generation, embedding retrieval or similarity search;
- vector-store authorization, document-level isolation or cross-document
  retrieval testing;
- any connection to Redis, PostgreSQL, a vector database, a SaaS memory service,
  a remote MCP server or an HTTP provider;
- reading or writing customer memory, or testing a production agent;
- OAuth, OIDC, JWT verification, JWKS retrieval or live identity binding.

Retrieval security belongs to Cycle 017. The distinction is not a formality: a
report covering persisted memory says nothing about what a retriever will hand
an agent tomorrow, and every artifact this cycle produces states that boundary
so a reader holding one file cannot mistake the two.

## Standards

ASI06 (Memory and Context Poisoning) is used as risk taxonomy and context.

Using a similar vocabulary is not conformance. DARE is not "ASI06 compliant" and
is not certified against any specification, and no artifact will say so.

## Reading a result

A `PASS` means exactly this:

> No memory-security invariant violation was observed for the tested vectors
> under the recorded conditions.

It does not mean memory is secure, that poisoning is impossible, or that the
system is fully protected. The wording in every artifact is chosen to say what
was tested rather than what is safe.
