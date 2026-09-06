# Identity, Privilege and Delegation Validation

DARE Agent Security can validate identity binding, delegation, privilege,
tenant/resource boundaries and authorization-to-execution binding against
explicit security invariants. This page describes what that establishes and,
just as importantly, what it does not.

## The question it answers

The engine answers one question:

> Did a controlled principal, delegation, privilege or authorization trace prove
> that effective authority exceeded, changed, crossed a boundary, or detached
> from the authority originally granted?

It is not an identity provider audit, an OAuth conformance suite, or a
penetration test against a real tenant. An identity model that reads alarmingly
is not a finding. A finding requires a deterministic fact that contradicts a
stated invariant.

## The relation everything rests on

```text
effective_authority <= delegated_or_source_authority_ceiling
```

Authority may remain equal or narrow as it passes through a delegation. It may
never silently expand.

The corollary that motivates most of the corpus:

> **Credential availability is not delegated authority.**

A more privileged service, workload or technical credential existing in the
runtime does not authorize the agent to exercise those privileges on the user's
behalf. That a powerful credential is *reachable* says nothing about whether the
human ever delegated anything through it.

## Nothing is ever performed

This is the boundary that matters most, so it is worth stating plainly.

A scenario may describe an agent reading another tenant's document, deleting a
record, or acting under a service identity it was never given. That request is
**observed as structured data and never dispatched**. No identity provider is
contacted, no authorization server or PDP is called, no token is parsed or
validated, no resource is read, no process is spawned, and no network I/O
happens. A cross-tenant intent produces a deterministic `FAIL` without any
tenant's data being touched.

That is not a policy the code follows; it is a shape the code has. The engine
declares no HTTP client, no OAuth library and no token parser among its
dependencies; the mode enum has no variant that could name a remote target; and
normalized operations carry `dispatched: false` structurally, with no code path
that could set it otherwise.

Boundary crossings are proven from **declared, typed, synthetic facts** —
principals, authority ceilings, tenant labels, resource owners — never by
performing the crossing.

## Five surfaces, reported separately

They are validated, counted and reported as five dimensions, and none ever
inherits another's result.

| Surface | What it is about |
|---|---|
| `PRINCIPAL_BINDING` | Who started the request, and whose authority it runs under |
| `DELEGATION` | Whether a delegation carried its subject, scope and validity forward intact |
| `PRIVILEGE` | Whether exercised authority stayed inside its source ceiling |
| `TENANT_RESOURCE` | Whether the operation stayed inside the tenant and owner boundary |
| `AUTHORIZATION_BINDING` | Whether the decision still covers the operation that ran |

A run exercises one surface. The other four are reported as **not tested**,
never as passing.

## Five principals, kept distinct

Collapsing these is the confusion the whole cycle is about, so the model keeps
them separate and so does every artifact:

- the **initiating principal** — who started the request;
- the **effective principal** — whose authority it actually runs under;
- the **agent principal** — the agent's own identity;
- the **delegated subject** — who the delegation is on behalf of;
- the **resource owner** — who owns the thing being touched.

Principal kinds are a closed set: `HUMAN`, `AGENT`, `WORKLOAD`, `SERVICE`. Only
a human originates authority; workloads and services are technical identities,
and being one is not by itself suspicious — exercising authority nobody
delegated is.

## Twelve invariants

Each is a deterministic comparison of typed fields. There is no model in the
verdict path, no similarity score, no classifier and no prose heuristic.

| Invariant | Surface |
|---|---|
| `INITIATING_PRINCIPAL_PRESERVED` | Principal binding |
| `AGENT_AUTHORITY_NOT_SUBSTITUTED_FOR_USER` | Principal binding |
| `DELEGATED_SUBJECT_PRESERVED` | Delegation |
| `DELEGATION_SCOPE_NOT_EXCEEDED` | Delegation |
| `DELEGATION_CHAIN_NO_PRIVILEGE_AMPLIFICATION` | Delegation |
| `DELEGATION_VALID_AT_USE` | Delegation |
| `EFFECTIVE_AUTHORITY_WITHIN_SOURCE_CEILING` | Privilege |
| `CREDENTIAL_CONTEXT_NOT_EXPAND_AUTHORITY` | Privilege |
| `TENANT_BOUNDARY_PRESERVED` | Tenant/resource |
| `RESOURCE_OWNER_BOUNDARY_PRESERVED` | Tenant/resource |
| `AUTHORIZATION_BOUND_TO_FINAL_OPERATION` | Authorization binding |
| `DENY_NOT_BYPASSED` | Authorization binding |

## Authorization binding is semantic, not byte equality

An operation's authorization-relevant fields — subject, action, resource, type,
tenant, objective, tool and the arguments that change what was authorized —
form a canonical projection, digested with the same Cycle 003 canonicalizer the
rest of DARE uses. Incidental arguments such as a trace id or a page size are
deliberately excluded.

So a permit for `subject=user-7 action=read resource=document-123 tenant=A`
still covers the same operation when a request id changes, and stops covering it
the moment the resource becomes `document-999`. The earlier decision does not
apply without re-evaluation.

Including everything would make every harmless difference invalidate a permit,
and a check that fires on everything gets switched off.

## Absence of evidence is not evidence of absence

Every invariant declares the observation channels it needs. If a run never
observed a principal context, an authority, a delegation edge, a resource, a
decision or an operation — whichever that invariant requires — the verdict is
`INCONCLUSIVE`.

Four invariants additionally require an *exercise* channel: naming an effective
principal proves nothing unless something was actually attempted under it.
Seeing is not doing.

An inconclusive result is not a pass and is never reported as one.

## One violation never masks another

A single trial can substitute the initiating principal, substitute the effective
principal, cross a tenant boundary and expand authority through an available
credential, all at once. All four are true, and all four are reported. Verdicts
are collected as a list, both within one invariant and across invariants; there
is no first-match short circuit anywhere in the evaluator.

## Refusals are not verdicts

A refused scenario — an unknown principal, a delegation loop, a chain deeper
than the bound, a smuggled executable field, a credential-shaped value — exits
as a refusal and writes no artifact. Refusing to run is not evidence that a
boundary was crossed, and no refusal message reads as `PASS`, `FAIL` or
`INCONCLUSIVE`.

## Bounds are security boundaries

| Bound | Value |
|---|---|
| Default trials | 3 |
| Hard maximum trials | 10 |
| Principals | 16 |
| Delegation edges | 12 |
| Delegation depth | 4 |
| Authorization decisions per trial | 8 |
| Operations per trial | 8 |
| Operations per run | 24 |
| Retained bytes per trial | 16384 |
| Retained bytes per run | 65536 |
| Seconds per trial | 30 |
| State changes | 0 |
| External egress bytes | 0 |

A scenario or flag may request less. None can request more: an over-limit input
is **refused**, never clamped upward, and run totals never reset between trials.

## What this is not

Cycle 015 does not implement, and this capability cannot be made to perform:

- OAuth or OIDC flows of any kind — authorization code, client credentials,
  device, token exchange, or on-behalf-of token issuance;
- JWT parsing, signature validation, JWKS retrieval, or issuer/audience
  cryptographic verification;
- live identity provider, PDP, AuthZEN endpoint or MCP authorization testing;
- credential harvesting or credential replay;
- SCIM or any provisioning protocol;
- any operation against a real tenant, resource or production identity.

Protocol and cryptographic identity belong to a later cycle. Cycle 015 models
authority declaratively.

## Standards

ASI03 (Identity and Privilege Abuse) is used as risk taxonomy and context. The
AuthZEN Authorization API informs how subject, action and resource are modelled.
COAZ and COAZ-MCP work is referenced at its own draft status, and the
authorization-to-execution binding is recorded as an open proposal.

Using similar concepts is not conformance. DARE is not "AuthZEN compliant" or
"COAZ compliant", and no artifact will say so.

## Reading a result

A `PASS` means exactly this:

> No identity-security invariant violation was observed for the tested vectors
> under the recorded conditions.

It does not mean identity handling is secure, that privilege escalation is
impossible, or that the system is protected. The wording in every artifact is
chosen to say what was tested rather than what is safe.
