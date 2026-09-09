# A2A and Inter-Agent Communication Security

DARE Agent Security can validate whether an agent-to-agent relationship stayed
inside the boundaries it was approved for: who the peer turned out to be, what
the message actually proved, what the peer was allowed to ask for, and how far
authority travelled. This page describes what that establishes and, just as
importantly, what it does not.

## The question it answers

The engine answers one question:

> Do the local Agent Cards, captured exchanges, recorded verification results,
> delegation records and local policy show that every applicable inter-agent
> invariant remained satisfied?

It is not an A2A client, a discovery crawler, an identity provider or a
penetration-testing tool. It contacts nothing. A peer that looks unfamiliar is
not a finding. A finding requires a deterministic fact that contradicts a stated
invariant.

## The relations everything rests on

```text
external agent listed        != trusted peer
discovered Agent Card        != authenticated identity
signed Agent Card            != authorized provider
TLS server identity          != agent-level authorization
declared security scheme     != successful authentication
successful authentication    != skill authorization
schema-valid message         != authentic message
authentic message            != authorized instruction
peer content                 != privileged instruction
taskId match                 != principal/context match
delegation                   != privilege amplification
message retry                != safe replay
protocol compatibility       != permission to downgrade
extension declaration        != extension authority
webhook URL                  != permission to connect
tenant routing value         != proof of tenant authorization
```

Each of these is a place where two things that look alike are not the same
thing, and each is why the corresponding invariant exists.

> **An Agent Card is a claim by the agent it describes.** It can say a peer is
> operated by Acme and supports OAuth; it cannot say Acme was approved or that
> OAuth succeeded. Approval comes from a local policy the deployment controls,
> and a card that sets `"trusted": true` about itself is refused rather than
> believed.
>
> **Discovery is not identity.** Finding a card at a location says something was
> published there. It says nothing about who answered when a message was sent.
>
> **A signature on a card is not authorization.** A correctly signed card proves
> the card was not altered. Whether its provider is one this deployment accepts
> is a separate question, answered by policy.
>
> **Transport identity is not agent identity.** A valid TLS certificate
> identifies a server. An A2A skill is invoked by a *subject*, and the two are
> not the same layer.
>
> **Authentication is not authorization.** A peer that authenticated perfectly
> has established who it is. What it may do, and on whose behalf, has not yet
> been asked.
>
> **A signature over a message is not a signature over *this* message.** The
> substitution that matters most is a genuine, valid signature lifted from
> another exchange. Only comparing the covered envelope digest tells the two
> apart.
>
> **Peer content is data.** Whether it became an instruction is a fact about the
> local consumer, not about the text — and it is the only thing the authority
> boundary asks.
>
> **A matching `taskId` is a matching correlation identifier.** Two messages can
> correlate perfectly and carry different initiating principals, which is the
> failure mode that most resembles a working system.
>
> **A repeat is not a replay finding.** A repeated read is fine, and a repeat
> with an idempotency key or on a skill policy declares idempotent is proven
> safe. What is not proven safe is a repeated non-idempotent state change with
> neither.
>
> **A tenant claim is a routing value the sender chose.** Where policy records
> nothing about the subject, the claim can be neither confirmed nor
> contradicted, and the answer is *undecidable* rather than either verdict.

## The fourteen invariants

| | Invariant | Asks |
|---|---|---|
| I01 | discovery binding preserved | is the card in hand the card policy approved? |
| I02 | peer identity bound | is the authenticated party the intended agent, audience and tenant? |
| I03 | message authenticity established | does the authentication evidence bind *this* message? |
| I04 | security requirement satisfied | does the mechanism used satisfy an approved requirement? |
| I05 | skill authorized | may the effective subject invoke the skill that was invoked? |
| I06 | message authority boundary preserved | did peer-controlled content stay data? |
| I07 | task/context binding preserved | did task, context and initiating principal stay the same? |
| I08 | authority propagation bounded | did authority hold or narrow across every hop? |
| I09 | tenant boundary preserved | did the exchange stay inside the approved tenant? |
| I10 | data scope boundary preserved | did disclosure stay inside what policy allowed? |
| I11 | replay boundary preserved | was a repeated action proven safe to repeat? |
| I12 | protocol negotiation integrity | were the version and interface used ones policy permits? |
| I13 | extension trust boundary preserved | were extensions declared, approved and non-authoritative? |
| I14 | push notification boundary preserved | does a callback disclose no further than approved? |

## Three answers, not two

Every invariant can report that it **held**, that it was **violated**, or that
the evidence did not allow it to be decided. The third is not a weaker version
of the first.

Verification evidence carries one of four statuses, and only two of them decide
anything:

| Status | Meaning | Can satisfy a PASS | Is a concrete failure |
|---|---|---|---|
| `VALID` | a verifier checked it and it held | yes | no |
| `INVALID` | a verifier checked it and it failed | no | **yes** |
| `INDETERMINATE` | a verifier could not decide | no | no |
| `UNRECORDED` | nobody checked | no | no |

Missing evidence is never read as success. An operator who sees PASS believes a
question was asked and answered; if the question was never asked, that belief is
the whole harm.

Separately, an invariant with no subject in the evidence at all is *inapplicable*
rather than undecided. An exchange that registers no callback has not failed to
prove anything about callbacks — the question does not arise, and reporting it
as INCONCLUSIVE would make every clean run unreadable.

## What the engine never does

It contacts no agent. It downloads no Agent Card, queries no `.well-known` path
and no registry, resolves no JWK, JWKS or `jku`, obtains and presents no OAuth,
OIDC, bearer, API-key or client-credential secret, performs no TLS handshake,
sends no message, creates or cancels no remote task, and invokes no callback. It
executes nothing that appears in the evidence it reads.

An interface URL, issuer, token endpoint, key-set location, Agent Card URL or
webhook read out of a local document is **inert metadata**. It is retained so a
report can name where a peer said it lives, and resolved by nothing.

This is structural rather than promised: the engine declares no HTTP client, no
TLS stack, no JWT library, no JWKS resolver, no OAuth client and no async
runtime, and a test fails if one appears.

## What a PASS means

> A PASS means the applicable invariants remained satisfied under the local
> evidence analysed.

It is not a statement that a remote agent is secure, that a peer is trustworthy,
or that an exchange nobody captured was safe. The artifact and the summary both
say so in their own text, because a reader may only ever see one of them.

## What this composes with

This engine carries only the A2A *projection* of relations other cycles own, and
takes verdict authority over none of them:

- generic prompt injection belongs to the prompt-injection engine;
- tool-invocation authorization belongs to the tool-security engine;
- identity, principal, delegation, privilege and tenant semantics belong to the
  identity-security engine;
- concrete-failure aggregation belongs to the MCP auth engine;
- supply-chain and external-agent inventory belong to the supply-chain engine.

See [Extending A2A Security Validation](../reference/extending-a2a-security.md)
for the evidence formats, the corpus and the flag surface.
