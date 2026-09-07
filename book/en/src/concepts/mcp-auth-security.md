# MCP 2026 Authentication and Authorization Validation

DARE Agent Security can validate whether an MCP deployment's authentication and
authorization semantics stay bound across protocol revision, request routing,
Protected Resource Metadata, authorization-server and issuer selection, token
resource and audience, PKCE, redirect and state, scope step-up, client
registration, credential separation, self-reported identity metadata and the
operation finally performed. This page describes what that establishes and,
just as importantly, what it does not.

## The question it answers

The engine answers one question:

> Did a controlled, local authorization trace prove that an operation was
> executed under authority it was never granted?

It is not an OAuth deployment audit, an identity-provider review, or a
penetration test against a live MCP server. A configuration that reads
alarmingly is not a finding. A finding requires a deterministic fact that
contradicts a stated invariant.

## The relations everything rests on

```text
protocol_metadata != authenticated_identity
token_presence    != token_validity
valid_token       != correct_audience_or_resource
correct_token     != authorization_for_a_mutated_operation
inbound_credential != upstream_api_credential
same_scenario_id  != same_authorization_semantics
```

Each of these is a place where a deployment can be entirely well-formed and
still wrong, and each is why the corresponding invariant exists.

> **`clientInfo` is what a peer calls itself.** Anything can claim any name. An
> acting principal established from self-description is not authenticated, and
> the engine reports that on every run — not only when a scenario asks about it.
>
> **A token being present is not a token being valid.** An accepted credential
> with nothing recorded behind the acceptance is a gap, not a pass.
>
> **A validly issued token is not a token issued for *this* resource.** A token
> minted for another audience is genuine and still unauthorized here.
>
> **A permit does not survive the operation changing under it.** Authorization
> covered what was asked; if what was performed differs, the permit does not
> stretch to cover it.
>
> **The credential a caller presented to the MCP server is not the credential
> the server may present upstream.** Forwarding it makes the server a confused
> deputy, whatever the inbound token was worth.

## Nothing is ever fetched, exchanged or verified

This is the boundary that matters most, so it is worth stating plainly.

A scenario may describe an authorization response arriving from an issuer that
was never selected, a token minted for a different resource, a PKCE flow
downgraded to a method that binds nothing, or an inbound bearer credential
forwarded to an upstream API. All of it is **described from local synthetic
fixtures**.

No production MCP endpoint, live OAuth or OIDC flow, browser login,
authorization-code exchange, real bearer or refresh token, real cookie, client
secret, private key, live JWKS, token introspection, Protected Resource Metadata
retrieval, authorization-server metadata retrieval, CIMD or dynamic client
registration, external identity provider, remote protected resource or upstream
API is involved. No state changes and nothing leaves the process.

That is not a policy the code follows; it is a shape the code has:

- the engine declares no HTTP client, OAuth client, JWT library or TLS stack of
  its own;
- the mode enum has three variants — `REPLAY`, `SIMULATED`, `LOCAL_SYNTHETIC` —
  and no variant that could name a remote target;
- issuers, resources and endpoints are a `SyntheticUri` type that **cannot
  express a URL**, checked at construction and again on deserialization;
- the CLI has no `--url`, `--endpoint`, `--authorization-server`,
  `--token-endpoint`, `--jwks-url`, `--issuer-url`, `--client-secret`,
  `--access-token`, `--refresh-token`, `--authorization-code`, `--private-key`,
  `--cookie`, `--remote` or `--command` flag, and it reads no credential from
  the environment.

One thing that would be an overclaim, stated plainly rather than left out: a
transport stack *does* exist transitively. `dare-mcp-discovery` — the Cycle 002
crate this engine imports two protocol-revision constants from — carries `rmcp`
and through it `reqwest`, `hyper` and `rustls`. One `cargo tree` shows it.

The boundary is therefore not "no transport exists in the graph". It is that
**nothing here reaches it**: the engine's single reference to that crate is the
two-constant re-export, and a test fails if a second one appears. The constants
are imported rather than restated because two copies of "the current revision"
in different crates eventually disagree, and the disagreement would be silent.
An accurate boundary a test enforces is worth more than a stronger claim nobody
checks.

Boundary crossings are proven from **declared, typed, synthetic facts** — issuer
ids, resource indicators, audiences, scopes, code-challenge methods, redirect
identifiers, trust classes and digests — never by performing the crossing.

Token claims are structures with a recorded validity *state*: a description of
what a verifier reported, not a verification performed here. Nothing in the
engine signs, verifies, introspects or exchanges a credential, and no fixture
contains a usable one.

## Nothing self-reported is ever the judge

There is no model, no heuristic and no prose inference anywhere in the verdict
path. A fixture cannot declare its own verdict: the expected outcome for every
lab lives in the test register, never in the scenario file, so the fixtures
describe a situation and the register says what the engine ought to conclude.

The same rule applies to the target. A server's own claim about its trust class
is not accepted — `SelfReportedMetadata::trust()` is a method with no field
behind it, so there is nothing for a document to set.

## A trace is evidence, never authority

Replay accepts a sanitized local trace of what a run observed. A trace records
what happened; it is **not** the authority that says what was approved.

Matching on `scenario_id` alone is identity, not authority — and a trace that
kept the approved id while restating a request with wider operation semantics
would have that widened version judged as though it had been approved. So a
trace's observed requests are checked against the approved scenario before any
evaluator sees them, and `run_scenario` re-checks the binding itself, so a
caller who forgets cannot get a verdict out of an unbound trace.

Routing metadata is deliberately left free to disagree. That disagreement is
exactly what the binding invariants judge.

## Three verdicts, and silence is not one of them

| Verdict | Meaning |
| --- | --- |
| `PASS` | No invariant violation was observed for the tested vectors, under the recorded conditions. |
| `FAIL` | A deterministic violation was observed. Every independent violation is reported, not just the first. |
| `INCONCLUSIVE` | The run did not observe what the invariant needs. **This is not a pass.** |
| `ERROR` | The harness could not observe at all; no security conclusion is available in either direction. |

`INCONCLUSIVE` is the verdict that matters most in practice. A coverage-blind
engine reports silence as success, and a target that supplies no evidence would
score better than one that supplies some. Two labs exist purely to hold that
line: one strips every token observation, one strips the PKCE channels, and both
must report `INCONCLUSIVE` rather than either of the other two answers.

## A missing control is a gap, not an exemption

Coverage distinguishes two reasons a property might not be assessed, and the
difference is the whole point:

- **`NOT_APPLICABLE`** — the target does not have the shape. A deployment on a
  legacy protocol revision, on stdio, or with no authorization flow at all has
  no modern authorization surface to answer for. The property leaves the
  denominator entirely.
- **`NOT_TESTED`** — the target has the shape and the control's evidence is
  absent. That is a gap. It stays in the denominator and lowers the required
  coverage ratio.

Protected Resource Metadata, authorization-server metadata, token claims, PKCE
context, a scope challenge, client registration and credential forwarding are
all *control/evidence* predicates, so their absence is always the second case.
This is also why every property in the `mcp-auth-hardening-2026` profile is
`REQUIRED` and none is `CONDITIONAL`: only `REQUIRED` properties feed the
required-coverage ratio, so a `CONDITIONAL` property whose evidence is missing
would print a gap that counted toward nothing.

## Standards status, stated plainly

MCP `2026-07-28` is the current baseline and is treated as normative. Beyond
that, the honest statuses are:

| Source | Status |
| --- | --- |
| MCP 2026-07-28 authorization | NORMATIVE |
| OpenID AuthZEN Authorization API 1.0 | NORMATIVE where applicable |
| COAZ, COAZ-MCP | DRAFT |
| `openid/authzen#603` | OPEN_PROPOSAL |
| DPoP, workload identity federation, ID-JAG, standardized token exchange, Enterprise-Managed Authorization | FUTURE |

Two consequences follow, and the engine enforces both.

**An open proposal is not a requirement.** Nothing here converts a draft or a
proposal into a mandatory PASS condition, and the property mappings in the
provenance record carry a status of `INFORMATIVE`, `DRAFT` or `OPEN_PROPOSAL` —
never `NORMATIVE`.

**Forward-looking work is not assessed.** DPoP, workload identity federation,
ID-JAG, standardized token exchange and Enterprise-Managed Authorization are
outside what this cycle examines. A deployment using none of them is not
reported as deficient, and a deployment using all of them is not reported as
better.

The provenance record also states, without hedging, that no upstream
re-verification of these statuses was performed. They are pinned as of the cycle
and should be re-checked before being relied on.

## What a PASS does not mean

A `PASS` is the bounded claim and nothing more:

> No MCP 2026 authentication/authorization hardening invariant violation was
> observed for the tested vectors under the recorded conditions.

It does **not** mean MCP authentication is secure, that authorization is
correct, that tokens cannot be misused, that a client cannot be impersonated, or
that the deployment is spec-compliant. The CLI refuses to write a summary
containing any of those phrasings, including the conformance claims — a bounded
run is not a standards assertion.

It also says nothing about surfaces this cycle does not own. Whether retrieved
content acted as an instruction remains prompt-injection's question; persisted
memory remains memory-security's; retrieval authorization remains RAG-security's;
and authorization-to-execution integrity is Cycle 003's engine, composed with
rather than reimplemented here.

## Related

- [Extending MCP Auth Security Validation](../reference/extending-mcp-auth-security.md)
- [Identity Security Validation](identity-security.md)
- [Assessment Coverage](assessment-coverage.md)
- [Evidence](evidence.md)
