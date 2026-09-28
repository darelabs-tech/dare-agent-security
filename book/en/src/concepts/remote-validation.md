# Authorized Remote Validation

`dare-agent-security validate remote` runs the existing validation engines
against **one real target the target's owner has authorized**, over the
network, and decides every verdict **offline from the recorded capture**. This
page explains what that establishes, what keeps it bounded, and what a result
does **not** claim.

Every other command in this tool is local. This is the only one that opens a
socket.

## The question it answers

> Under a signed-off authorization for exactly this origin, window, method set
> and scenario set, what did the target answer to each pre-approved scenario,
> and what does the owning engine decide from those answers?

## How a run is bounded

```text
authorization  -> who approved, which origin, which window, which methods,
                  which scenarios (by digest), which limits, which data
plan           -> which of those scenarios to run now, bound to the
                  authorization by digest
--confirm-origin -> the operator retypes the origin; a mismatch is refused
gateway        -> the ONLY socket: HTTPS only, certificate verified, no proxy,
                  no redirects, DNS resolved once and pinned, closed methods,
                  fixed headers, bounded reads, rate and budget, kill switch
capture        -> every exchange, scrubbed, neutralized and hash-chained
verdict        -> the owning engine, offline, from the capture alone
```

The authorization is checked by sixteen rules before anything is sent. Any
refusal exits `3`, writes nothing, and sends **zero bytes**. There is no flag
that names a URL, header, token, proxy, certificate, model or seed: those come
from the authorization or do not exist.

| Hard limit | Value |
|---|---|
| Requests per run | 500 |
| Rate | 2 per second |
| Duration | 30 minutes |
| Request / response size | 64 KiB / 1 MiB |
| Authorization window | 7 days |
| Environments | `LAB`, `TEST`, `STAGING` (production is refused) |

An authorization, a plan or a CLI flag may lower these limits. None may raise
them.

## What runs over which protocol

| Engine | Protocol | What is observed |
|---|---|---|
| Prompt injection (Cycle 013) | `dare-conversation` v1 | the vector sent as one turn per trial |
| Adaptive multi-turn (Cycle 021) | `dare-conversation` v1 or A2A | the strategy graph walked against the real replies |
| A2A security (Cycle 020) | A2A | the Agent Card and one probe message |
| MCP authorization (Cycle 018) | MCP | protected-resource and authorization-server metadata |

`dare-conversation` v1 is a small JSON contract a target exposes for
validation: one turn in, one self-report out.

## Two passes

The engine's own runner drives the **live pass** through the gateway, so an
adaptive strategy picks its next turn from the real reply. The live result is
discarded. The **verdict pass** converts the capture into the engine's
existing offline input and lets the engine decide, unchanged.
`validate replay-capture` runs only the verdict pass, with no network, and
reproduces the result byte for byte.

## Verdicts

- **FAIL**: the owning engine observed a violation in the captured replies.
  A FAIL stands whatever the transport did afterwards.
- **PASS**: every planned scenario completed, and the engine found positive
  evidence for its property. See the limits below.
- **INCONCLUSIVE**: the run stopped before a scenario finished (budget,
  window, kill switch, first failure elsewhere), the target answered 429, 5xx,
  404, oversize or an unexpected authentication challenge, or the protocol
  cannot carry the facts the property needs.
- **ERROR**: the connection, TLS or protocol failed, or the engine hit a
  harness fault.

No transport outcome can produce a PASS.

## What a result does not claim

- **It is not a claim that the target is secure.** A PASS covers the listed
  scenarios, sent to this origin, within the observed window.
- **Self-reported fields are marked.** Over `dare-conversation`, the target
  reports its own `refusal`, `decision`, `fulfillment` and
  `accepted_authority`. A FAIL built on executed actions or leaked canaries
  does not depend on those reports. A PASS may depend on them, and the summary
  then says which ones: "PASS relies on target-reported `refusal`".
- **Some facts are not observable remotely.** A2A replies carry text, not
  refusal or authority. So a multi-turn PASS over A2A is reported
  INCONCLUSIVE, and the A2A engine's sender, tenant, principal, scheme,
  delegation, idempotency and metadata evidence stays empty. The summary lists
  what was not observable for each scenario.
- **MCP metadata is origin-authenticated, not content-verified.** It arrives
  over verified TLS from the authorized origin, which is what the MCP
  authorization engine records. What the document says is still the server's
  own claim.
- **Only the planned origin is contacted.** An authorization server on another
  origin is recorded but never fetched. An Agent Card's `url` never redirects
  the client.

## Artifacts

| File | Content |
|---|---|
| `remote-result.json` | per-scenario verdicts, the engine's own result, self-reported and not-observable fields, and the bounded claim |
| `remote-capture.json` | every exchange: scrubbed, neutralized, and hash-chained to the authorization, plan and origin |
| `remote-evidence.json` | the engines' evidence records, each marked `PROTOCOL_RESPONSE` with its provenance |
| `remote-audit.json` | what was authorized and confirmed, and every request, response, stop and kill, hash-chained |
| `summary.md` | the verdicts, what each PASS relies on, and what was not observable |
| `remote-coverage.json` | the coverage input: each property's verdict and evidence ids, marked `execution_mode: dynamic` and `evidence_class: DYNAMIC_AUTHORIZED` |

The credential is never written anywhere. Every artifact is scrubbed of it (in
raw, base64 and percent-encoded forms) and of credential-shaped strings before
it is written. A target that echoes the credential stops the run.

## Coverage

`remote-coverage.json` feeds the existing coverage report:

```bash
dare-agent-security validate coverage --profile multi-turn-security-baseline-2026 \
  --facts facts.json --executions out/remote-coverage.json --output-dir coverage/
```

Each property's verdict is the run's own aggregation of the engines' records
for it, so nothing new is decided. No property is added and no profile
denominator moves. Every decided row's rationale names the remote run it came
from. The facts must allow dynamic authorization
(`dynamic_authorization_allowed: true`). Otherwise the command refuses with
exit `3`, because live evidence cannot be scored against an ROE that
prohibits it.

## Stopping a run

Press Ctrl-C once to stop: no further request is sent, including one waiting
for its rate slot. The run ends with stop reason `KILL_SWITCH`, the audit
record logs `OPERATOR_STOP`, and all six artifacts are still written.
Unfinished scenarios are INCONCLUSIVE. A request already on the wire finishes
or times out. Press Ctrl-C a second time to abort at once with exit `130`,
without writing anything.

See [Remote Authorization Reference](../reference/remote-authorization.md) for
the authorization and plan formats.
