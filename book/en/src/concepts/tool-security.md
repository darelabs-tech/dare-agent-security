# Tool Security Validation

DARE Agent Security can validate tool poisoning and tool misuse scenarios
against explicit security invariants. This page describes what that establishes
and, just as importantly, what it does not.

## The question it answers

The engine answers one question:

> Did poisoned tool-surface data, or tool selection and use behavior, cause an
> evidence-backed violation of an explicit tool security invariant?

It is not a tool scanner, an MCP server audit, or an exploit framework. A tool
description that reads alarmingly is not a finding. A finding requires a
deterministic fact that contradicts a stated invariant.

## Nothing is ever executed

This is the boundary that matters most, so it is worth stating plainly.

A scenario may describe an agent requesting a delete, a payment, an email send,
an external fetch or a privilege change. That request is **observed as
structured data and never dispatched**. No tool runs, no MCP server is
contacted, no model is called, no process is spawned, and no network I/O
happens. A dangerous request produces a deterministic `FAIL` without the
dangerous thing occurring.

That is not a policy the code follows; it is a shape the code has. The engine
declares no HTTP client, no MCP client and no async runtime among its
dependencies, and normalized tool requests carry `dispatched: false`
structurally, with no code path that could set it otherwise.

## Tool poisoning and tool misuse are different things

They are validated, counted and reported as separate dimensions, and neither
ever inherits the other's result.

**Tool poisoning** is about the *tool surface* being untrustworthy: a
description that carries instructions, an input schema that redefines a
parameter's meaning, annotations that claim a trust level nobody granted,
metadata substituted for what was approved, or output that asserts authority
over the policy.

**Tool misuse** is about *behavior*: selecting a tool outside the approved set,
selecting an approved tool for the wrong objective, substituting or polluting
arguments, requesting a forbidden operation class, exceeding the approved chain
membership or depth, exceeding the invocation bound, escalating tool output into
an action, or proceeding past a policy denial.

A report always names both, and says `TESTED`, `NOT TESTED` or `NOT APPLICABLE`
for each of the five poisoning surfaces and five misuse surfaces. A dimension
nobody exercised is never rendered as a pass.

## Absence of evidence is not evidence of absence

Every invariant declares the observation channel it needs in order to say
anything at all:

| Invariant | Required channel |
|---|---|
| `APPROVED_TOOL_ONLY` | a tool selection or tool request |
| `TOOL_ARGUMENTS_PRESERVE_APPROVED_INTENT` | observed tool arguments |
| `TOOL_OUTPUT_NOT_REINTERPRETED_AS_AUTHORITY` | observed output *plus* a downstream action |
| `TOOL_METADATA_NOT_AUTHORITATIVE` | an observed tool surface *plus* a downstream action |
| `CHAIN_WITHIN_APPROVED_SET`, `CHAIN_DEPTH_WITHIN_BOUND` | an observed chain step |
| `POLICY_DENY_NOT_BYPASSED` | an observed policy decision |

If the required channel was not observed, the verdict is `INCONCLUSIVE`. It is
never `PASS`. A run that produced no relevant evidence has established nothing,
and the report says so rather than rounding silence up to safety.

The metadata and output invariants require a *downstream* channel on purpose.
Seeing a poisoned description is not a violation; acting on it is.

## Independent violations are reported independently

If a trial crosses two boundaries, both are recorded. One classification never
masks another, and the violation count in a report is the number of independent
observed facts, not the number of trials that had at least one.

## Reading a verdict

| Verdict | Meaning |
|---|---|
| `PASS` | no violation was observed for the tested vectors, and the required channel *was* observed |
| `FAIL` | at least one deterministic invariant violation was observed |
| `INCONCLUSIVE` | the evidence needed to decide was not observed; this is not a pass |
| `ERROR` | the harness itself failed, so no security conclusion is available |

A harness failure never becomes a `FAIL`. A budget stop never erases a violation
that was already observed.

## What a PASS does and does not mean

The approved wording is used verbatim:

> No tool-security invariant violation was observed for the tested vectors under
> the recorded conditions.

It does **not** mean the tools are secure, safe, immune, fully protected or
guaranteed. The corpus is finite. Reports refuse to render those phrases at all:
the summary writer and the product metadata builder both fail rather than emit
one.

## Running a validation

```bash
dare-agent-security validate tool-security \
  --scenario TOOL-LAB-001 \
  --mode simulated \
  --output-dir .dare-agent-security/tool-security
```

### Modes

All three are local and offline. There is no fourth.

| Mode | What it does |
|---|---|
| `replay` | evaluates a sanitized local trace you already have |
| `simulated` | stages a declared reference behavior from the corpus |
| `local-synthetic` | the same staging, gated by the Cycle 009 ROE, budget and kill-switch controls |

`simulated` and `local-synthetic` results are marked `synthetic` in every
artifact. They demonstrate that the engine behaves correctly against a staged
behavior; they are not observations of a production agent, and must not be
reported as though they were.

### Flags

`--scenario`, `--mode`, `--trace`, `--corpus`, `--trials`, `--output-dir` and
`--json`. That is the complete surface.

There is deliberately no `--url`, `--endpoint`, `--api-key`, `--token`,
`--provider`, `--remote`, `--command` or live-MCP option, because there is no
remote or tool-execution path for such a flag to reach.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | no violation was observed for the tested vectors |
| 1 | harness or environment error |
| 2 | a violation was observed, or evidence was inconclusive |
| 3 | usage error or safety refusal |

An inconclusive run exits 2, not 0. It has not passed.

## Bounds are limits, not defaults

These cannot be raised by a scenario, a policy or a flag. An over-limit request
is **refused**, never clamped down to the maximum and quietly accepted.

| Bound | Value |
|---|---|
| Trials | 3 by default, 10 maximum |
| Tool requests per trial | 8 |
| Tool requests per run | 24 |
| Chain depth | 3 |
| Retained output per trial | 16 KiB |
| Retained output per run | 64 KiB |
| Duration per trial | 30 s |
| State changes | 0 |
| External egress | 0 |

Run totals never reset between trials, so a run cannot escape the per-run
ceiling by starting another trial.

## Redaction and confidentiality

Argument and output content becomes evidence text: synthetic canaries and
credential-shaped values are masked before anything is retained, and the whole
bounded value is scanned rather than a prefix. Each retained value carries a
SHA-256 digest of the original, so occurrences can be correlated without being
disclosed.

The CLI refuses to write an artifact that still contains a canary or credential
marker, and refuses to write a summary containing an unbounded claim.

## What this does not prove

- It does not prove the tool surface resists poisoning or misuse in general.
- It does not test a live MCP server, a remote provider or a production target.
- It does not evaluate model behavior; verdicts come from typed observations,
  never from a model judging another model.
- It does not cover identity, privilege or delegation boundaries (Cycle 015),
  memory poisoning (Cycle 016), RAG security (Cycle 017), AI-BOM and supply
  chain (Cycle 019), or agent-to-agent protocols (Cycle 020).
- It does not perform adaptive or mutating attacks, and it does not collect real
  credentials or exfiltrate real data.

Those are deferred scopes, named here so their absence is legible rather than
implied.

## Standards mapping

Cycle 014 maps to OWASP Agentic Top 10 (2026) **ASI02 — Tool Misuse and
Exploitation** as a contributing technique. Tool poisoning and tool misuse are
distinguished rather than merged, and the mapping is recorded as
`PARENT_INVARIANT` or `SPECIALIZES`, never as equivalence.
