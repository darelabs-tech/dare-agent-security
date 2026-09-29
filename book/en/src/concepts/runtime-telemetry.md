# Runtime Telemetry Security

`dare-agent-security validate runtime-telemetry` reads **OpenTelemetry trace exports**
that an agent system already recorded, together with an optional **runtime policy**, and
judges what the traces show the agents did at runtime: which tools they called, under
which principal, against which tenant's data, to which hosts, how often they retried,
and whether the telemetry itself leaks secrets or is too incomplete to judge.

It reads local files only. It emits no telemetry, opens no port, contacts no collector
and never calls the system under test.

## The question it answers

> Given the spans this system exported, did its agents stay inside the runtime policy,
> and is the telemetry itself confidential and complete enough to prove it?

A result never rests on absence. A property passes only on traces that are proven
complete for it and that contain at least one positive observation. A missing span is
never taken as evidence that nothing happened.

## Inputs

```bash
dare-agent-security validate runtime-telemetry \
  --traces export-1.json --traces export-2.json \
  --policy runtime-policy.json \
  --output-dir .dare-agent-security/runtime-telemetry
```

- **`--traces`** takes an OTLP/JSON trace export (`ExportTraceServiceRequest`), 1 to 64
  of them. Each file is admitted before it is parsed: no symbolic link, at most 16 MiB
  per file and 256 MiB in total, and JSON nested at most 64 levels deep. It is then
  checked against a closed subset of the OTLP/JSON mapping:
  - trace and span ids are hexadecimal of the right length, in either case, and an
    all-zero id is refused;
  - times are integers, given as a string or as a number;
  - `kind` and `status.code` are integers;
  - at most 256 attributes are allowed per span.

  A refusal names the file by its position, never its content. File order never
  matters: files are processed in content-digest order.
- **`--policy`** (optional) is the runtime policy. Without it, only the two telemetry
  properties are judged.
- **`--max-spans`** (default and maximum 1 000 000) can only lower the span bound. A
  run that reaches the bound reports `stop_reason: max_spans` and never passes a
  property.
- **`--json`** also prints the result document.

There is no endpoint, listener, port, collector, header, token, exec or mode flag.

## The runtime policy

```json
{
  "schema_version": "1",
  "policy_id": "support-desk",
  "content_capture_allowed": false,
  "principal_keys": ["user.id"],
  "tenant_keys": ["tenant.id"],
  "approval": {"event_name": "dare.approval", "tool_key": "gen_ai.tool.name"},
  "required_operations": ["TOOL_EXEC"],
  "agents": [{
    "name": "assistant",
    "allowed_tools": ["search", "refund"],
    "destructive_tools": ["refund"],
    "principal": "user-7",
    "tenant": "tenant-a",
    "egress_hosts": ["api.example.com", "*.docs.example.com"],
    "max_retries": 1
  }]
}
```

The policy is closed: an unknown field is refused. OpenTelemetry has no stable
convention for principals or tenants, so the policy names the attribute keys to read.
Each key must come from a closed allow-list: `user.id`, `enduser.id`,
`enduser.pseudo.id` and `user.name` for principals, and `tenant.id`,
`gen_ai.data_source.id` and `gen_ai.memory.store.id` for tenants. A key that is not on
the list is refused rather than guessed.

## How spans are recognized

Span kinds come from a pinned mapping of the OpenTelemetry semantic conventions
(`standards/runtime-telemetry/2026/semconv-mapping.json`). The pins are the core
conventions `v1.44.0` and the GenAI conventions at a pinned commit, because the GenAI
conventions have no release yet.

| Kind | Recognized by |
|---|---|
| agent invocation | `gen_ai.operation.name = invoke_agent` |
| model call | `chat`, `text_completion`, `generate_content`, `embeddings` |
| tool execution | `execute_tool` |
| retrieval | `retrieval` |
| memory | `search_memory`, `upsert_memory`, `update_memory`, `create_memory`, `delete_memory` |
| MCP call | `mcp.method.name` |
| HTTP client | a CLIENT span with `http.request.method` |

The **acting agent** of a span is the nearest agent-invocation span above it. Attribute
keys the mapping does not know are counted, never interpreted.

## Rules

| Rule | Property | Fails when |
|---|---|---|
| B-1 | `AGENT.TOOL.AUTHORIZATION_BOUNDARY` | a tool runs that the acting agent's `allowed_tools` does not list, or its agent is not in the policy |
| B-2 | `AGENT.HUMAN_APPROVAL.INTENT_BINDING` | a destructive tool runs without an earlier approval event naming that tool |
| B-3 | `AGENT.IDENTITY.PRINCIPAL_BINDING` | an agent or tool span runs under a principal other than its agent's policy principal |
| B-4R | `AGENT.RAG.TENANT_DOCUMENT_ISOLATION` | a retrieval span carries another tenant |
| B-4M | `AGENT.MEMORY.TENANT_BOUNDARY` | a memory span carries another tenant |
| B-5 | `AGENT.CODE_EXECUTION.EGRESS_BOUNDARY` | an HTTP client span targets a host outside `egress_hosts` (`server.address`, or the host of `url.full`; exact match or a `*.` suffix) |
| B-6 | `AGENT.FAILURE.RETRY_AMPLIFICATION` | calls to the same target under the same parent are retried after failures more than `max_retries` times, or `http.request.resend_count` exceeds it |
| T-1 | `AGENT.TELEMETRY.CONFIDENTIALITY` | an attribute, event or span name carries a credential marker, a bearer token, an e-mail address or a credential-bearing HTTP header; or GenAI content (messages, system instructions, tool arguments or results) is exported although `content_capture_allowed` is false |
| T-2 | `AGENT.TELEMETRY.COMPLETENESS` | a span of a kind the policy requires lacks the keys that kind needs |

B-1 to B-6 need a policy. Without one they are `NOT_APPLICABLE`, and T-1 treats content
capture as not allowed.

## Completeness

Before any rule passes a trace, the trace must be complete for that rule. Each of the
following gaps makes the rule **INCONCLUSIVE** on that trace, never PASS:

- an orphan span;
- a conflicting duplicate span id;
- a parent cycle or a malformed tree;
- a tree deeper than 256 levels;
- a missing root;
- a child that starts before its parent;
- dropped attributes, events or links;
- an unsampled span anywhere in the trace;
- no span of a kind the rule needs;
- a missing key the rule reads;
- a value too long to scan;
- the span bound.

A violation that is seen is still a **FAIL**, even on an incomplete trace. Identical
duplicate spans across files are removed and counted.

Per property, the traces combine as FAIL > INCONCLUSIVE > PASS. If no trace exercised
the property, it is `NOT_TESTED` and has no verdict. A required operation that no trace
shows makes T-2 INCONCLUSIVE. The run verdict follows the same order. A run that judged
nothing is INCONCLUSIVE.

## No value leaves

Attribute values stay in memory. Every artifact carries only attribute keys, trace and
span ids, rule codes and **fingerprints**: the kind, the length and a SHA-256 digest of a
value, never the value itself. This holds for every tool name, host, principal, tenant,
prompt, completion and tool argument. A key that is not a plain dotted name is written as
a digest of itself. Every artifact passes the product's credential sweep before the
first byte is written.

## Outputs

| File | Contents |
|---|---|
| `runtime-telemetry-result.json` | input digests and span counts, the semantic-convention pins and mapping digest, the policy id and digest, bounds and stop reason, traces by kind, incomplete traces with their gaps, and each property's verdict, coverage, reason, per-trace counts and evidence id |
| `runtime-telemetry-evidence.json` | Cycle 001 `SecurityEvidence` records (`observed.source = RUNTIME_EVENT`), the passive `TRACE` executions document, and the Cycle 006 coverage report over `runtime-telemetry-baseline-2026` |
| `runtime-telemetry-findings.json` | every failing or undecided trace: rule, trace id, span ids, keys, fingerprints and reason codes |
| `summary.md` | counts, per-property verdicts with reasons, incomplete and failing traces by id, with names neutralized, and what the result does not claim |

The same inputs in any file order give byte-identical files, and no output carries a
time. Evidence timestamps are the traces' own span times.

## Coverage

The run records two new properties, `AGENT.TELEMETRY.CONFIDENTIALITY` and
`AGENT.TELEMETRY.COMPLETENESS`, gated by the predicate `runtime_trace_present`. It feeds
the optional profile `runtime-telemetry-baseline-2026`, which covers the nine properties
the rules judge. The telemetry properties and retry amplification are `REQUIRED`; the
rest are `CONDITIONAL`.

## Attack paths

An output directory with the policy copied to `inputs/policy.json` can be given to
[`validate attack-paths`](attack-paths.md). The policy is re-bound by its canonical
digest. Its declared agents, tools, principals, hosts and tenant stores become
statically proven relationships, and the traces' verdicts guard them.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Every judged property is PASS; the rest are `NOT_APPLICABLE` or `NOT_TESTED` |
| 1 | Internal error |
| 2 | A property is FAIL or INCONCLUSIVE, or nothing could be judged |
| 3 | Refusal: admission, trace or policy schema, a bound out of range, the output directory, or an artifact that would carry a credential-shaped value. Nothing is written |

## What a result does not claim

- **The traces are self-reported.** The system under test produced them, and this tool
  judged only what they record.
- **No authenticity is claimed.** The exports are unsigned. A forged or edited export
  cannot be told from a real one.
- **Absence is not proof.** A span, event or attribute missing from a trace is never
  evidence that the action did not happen.
- **A PASS covers only the supplied traces**, and only those proven complete for the
  property.
