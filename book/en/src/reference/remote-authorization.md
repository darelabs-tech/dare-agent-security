# Remote Authorization Reference

`validate remote` reads two documents: an **authorization** that the target's
owner approves, and a **plan** that selects what to run under it. Both are JSON,
validated against `schemas/remote-validation/v1/`, capped at 256 KiB, and refuse
unknown fields. This page lists every field and every rule.

## Authorization (`authorization.schema.json`)

| Field | Meaning |
|---|---|
| `schema_version` | `"1"` |
| `authorization_id` | lowercase identifier, 3–64 characters |
| `target_owner`, `approved_by` | who owns the target and who approved this run |
| `environment` | `LAB`, `TEST` or `STAGING` (`PRODUCTION` is refused) |
| `origins` | 1–4 origins, each `https://host[:port]`: no path, query, userinfo or fragment |
| `network_scope` | `LOOPBACK_LAB` (exactly when `LAB`), `PRIVATE` or `PUBLIC` |
| `not_before`, `not_after` | RFC 3339; at most 7 days apart |
| `endpoints` | `conversation`, `a2a_rpc`, `mcp`: absolute paths on the origin |
| `protocols` | any of `DARE_CONVERSATION`, `A2A`, `MCP` |
| `methods` | the closed set below; each must belong to a granted protocol |
| `scenarios` | `{engine, scenario_id, scenario_digest, graph_digests?}`: what may run, pinned by the engine's own digest |
| `data_classes` | only `SYNTHETIC`, `CANARY`, `TEST` |
| `credential_ref` | optional; the **name** of an environment variable, never a value |
| `limits` | optional lowering of the hard limits |
| `prohibited` | must contain all of `STATE_MUTATION`, `CREDENTIAL_EXTRACTION`, `DESTRUCTIVE_OPERATION`, `EXTERNAL_PUBLICATION` |
| `signature` | reserved; must be absent in v1 |

### Closed method set

| Protocol | Methods |
|---|---|
| `DARE_CONVERSATION` | `DARE_CONVERSATION_TURN` |
| `A2A` | `A2A_AGENT_CARD_GET`, `A2A_MESSAGE_SEND`, `A2A_TASKS_GET` |
| `MCP` | `MCP_INITIALIZE`, `MCP_INITIALIZED`, `MCP_TOOLS_LIST`, `MCP_RESOURCES_LIST`, `MCP_PROMPTS_LIST`, `MCP_RESOURCES_READ`, `MCP_PROMPTS_GET`, `MCP_PROTECTED_RESOURCE_METADATA_GET`, `MCP_AUTH_SERVER_METADATA_GET` |

All of them are read-only. `MCP_RESOURCES_READ` and `MCP_PROMPTS_GET` are sent
only for a URI or name the server listed earlier in the same run.

## Plan (`plan.schema.json`)

| Field | Meaning |
|---|---|
| `schema_version`, `plan_id` | `"1"` and an identifier |
| `authorization_id`, `authorization_digest` | the authorization this plan runs under, pinned by digest |
| `origin` | one of the authorization's origins |
| `protocol` | one granted protocol |
| `methods` | a subset of the authorization's methods for that protocol |
| `runs` | 1–32 `{engine, scenario_id, scenario_digest, graph_digests?, a2a_policy_file?}`, each granted by the authorization |
| `limits` | optional further lowering |
| `stop_on_first_fail` | default `true` |

`a2a_policy_file` is a plain `*-policy.json` name resolved under `--policy-dir`.
Any path that could leave that directory is refused.

## The sixteen rules

They are checked in this order. The first one that fails refuses the run with
exit `3`, before any byte is sent and before anything is written.

| # | Refused when |
|---|---|
| 1 | the schema version is not supported |
| 2 | a signature is present (reserved in v1) |
| 3 | the environment is production |
| 4 | an origin is malformed, duplicated or out of range |
| 5 | the network scope and the environment disagree, or a `LAB` authorization names a non-loopback origin |
| 6 | an origin's address is not permitted in its scope (metadata, link-local and reserved addresses never are) |
| 7 | the window is invalid, longer than 7 days, or not current (`not_before` is inside; `not_after` is outside) |
| 8 | a mandatory prohibition is missing |
| 9 | data classes are empty or outside `SYNTHETIC`/`CANARY`/`TEST` |
| 10 | a protocol lacks its endpoint, or a method lacks its protocol |
| 11 | a limit is zero or above its hard maximum |
| 12 | the plan does not pin this authorization's digest |
| 13 | the plan's origin, protocol or methods are not granted |
| 14 | a planned scenario is not granted with this digest, or its engine now computes a different one |
| 15 | `--confirm-origin` does not equal the planned origin |
| 16 | the credential variable is not set, or is out of range |

## `dare-conversation` v1

A target exposes one endpoint for validation. Each request carries exactly:

```json
{"schema_version": "1", "conversation_id": "conv-a", "turn_index": 0,
 "principal_id": "p-analyst", "content": "…the pre-approved turn…"}
```

It never names a node, an invariant, a canary or an expected outcome. The reply
echoes `conversation_id` and `turn_index` and reports on the turn:

| Field | Type |
|---|---|
| `output_text` | string or null |
| `refusal` | bool |
| `decision` | `ALLOW`, `DENY` or null |
| `fulfillment` | `FULL`, `PARTIAL` or `NO_FULFILLMENT` |
| `accepted_authority` | `NONE`, `READ`, `WRITE`, `ADMIN` or null |
| `actions` | `[{action_id, action_class, executed, approval_ref, action_digest, required_authority, argument_text}]` |
| `goal_id`, `emitted_fields`, `policy_decisions` | optional; read by the prompt-injection engine only |

A reply that does not validate, that echoes the wrong turn, or that adds a
field (such as its own `"verdict"`) is a protocol violation, and the scenario
is never PASS. Every field is target-reported, and the summary names the ones
a PASS relies on.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | every scenario PASS |
| 1 | ERROR (connection, TLS, protocol or engine) |
| 2 | FAIL or INCONCLUSIVE |
| 3 | refusal: nothing sent, nothing written |

## Example

```bash
DARE_REMOTE_TOKEN=… dare-agent-security validate remote \
  --authorization auth.json --plan plan.json \
  --confirm-origin https://agent.staging.example.test \
  --output-dir out/

# Recompute the same verdicts later, with no network:
dare-agent-security validate replay-capture \
  --capture out/remote-capture.json --audit out/remote-audit.json \
  --authorization auth.json --plan plan.json --output-dir replayed/
```
