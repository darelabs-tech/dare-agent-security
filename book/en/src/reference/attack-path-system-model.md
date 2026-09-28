# Attack-Path System Model Reference

The system model is the optional `--system-model` file of
[`validate attack-paths`](../concepts/attack-paths.md). It names the entities of your
system. It says which engine-local id is which entity, and it adds or removes entry
points and targets. It can also declare relationships that no engine observes.

Schema: `schemas/attack-path/v1/system-model.schema.json` (JSON Schema draft 2020-12,
`additionalProperties: false` throughout). The model is limited to 4 MiB and 64 levels
of nesting.

## Why identity needs a model

Engine ids are local to a scenario. `user-7` in a RAG run and `user-7` in a memory run
are two strings that two scenario authors wrote. Nothing proves they are the same
principal. So every node is **run-scoped** unless the model aliases it:

```text
node:<type>:<engine>:<run>:<local id>    run-scoped (no alias)
node:<type>:<entity id>                  an entity (aliased)
```

`<run>` is the first 12 hex digits of the SHA-256 of the run's result file. Two runs
join only at nodes that are aliased to the same entity.

## Top-level fields

| Field | Required | Content |
|---|---|---|
| `schema_version` | yes | `"1"` |
| `model_id` | yes | `^[a-z0-9][a-z0-9._-]{0,95}$` |
| `target_id`, `target_version` | yes | 1–160 characters; they become the graph's target |
| `entities` | yes | 1–2,000 entities |
| `aliases` | no | up to 10,000 |
| `entry_points`, `targets` | no | up to 2,000 each |
| `trust_boundaries` | no | up to 64, with up to 500 entities each |
| `declared_edges` | no | up to 5,000 |

## Entities

```json
{ "entity_id": "alice", "type": "HUMAN", "display_name": "Alice (tenant-a user)",
  "security": { "tenant": "tenant-a", "privileged": false, "sensitive": false, "destructive": false } }
```

- `entity_id` matches `^[a-z0-9][a-z0-9._-]{0,95}$`, so it cannot contain `:`.
- `type` is one of: `HUMAN`, `AGENT`, `IDENTITY`, `DELEGATED_AUTHORITY`, `MCP_SERVER`,
  `CAPABILITY`, `TOOL`, `CREDENTIAL`, `DOWNSTREAM_SERVICE`, `RESOURCE`, `DATA`, `TENANT`,
  `POLICY_DECISION_POINT`, `POLICY_ENFORCEMENT_POINT`.
- `security` flags merge with what the engines projected. A `sensitive` node, a
  `privileged` credential and a `destructive` node become targets.
- An entity is a node of the graph even when no alias matches it.

## Aliases

```json
{ "engine": "rag", "local_id": "user-7", "entity_id": "alice" }
{ "engine": "mcp-auth", "local_id": "cred-inbound", "run": "63821ecc58de", "entity_id": "inbound-token" }
```

- `engine` is one of: `prompt-injection`, `tool`, `identity`, `memory`, `rag`,
  `mcp-auth`, `supply-chain`, `a2a`, `multi-turn`, `remote`.
- Without `run`, the alias applies to every run of that engine. With `run`, it applies
  to that run only.

## Designations

```json
{ "entity_id": "uploaded-doc", "class": "RETRIEVED_DOCUMENT" }
{ "node_id": "node:resource:mcp-auth:63821ecc58de:mcp-invoices", "class": "SENSITIVE_RESOURCE" }
{ "entity_id": "handbook", "class": "RETRIEVED_DOCUMENT", "exclude": true }
```

- Each designation names exactly one of `entity_id` or `node_id`.
- Entry classes: `UNTRUSTED_INPUT`, `EXTERNAL_CONTENT`, `RETRIEVED_DOCUMENT`,
  `MEMORY_WRITE`, `PEER_AGENT`, `SUPPLY_CHAIN_COMPONENT`, `LOW_PRIVILEGE_PRINCIPAL`.
- Target classes: `SENSITIVE_RESOURCE`, `PRIVILEGED_CREDENTIAL`,
  `DESTRUCTIVE_CAPABILITY`, `CROSS_TENANT_RESOURCE`, `EXTERNAL_PUBLICATION`.
- `exclude: true` removes a designation of the same class, whether an engine made it or
  the model did.

## Trust boundaries

```json
{ "boundary_id": "support-zone", "entity_ids": ["assistant", "ticket-doc"] }
```

An edge with exactly one endpoint inside a boundary lists that boundary in
`crosses_trust_boundary`. A path with such an edge has `crosses_trust_boundary: true`
among its impact factors.

## Declared edges

```json
{ "type": "TRANSFERS_TO", "source": "support-agent", "target": "assistant",
  "status": "INFERRED",
  "rationale": "The support-agent build is the code the assistant runs." }
```

- Declared edges state a relationship that no engine artifact states: a deployment
  fact, or an architecture you know.
- `INFERRED` requires a `rationale`, and `NOT_TESTED` requires a `reason`. The edge
  cites the model line it came from.
- A declared edge carries **no guard**, so a path through it is at best
  `CONTROL_UNDECIDED`. Declaring a relationship never makes a path look controlled.
- `authority.principal`, when given, is checked by the continuity rules like any
  other. An access made under a principal the path never acquired makes the path
  `DISCONTINUOUS`.

## Refusals

Each of the following exits `3` and writes nothing. The message names the position in
the model, never its content.

| Refusal | Cause |
|---|---|
| duplicate entity | two entities with one `entity_id` |
| unknown entity | an alias, boundary or declared edge names an entity that does not exist |
| conflicting alias | one `(engine, local_id[, run])` key maps to two entities |
| type clash | an alias matches a projected node whose type differs from the entity's; pick one type, there is no implicit equivalence |
| tenant clash | an entity's `tenant` differs from the tenant an engine projected for a node aliased to it |
| unsafe label | a `display_name` fails the label check (markup, control characters, credential-shaped text) |
| unknown designation target | a designation resolves to no node of the graph |
| declared edge without rationale / reason | an `INFERRED` edge with no rationale, or a `NOT_TESTED` edge with no reason |
| invalid document | schema violation, over 4 MiB, deeper than 64, a symlinked file, a list over its limit, or an id containing `:` |

An alias that matches no node is **not** an error. It is listed under `aliases_unused`
in `projection-report.json`, so a typo can be found.

## A worked example

This model joins a RAG run and an identity run through one person, and makes an
uploaded document an entry point:

```json
{
  "schema_version": "1", "model_id": "support-desk", "target_id": "support-desk", "target_version": "2026.09",
  "entities": [
    { "entity_id": "alice", "type": "HUMAN", "display_name": "Alice", "security": { "tenant": "tenant-a" } },
    { "entity_id": "uploaded-doc", "type": "DATA", "display_name": "Uploaded document" },
    { "entity_id": "index-admin-cred", "type": "CREDENTIAL", "display_name": "Index admin credential",
      "security": { "privileged": true } }
  ],
  "aliases": [
    { "engine": "rag", "local_id": "user-7", "entity_id": "alice" },
    { "engine": "identity", "local_id": "user-7", "entity_id": "alice" },
    { "engine": "rag", "local_id": "doc-upload", "entity_id": "uploaded-doc" },
    { "engine": "identity", "local_id": "cred-index-admin", "entity_id": "index-admin-cred" }
  ],
  "entry_points": [ { "entity_id": "uploaded-doc", "class": "RETRIEVED_DOCUMENT" } ]
}
```

With a RAG run whose content-trust check failed, and an identity run whose
privilege-amplification check failed, the result is one path:
uploaded document → Alice → index admin credential. It is `CONTROL_FAILED` on both
properties. This is ATTACK-PATH-LAB scenario APL-001, under
`crates/dare-agent-security-cli/tests/fixtures/attack-path-lab/`.
