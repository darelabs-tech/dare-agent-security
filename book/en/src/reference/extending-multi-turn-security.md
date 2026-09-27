# Extending Multi-Turn Security Validation

This page is for adding MULTITURN-LAB entries or replaying your own
conversations.

## Files

| Document | Schema |
|---|---|
| Scenario | `schemas/multi-turn-security/v1/scenario.schema.json` |
| Strategy graph | `schemas/multi-turn-security/v1/strategy-graph.schema.json` |
| Transcript | `schemas/multi-turn-security/v1/transcript.schema.json` |
| Result | `schemas/multi-turn-security/v1/result.schema.json` |

Every input goes through the same admission path. Each check runs before any
turn:
- size ≤ 4 MiB and depth ≤ 32;
- `schema_version` must be `"1"`;
- a hostile sweep refuses executable, credential, remote/model, **generation**
  (`generate`, `mutate`, `template`, `paraphrase`, `seed`, `temperature`) and
  self-verdict field names, as well as control, bidi and zero-width characters
  and credential-shaped values;
- the JSON Schema, with `additionalProperties: false`.

## Writing a strategy graph

- Every node is a complete, pre-authored turn. There is no templating.
- Edges map an observation class to the next node. `UNCLASSIFIABLE` can never
  be an edge label, because it always stops the path.
- The graph must be acyclic, and every node must be reachable. Terminals have
  no outgoing edges, and non-terminals have at least one.
- To express "try again with another framing", add explicit nodes.
- A node may carry:
  - `plants_canary`, a declared canary: the node plants it;
  - `claimed_authority`, a claim above the principal's verified level;
  - `approval` (only on `APPROVAL` turns);
  - `proposes_action_class`.

A missing edge is legitimate. The run stops with `NO_TRANSITION`, and the
result is INCONCLUSIVE, never PASS.

## Replaying your own conversation

A scenario file runs in `replay` mode only:

```bash
dare-agent-security validate multi-turn \
  --scenario scenario.json --graph graph.json \
  --mode replay --transcript transcript.json --output-dir out/
```

Each recorded turn names the node it answered, and indices must be `0, 1, 2, …`.
- A reordered, duplicated or gapped transcript is refused (exit 3).
- A recorded `chain_digest` that does not match is refused as tampering.
- A turn for the wrong node, a missing turn or a left-over turn is a strategy
  fault (ERROR).

The simulated reference agents belong to the lab. A scenario file cannot be run
by one, so a real scenario is never labelled with a synthetic behaviour.

## Adding a corpus entry

Entries live in `crates/dare-multi-turn-security/src/corpus.rs` and state a
**class** (`CONTROL`, `ATTACK`, `GAP`, `FAULT`, `REFUSAL`), never a verdict.
The harness contract in `tests/multiturn_lab.rs` asserts the outcome per
class, in every mode the entry is staged for. Every agent-driven entry is also
recorded and replayed to the same verdict. Add a control next to every new
attack: an engine that failed everything must fail the corpus.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | PASS |
| 1 | ERROR (harness error or strategy fault) |
| 2 | FAIL or INCONCLUSIVE |
| 3 | usage error or refusal; nothing is written |
