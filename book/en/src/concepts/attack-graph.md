# Attack Graph

The Agent Attack Graph models bounded agent → tool → resource paths so you
can see *how* individual findings could chain together, not just that they
exist in isolation.

## What it is

- A **deterministic, bounded** graph built from normalized facts you (or an
  upstream discovery/coverage step) supply — it does not itself execute
  anything.
- Path derivation is hard-capped: at most 64 edges per path and 10,000 paths
  emitted, so graph generation always terminates and stays reviewable.
- Output includes canonical JSON plus rendering artifacts: Mermaid, DOT, and
  a plain-text summary.

## What it is not

- It does not perform live exploitation or execute an attack path against a
  real target — analysis only.
- It is not a general-purpose graph database; it is scoped to the
  agent/tool/resource facts you provide for one assessment run.

## Reading the graph

Each path represents a sequence of steps an agent could take from an entry
point to a sensitive resource, given the facts observed. Use it to prioritize
remediation: a `FAIL` finding that sits on a short path to a sensitive
resource matters more than one that is graph-isolated.

## Where it's generated

`validate attack-graph` (power-user) or automatically as part of product
`assess`, writing `attack-graph.json`, `paths.json`, `graph.mmd`, `graph.dot`,
and `summary.md` — see [Generated Artifacts](../reference/artifacts.md).
