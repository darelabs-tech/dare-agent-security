# Evidence-Derived Attack Paths

`dare-agent-security validate attack-paths` takes the artifacts that the validation
engines already wrote and joins them into one attack graph. It then enumerates the
paths from where an attacker can start to what an attacker wants, and marks each
path with the state of the controls that guard it.

It reads local files only. It runs no engine, sends nothing, and executes no path.

## The question it answers

> Given what the engines observed, which chains of relationships lead from an
> entry point to a sensitive target? On each chain, did every control that guards
> it hold, did one fail, or was one never decided?

A single `FAIL` finding tells you that one boundary broke. A path tells you what that
break connects to.

## Inputs

```bash
dare-agent-security validate attack-paths \
  --artifacts .dare-agent-security/rag-security \
  --artifacts .dare-agent-security/identity-security \
  --system-model system-model.json \
  --output-dir .dare-agent-security/attack-paths
```

- **`--artifacts`** takes an engine's output directory, 1 to 64 of them. Each directory
  holds exactly one engine's result and evidence files. The directory also needs the
  engine inputs that the result pins, under `inputs/`:

  | Engine | What `inputs/` holds |
  |---|---|
  | tool, identity, memory, RAG, MCP Auth | `scenario.json`, the scenario the result names by digest |
  | supply chain, A2A | nothing for a built-in scenario id; otherwise `scenario.json` plus the `evidence/` directory (static mode) or the capture (replay) |
  | prompt injection, multi-turn | nothing: the result and evidence are enough |
  | remote (`validate replay-capture`) | nothing |
  | runtime telemetry | `policy.json`, the runtime policy the result pins by digest; without it the run is counted as result-only and projects nothing |

  Every input is re-bound to the digest its result pins, using the owning engine's
  own digest function. Several things are refused: an edited scenario, a changed
  evidence byte, a symlink, a path that leaves the directory, a file over 16 MiB,
  JSON nested more than 64 deep, and the same run given twice. A refusal exits `3`
  and writes nothing.
- **`--system-model`** (optional) names the entities of your system and says which
  engine-local id is which entity. Without it, runs are not joined: every node stays
  scoped to the run that produced it. See the
  [system model reference](../reference/attack-path-system-model.md).
- **Bounds.**

  | Bound | Default | Maximum |
  |---|---|---|
  | `--max-path-edges` | 8 | 12 |
  | `--max-paths` | 10,000 | 10,000 |
  | `--max-paths-per-pair` | 64 | 64 |
  | Search steps | 5,000,000 | fixed |

  A value above its maximum is refused, not clamped.

## How the graph is built

1. **Projection.** Each engine's result becomes nodes, edges and guards through a
   fixed table per engine:
   - a retrieved document `TRANSFERS_TO` the principal that read it;
   - a principal `USES_CREDENTIAL`;
   - a peer agent `CALLS` the agent under test;
   - a package `TRANSFERS_TO` the component that depends on it;
   - and so on.

   Every edge cites the evidence records that observed it, or the pinned input that
   states it.
2. **Guards.** A property the engine tested becomes a guard on the edges it
   protects, carrying the engine's verdict. When a `FAIL` names specific entities, the
   `FAIL` stays on the edges that touch them, and the other guarded edges of that run
   become `INCONCLUSIVE`. No verdict is decided again.
3. **Identity.** Two engines that both mention `user-7` are **not** assumed to mean
   the same person. Nodes join only when the system model aliases both to one entity.
4. **Designation.** Entry points are the following:
   - untrusted input, external content, a retrieved document, a memory write;
   - a peer agent, a supply-chain component, a low-privilege principal.

   Targets are the following:
   - sensitive resources, privileged credentials and destructive capabilities;
   - resources of another tenant;
   - external publication.

   Engines designate what they alone can tell, and the system model can add or
   exclude any designation.

## Feasible and discontinuous paths

A path is **feasible** when each step is explained by the authority the path has
carried so far:
- a delegation or authentication hands authority on;
- content that reaches an agent steers it;
- an access made by an actor acting under the current principal continues the path.

The first step that nothing explains makes the path **`DISCONTINUOUS`**. An example is
an access made under a principal the path never acquired. That step is reported with
its index. A discontinuous path is listed apart. It never fails the gate and never
forms a chokepoint.

## Control state

Each feasible path gets exactly one control state:

| State | Meaning |
|---|---|
| `CONTROL_FAILED` | A guard on the path is `FAIL`. The failing guards are listed |
| `CONTROL_UNDECIDED` | No guard fails, but an edge is `INCONCLUSIVE`, `ERROR`, or carries no guard at all. The undecided edges are listed |
| `CONTROLS_HELD` | Every edge on the path is guarded, and every guard is `PASS` |

A path's state is never better than its weakest edge. Structural edges
(`BELONGS_TO_TENANT`, `ENFORCED_BY`) state facts rather than accesses, so no guard is
required on them. A relationship that only the system model declares is `INFERRED` and
never assessed. A path through it is therefore at best `CONTROL_UNDECIDED`.

**Chokepoints** are the edges that every failed path to a target shares. Fixing a
chokepoint cuts every enumerated failed path to that target. It is marked `partial`
when enumeration was truncated. It is a count, not a score.

## Outputs

| File | Content |
|---|---|
| `attack-graph.json` | the v2 graph: nodes, edges with evidence and guards, entry points, targets, and the artifacts and model it came from |
| `attack-paths.json` | feasible paths, discontinuous paths, chokepoints and the enumeration record (bounds, steps used, truncation and the bound that stopped it) |
| `projection-report.json` | per artifact: verified inputs, fact counts, what was not projected and why; aliases used and unused |
| `graph.mmd`, `graph.dot` | views with evidence and control state written as text |
| `summary.md` | counts per control state, the paths, chokepoints, and what the result does not claim |

The same artifacts, given in any order, produce byte-identical files. No output
carries a wall-clock time.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Every feasible path is `CONTROLS_HELD` (or there is none), and nothing was truncated |
| 1 | Internal error |
| 2 | A feasible path is `CONTROL_FAILED` or `CONTROL_UNDECIDED`, or enumeration was truncated |
| 3 | Refusal: an invalid or unbound input, or a bound above its maximum. Nothing is written |

A gate does not pass on what was not decided.

## What a result does not claim

- **`CONTROLS_HELD` does not mean "secure".** It means that every control guarding an
  enumerated path was observed to hold in the runs you supplied, and nothing more.
- **Paths longer than `--max-path-edges` are not covered.** Neither is any
  relationship that no artifact and no system-model line states. A missing path is
  not a proof that no path exists.
- **Exit `0` with no path can mean nothing was tested.** An engine you did not run
  contributes no edge. A chain that needs its relationship simply does not appear.
- **No path was executed.** The paths are built from what the engines observed, and
  most engines run synthetic scenarios. The summary says how many artifacts came from
  synthetic runs and how many from authorized remote runs.

## Product integration

The product fixture can name a graph this command wrote, with `"attack_graph_v2":
"<path inside the target>"`. `dare-agent-security assess` then validates the graph with
the v2 contract and writes it as the run's `attack-graph.json`. The product does not
construct the graph itself.
