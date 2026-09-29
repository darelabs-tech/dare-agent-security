# Blast Radius

`dare-agent-security validate blast-radius` takes an attack graph written by
[`validate attack-paths`](attack-paths.md) and a set of compromised starting points,
called **seeds**. It reports what each seed can reach. For every target reached, it also
reports whether a control observed to hold stands between the seed and that target.

It reads local files only. It runs no engine, sends nothing, and executes no reach.

## The question it answers

> If this principal, credential, piece of content or component were compromised, which
> sensitive targets could the attacker reach through the relationships the engines
> observed? For each target, does some route get there without crossing a control that
> held?

An attack path starts from a designated entry point. A blast radius starts from
whatever you say was compromised, and it reports reach in counts and routes, never as a
score.

## Inputs

```bash
dare-agent-security validate blast-radius \
  --graph .dare-agent-security/attack-paths/attack-graph.json \
  --compromise compromise.json \
  --output-dir .dare-agent-security/blast-radius
```

- **`--graph`** is the v2 `attack-graph.json`. It is admitted with a 16 MiB size limit,
  a 64-level JSON depth limit and no symbolic links, then validated with the v2 graph
  contract. A graph edited after `validate attack-paths` sealed it is refused.
- **`--compromise`** names the seeds. As an alternative, **`--seed-entry-points`** seeds
  every entry point of the graph. Exactly one of the two is required.

  ```json
  {"schema_version": "1", "scenario_id": "inbound-token-leak",
   "graph_id": "graph:<64 hex>",
   "seeds": [{"node_id": "node:credential:inbound-token", "kind": "CREDENTIAL_LEAK"}]}
  ```

  `graph_id` binds the scenario to one graph, and a scenario for another graph is
  refused. A seed names a `node_id`, or an `entity_id` that names exactly one node.
  There can be up to 64 seeds.
- **Bounds.** A value above its maximum is refused, not lowered. A scenario may lower a
  bound further.

  | Bound | Default | Maximum |
  |---|---|---|
  | `--max-depth` (edges per walk) | 8 | 12 |
  | `--max-states` (per search) | 1 000 000 | 1 000 000 |
  | States in total | 5 000 000 | fixed |

## Seed kinds

| Kind | Fits | The attacker starts as |
|---|---|---|
| `PRINCIPAL_TAKEOVER` | human, agent, identity | that principal, acting as itself |
| `CREDENTIAL_LEAK` | credential | a holder of that credential |
| `CONTENT_INJECTION` | data | content with no principal of its own, which steers whatever agent it reaches |
| `COMPONENT_COMPROMISE` | tool, MCP server, capability, downstream service | the component itself, with no principal of its own |

A kind that does not fit its node is refused. With `--seed-entry-points`, an entry
point's class gives its kind: a low-privilege principal or a peer agent becomes a
takeover; untrusted input, external content, a retrieved document or a memory write
becomes an injection; a supply-chain component becomes a component compromise.

A compromised component does not gain a principal it never acquired. It continues
through unnamed accesses, credentials it uses and delegations it makes. However, an
access that the graph says runs under a named principal is refused unless the walk
acquired that principal. The step is counted, not taken.

## How reach is computed

Each step follows the same continuity rule that [attack paths](attack-paths.md) use.
Delegation hands authority on. A credential widens it. Content steers the agent it
reaches. An access continues only under an actor acting for the current principal. A
step that no rule explains is not taken, and it is counted in `refused_steps`.

Every seed is searched twice:

- **Structural view:** every relationship.
- **Uncontained view:** only the relationships where no control was observed to hold.
  An edge is held when it has guards and every one of them is `PASS`.

| Exposure | Meaning |
|---|---|
| `EXPOSED` | the uncontained view reaches the target; its route is given, with the failed or undecided controls on it |
| `CONTAINED` | only the structural view reaches it, and the uncontained search finished; the **frontier** lists the held edges on the structural route |
| `CONTAINMENT_UNKNOWN` | only the structural view reaches it, and the uncontained search was cut by a bound, so containment was not shown |

The search goes over walks, not simple paths. Every authority state reachable within
`--max-depth` is found, so `CONTAINED` is never claimed while an uncontained walk
exists within the bounds. The **remediation delta** gives, for each failed edge on an
exposed route, how many exposed targets its seeds would no longer reach if that edge's
controls held.

## Outputs

| File | Contents |
|---|---|
| `blast-radius.json` | per seed, both searches' records, every target with exposure and routes, and impact counts per view (targets by class, tenants reached, trust boundaries crossed, privileged credentials acquired); then totals, the frontier and the remediation delta |
| `graph.mmd`, `graph.dot` | the reached subgraph, with `[seed …]`, `[exposed]`, `[contained]` and `[unknown]` tags and `held` / `FAIL <property>` edge labels, all written as text |
| `summary.md` | the counts, the routes per seed (50 at most, the rest in the JSON), the frontier, the delta, the search record, and what the result does not claim |

The same inputs give byte-identical files, and no output carries a time. Every file is
checked for credential-shaped values before the first one is written.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No target is `EXPOSED`, and nothing was truncated |
| 1 | Internal error |
| 2 | A target is `EXPOSED`, or a search was truncated |
| 3 | Refusal: an invalid graph or scenario, an unknown, ambiguous or unfitting seed, or a bound out of range. Nothing is written |

## What a result does not claim

- **`CONTAINED` does not mean "safe".** It means only that every route to the target
  within `--max-depth` crosses a control that was observed to hold in the runs you
  supplied.
- **Unreached is not unreachable.** A relationship that no artifact and no model line
  states is not in the graph.
- **No reach was executed.**
- **The remediation delta is not a ranking of risk.** It counts what one edge's
  controls would contain if they held.
