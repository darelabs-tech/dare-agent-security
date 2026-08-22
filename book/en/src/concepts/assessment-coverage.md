# Assessment Coverage

Coverage answers a different question than a pass/fail verdict: **how much of
what should have been checked was actually checked?**

## Security properties

A profile (e.g. `mcp-security-baseline`) lists a set of security properties
drawn from a versioned registry
([`schemas/coverage/v1/registry.json`](https://github.com/darelabs-tech/dare-agent-security/blob/main/schemas/coverage/v1/registry.json)).
Each property is marked `REQUIRED` or optional for that profile.

## Property status

| Status | Meaning |
|---|---|
| `PASS` | The property was evaluated and held. |
| `FAIL` | The property was evaluated and did not hold. |
| `INCONCLUSIVE` | The property could not be evaluated definitively. |
| `ERROR` | Evaluation itself failed (harness error, not a security finding). |
| `BLOCKED` | The property could not be evaluated because a prerequisite was blocked or out of scope. |

## Coverage gate

`validate coverage` (and the product `assess` command, which orchestrates it)
can fail the run on two independent conditions:

- **minimum required coverage** — the ratio of evaluated `REQUIRED`
  properties falls below a threshold;
- **required-blocked policy** — any `REQUIRED` property landed in `BLOCKED`.

This prevents a report from looking "clean" simply because most checks were
skipped rather than passed.

## Where it's reported

The report includes an Assessment Coverage section that lists, per property,
its status and a link to the underlying evidence — see
[`coverage-report.json`](../reference/artifacts.md). Read this section
*before* trusting a PASS: coverage tells you what the PASS actually covers.
