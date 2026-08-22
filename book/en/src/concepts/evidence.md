# Evidence

DARE Agent Security is **evidence-first**: every conclusion is backed by a
reproducible artifact, not by an LLM's opinion.

## The evidence contract

Every check — discovery, authorization-integrity validation, adversarial
tests, continuous revalidation — emits evidence conforming to a single,
protocol-neutral, versioned schema:
[`schemas/evidence/v1/evidence.schema.json`](https://github.com/darelabs-tech/dare-agent-security/blob/main/schemas/evidence/v1/evidence.schema.json).

An evidence record captures, at minimum:

```text
Expected: what the policy/spec says should happen
Observed: what actually happened
Result:   PASS | FAIL | INCONCLUSIVE
Evidence: request + policy + trace + outcome
```

This is what makes a finding reviewable by a human security team instead of
being a black-box verdict.

## Where evidence lives

For product assessments, evidence is written locally under:

```text
.dare-security/runs/<run-id>/evidence/
```

It is never uploaded anywhere by default — see [Confidential Mode](../privacy/confidential-mode.md).

## Verdicts you'll see

| Verdict | Meaning |
|---|---|
| `PASS` | The expectation held. |
| `FAIL` | The expectation did not hold — a real finding. |
| `INCONCLUSIVE` | The check could not reach a definitive verdict (e.g. target unreachable, ambiguous state). Treated as a failure by default (`fail-on-inconclusive`). |
| `BLOCKED` | The check was refused by a safety/scope boundary before it could run. |

## Why not "LLM as judge"

An LLM can help *explain* a finding in the executive report, but it never
decides PASS/FAIL. That decision comes from deterministic comparison against
an expected policy outcome, so the same input always produces the same
verdict.
