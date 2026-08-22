# First Assessment

This walks through the full acceptance journey: a demo target that fails,
applying the documented remediation, and confirming it passes on re-assessment.

The demo fixtures (`examples/vulnerable-mcp`, `examples/secure-mcp`,
`examples/agentic-demo`) live inside the source repository, not inside a
release archive. Clone the repo to follow along locally, or point `assess` at
your own MCP project instead once you're comfortable with the flow:

```bash
git clone https://github.com/darelabs-tech/dare-agent-security.git
cd dare-agent-security
```

## 1. Assess the vulnerable demo (expect a failing gate)

```bash
dare-agent-security assess examples/vulnerable-mcp --offline --confidential
```

This exits non-zero — the assessment gate is `FAIL` (or `PARTIAL` /
`BLOCKED` / `INCONCLUSIVE`, depending on the finding). That is expected: the
fixture is intentionally misconfigured.

```bash
dare-agent-security report --path examples/vulnerable-mcp
```

Open the executive report (`.dare-security/runs/<run-id>/reports/executive.html`)
to see the finding in plain language, and the technical report for full
evidence.

## 2. Apply the documented remediation

Read `examples/vulnerable-mcp/REMEDIATION.md` and apply the described fix.

## 3. Re-assess the secure demo (expect a passing gate)

```bash
dare-agent-security assess examples/secure-mcp --offline
dare-agent-security report --path examples/secure-mcp
```

This exits `0` — the gate is `PASS`. You've now seen the full
`FAIL → fix → PASS` loop that the [Product Validation Program](https://github.com/darelabs-tech/dare-agent-security/blob/main/DARE/PRODUCT-VALIDATION-PROGRAM.md)
treats as the core signal that DARE is doing its job.

## 4. Try the integrated workflow demo

```bash
dare-agent-security assess examples/agentic-demo --offline --confidential
```

## What just happened

Each `assess` run wrote a versioned run directory:

```text
.dare-security/runs/<run-id>/
  summary.json
  findings.json
  coverage.json
  attack-graph.json
  validation.json
  drift.json
  evidence/
  reports/executive.html
  reports/technical.html
```

Nothing left your machine. See [Confidential Mode](../privacy/confidential-mode.md)
and [Generated Artifacts](../reference/artifacts.md) for details.

## Next steps

- Point `assess` at a real MCP project you own or are authorized to test.
- Read [Assessment Profiles](../assessments/profiles.md) to understand what
  `mcp-security-baseline` actually checks.
- Wire the [GitHub Action](../ci/github-actions.md) into your CI pipeline.
