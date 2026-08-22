# DARE Agent Security

**Deterministic adversarial validation and security conformance testing for AI
agents and MCP systems.**

DARE Agent Security is an open-source DARE Labs project focused on testing
whether agentic systems behave safely at authorization and execution
boundaries. It is intentionally **evidence-first**: security conclusions are
backed by reproducible test vectors, deterministic expectations, observed
behavior, and machine-readable evidence — not by an LLM acting as the final
security judge.

## What does it protect?

The current scope focuses on MCP (Model Context Protocol) servers and tools:

- passive MCP server and tool discovery;
- authorization and policy validation (AuthZEN / COAZ-MCP conformance vectors);
- deterministic bounded agent/tool/resource attack-path modeling;
- controlled, ROE-gated adversarial tests for authorized environments;
- continuous revalidation with fail-closed drift gates;
- machine-readable evidence suitable for CI/CD.

## Design principle

**Deterministic boundaries for nondeterministic AI systems.** A test should be
able to express:

```text
Expected: DENY or RE-EVALUATE
Observed: ALLOW
Result:   FAIL
Evidence: request + policy + trace + outcome
```

This makes every result reproducible and reviewable by a security team.

## What data leaves my environment?

By default: none required. Telemetry is off by default and is refused
entirely under `--confidential` / `--offline` (see
[Privacy](privacy/confidential-mode.md)). Assessments run locally and write
evidence and reports under `.dare-security/runs/` on disk.

## Where to go next

```text
Install
  → Quickstart
    → First Assessment
```

- [Installation](getting-started/installation.md) — get the binary onto your machine.
- [Quickstart](getting-started/quickstart.md) — run your first `doctor` / `assess` / `report` cycle.
- [First Assessment](getting-started/first-assessment.md) — the full vulnerable → fix → reassess journey.

## Responsible and authorized use

DARE Agent Security is intended for defensive validation, research,
conformance testing, and security testing of systems you own or are
explicitly authorized to assess. Do not use it to access, disrupt, exploit,
or test third-party systems without explicit authorization. See the
project's [Responsible Disclosure](https://github.com/darelabs-tech/dare-agent-security/blob/main/docs/responsible-disclosure.md)
policy for reporting vulnerabilities in the tool itself.

## Open-source boundary

This site documents the community-facing security engine, reusable test
vectors, conformance logic, generic adapters, evidence schemas, and CI/CD
integrations released as open source under Apache-2.0. It does not imply
that all DARE Labs security technology is open source — enterprise control
planes and managed continuous validation may remain proprietary.
