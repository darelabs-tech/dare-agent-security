# Agentic Security Registry 2026

DARE Agent Security includes an additive Agentic Security registry aligned to the OWASP Top 10 for Agentic Applications 2026. The registry converts broad risk families into narrow, machine-readable security properties that can be planned, measured and tied to evidence.

## What the registry is

A property states a testable security invariant. Every `AGENT.*` property has:

- a stable property ID;
- a closed risk-family identifier;
- a closed category;
- declarative applicability predicates;
- supported validation modes;
- an evidence requirement;
- local standards provenance;
- a maturity state.

The initial built-in profile is:

```text
agentic-security-baseline-2026
```

It deliberately selects a small representative set of properties. It is not a claim that every implementation pattern or every possible Agentic AI vulnerability is covered.

## Ten risk families

Cycle 012 represents the ten OWASP Agentic 2026 families:

```text
AGENT_GOAL_HIJACKING
TOOL_MISUSE_EXPLOITATION
IDENTITY_PRIVILEGE_ABUSE
AGENTIC_SUPPLY_CHAIN
UNEXPECTED_CODE_EXECUTION
MEMORY_CONTEXT_POISONING
INSECURE_INTER_AGENT_COMMUNICATION
CASCADING_FAILURES
HUMAN_AGENT_TRUST_EXPLOITATION
ROGUE_AGENTS
```

A standards mapping identifies why a property exists. It does not imply that a DARE property is textually or normatively equivalent to an entire OWASP risk family or control.

## Coverage is not a security verdict

Coverage answers **what was applicable and what was actually tested**. It does not answer, by itself, whether the system is secure.

The authoritative states remain:

- `APPLICABLE` — the property applies and awaits or has a test outcome;
- `NOT_APPLICABLE` — target shape makes the property irrelevant;
- `NOT_TESTED` — applicable/capable but no valid verdict exists;
- `OUT_OF_SCOPE` — excluded by approved assessment scope;
- `BLOCKED` — policy, Rules of Engagement or runtime constraints prevent the test.

Important fail-closed rules:

```text
APPLICABLE without verdict -> NOT_TESTED
BLOCKED never -> NOT_APPLICABLE
UNASSESSED / NOT_TESTED never -> SECURE
```

The Cycle 006 denominator is unchanged. `NOT_APPLICABLE` and `OUT_OF_SCOPE` remain excluded; `NOT_TESTED` and `BLOCKED` remain eligible coverage debt.

## Risk-family view

For the Agentic profile, the coverage CLI also writes:

```text
risk-family-coverage.json
```

This is an additive derived artifact. The stable v1 `coverage-report.json` contract is unchanged.

Family states are descriptive:

- `UNASSESSED` — zero tested eligible properties;
- `PARTIALLY_ASSESSED` — some but not all eligible properties tested;
- `ASSESSED` — all eligible properties in that family were tested.

`ASSESSED` describes coverage completion, not a PASS verdict and not a claim of security.

## Evidence and verdicts

A confirmed security result must remain evidence-backed. Agentic registry metadata can name acceptable evidence classes such as:

```text
STATIC
PASSIVE_RUNTIME
DYNAMIC_AUTHORIZED
SYNTHETIC
POLICY
TRACE
CONFIGURATION
```

Declaring an evidence class does not create an active testing engine. A later approved cycle must implement any new execution capability.

## Standards provenance and offline behavior

The standards manifest and crosswalk are committed as local data under:

```text
standards/agentic/2026/
```

Runtime registry, schema and provenance validation does not fetch standards from the network. This preserves confidential/offline assessments and makes results reproducible against a known snapshot.

## MCP compatibility

Existing `MCP.*` properties and `mcp-security-baseline` remain valid and are not renamed. The MCP-to-Agentic crosswalk is additive metadata only. It must never reinterpret an existing MCP property to make taxonomy cleaner.

## What Cycle 012 does not do

Cycle 012 does **not** add:

- an active prompt-injection engine;
- indirect prompt-injection execution;
- Garak or PyRIT orchestration;
- active RAG poisoning tests;
- active memory poisoning tests;
- active agent-to-agent attack execution;
- remote authorized dynamic execution;
- runtime enforcement or a SaaS control plane;
- autonomous exploit chains;
- an LLM acting as the final security judge.

Those capabilities require separate design, authorization and evidence semantics.

## Example

```bash
dare-agent-security validate coverage \
  --profile agentic-security-baseline-2026 \
  --facts facts.json \
  --output-dir .dare-agent-security/agentic
```

The result can honestly show a family as `UNASSESSED` or properties as `NOT_TESTED`. That is preferable to converting absence of evidence into a false PASS.
