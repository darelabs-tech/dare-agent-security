# DARE Agent Security

> Deterministic adversarial validation and security conformance testing for AI agents and MCP systems.

DARE Agent Security is an open-source DARE Labs project focused on testing whether agentic systems behave safely at authorization and execution boundaries.

The project is intentionally **evidence-first**: security conclusions should be backed by reproducible test vectors, deterministic expectations, observed behavior, and machine-readable evidence rather than by an LLM acting as the final security judge.

## Initial scope

The first releases will focus on a narrow, testable surface:

- MCP server and tool discovery;
- security baseline generation;
- authorization and policy validation;
- AuthZEN / COAZ-MCP conformance vectors;
- mappings to OWASP Agentic Security guidance;
- controlled adversarial tests for authorized environments;
- basic agent/tool/resource attack-path modeling;
- machine-readable evidence suitable for CI/CD.

Planned CLI direction:

```text
dare-agent-security discover
dare-agent-security validate
dare-agent-security attack
dare-agent-security graph
dare-agent-security prove
```

The command surface is not stable yet.

## Design principle

**Deterministic boundaries for nondeterministic AI systems.**

A test should be able to express:

```text
Expected: DENY or RE-EVALUATE
Observed: ALLOW
Result:   FAIL
Evidence: request + policy + trace + outcome
```

This makes the result reproducible and reviewable by security teams.

## Standards-first approach

DARE Agent Security aims to implement and test existing security standards and community taxonomies rather than create an incompatible proprietary taxonomy.

Initial areas of interest include:

- Model Context Protocol (MCP);
- OpenID AuthZEN;
- COAZ and COAZ-MCP;
- OWASP Agentic Security guidance;
- relevant OAuth/OIDC authorization requirements;
- relevant CWE mappings where appropriate.

Standards mappings will evolve with the upstream specifications.

## Open-source boundary

This repository contains the community-facing security engine, reusable test vectors, conformance logic, generic adapters, evidence schemas, CLI integrations, CI/CD integrations, and synthetic test labs that are intentionally released as open source.

It does **not** imply that all DARE Labs or Dewtech security technology is open source. Enterprise control planes, proprietary datasets, customer-specific integrations, private findings, historical intelligence, advanced attack-graph analytics, managed continuous validation, and other commercial components may remain proprietary and are not licensed by this repository.

No customer source code, credentials, internal endpoints, non-public architecture, findings, or confidential test data should ever be committed here.

## Responsible and authorized use

DARE Agent Security is intended for defensive validation, research, conformance testing, and security testing of systems you own or are explicitly authorized to assess.

Do not use the project to access, disrupt, exploit, or test third-party systems without explicit authorization.

Active tests should start in local, sandbox, or staging environments and must respect the target's approved scope, rules of engagement, rate limits, data-handling rules, and kill-switch procedures.

## Project status

**Stage:** Bootstrap / pre-alpha — Cycle 001 evidence contract in progress

The public v1 evidence schema lives at [`schemas/evidence/v1/evidence.schema.json`](schemas/evidence/v1/evidence.schema.json). Synthetic fixtures are in [`examples/evidence/`](examples/evidence/). The Rust kernel is `crates/dare-security-evidence` ([README](crates/dare-security-evidence/README.md)). Validate the JSON contract locally from the committed schema; do not fetch `$id` from the network.

Current priorities:

1. define the security evidence model;
2. implement MCP discovery and baseline validation;
3. implement deterministic COAZ-MCP/AuthZEN conformance vectors;
4. build a safe reference lab with intentionally vulnerable MCP examples;
5. publish the first reproducible benchmark methodology;
6. integrate with CI through a GitHub Action.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions should be small, reproducible, standards-referenced where applicable, and backed by tests.

Security vulnerabilities in this project must **not** be reported through a public issue. See [SECURITY.md](SECURITY.md).

## Trademarks

The Apache-2.0 license covers the software in this repository. It does not grant rights to DARE Labs names, logos, or trademarks. See [TRADEMARKS.md](TRADEMARKS.md).

## License

Licensed under the [Apache License 2.0](LICENSE).

Copyright 2026 DARE Labs and contributors.
