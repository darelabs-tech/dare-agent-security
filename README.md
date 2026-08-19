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

**Stage:** Pre-alpha — Cycle 002 passive MCP discovery and Cycle 003 COAZ integrity vectors are usable against synthetic fixtures

Cycle 001 shipped the protocol-neutral evidence kernel (`crates/dare-security-evidence`, schema at [`schemas/evidence/v1/evidence.schema.json`](schemas/evidence/v1/evidence.schema.json)). Cycle 002 adds `dare-agent-security discover`: a passive inventory of an operator-supplied MCP target. Cycle 003 adds `validate coaz-integrity`: deterministic authorization-to-execution integrity vectors for COAZ-MCP (built-in synthetic fixtures only). Validate JSON contracts locally from committed schema files; do not fetch `$id` from the network.

### Discover quick start

Build the synthetic lab, then scan it over stdio. The scanner never interpolates a shell; the program after `--` is `argv[0]`.

```bash
cargo build -p synthetic-mcp
cargo run -p dare-agent-security -- discover --stdio -- target/debug/synthetic-mcp
cargo run -p dare-agent-security -- discover --stdio --json -- target/debug/synthetic-mcp
```

Human mode writes a baseline summary to stdout. `--json` writes one Inventory v1 object to stdout (diagnostics on stderr). See [docs/synthetic-lab.md](docs/synthetic-lab.md) for Streamable HTTP loopback and [crates/dare-mcp-discovery/README.md](crates/dare-mcp-discovery/README.md) for crate architecture.

### Validate coaz-integrity quick start

Run all seven built-in authorization-integrity vectors (secure reference PEP, synthetic fixtures only):

```bash
cargo build -p dare-agent-security
cargo run -p dare-agent-security -- validate coaz-integrity --all
cargo run -p dare-agent-security -- validate coaz-integrity --fixture COAZ-INTEGRITY-003 --json
```

Secure mode expects verdict `PASS` (exit 0). To prove stale-permit forwarding on mutation vectors, use the intentionally vulnerable reference mode (exit 2):

```bash
cargo run -p dare-agent-security -- validate coaz-integrity --all --reference-mode vulnerable
```

See [docs/coaz-integrity.md](docs/coaz-integrity.md) for the vector matrix, standards snapshot, and upstream contribution package.

### Exit codes

`discover` uses stable numeric codes documented in [`crates/dare-agent-security-cli/EXIT.md`](crates/dare-agent-security-cli/EXIT.md) and in `--help`:

| Code | Meaning |
|------|---------|
| 0 | Complete success |
| 1 | Scanner execution error |
| 2 | Partial or inconclusive result |
| 3 | Unsupported or refused target |

### Passive boundary

Default discovery is **list-only**. It may send `server/discover` (MCP `2026-07-28`) or the explicit legacy `initialize` / `notifications/initialized` handshake (MCP `2024-11-05`), plus `tools/list`, `resources/list`, `resources/templates/list`, and `prompts/list`. It does **not** invoke `tools/call`, `resources/read`, or `prompts/get`. See [docs/passive-policy.md](docs/passive-policy.md).

### No credential flags

There are no `--token`, `--password`, or `--credential` flags. HTTP targets are HTTPS-only; credentials in the URL are refused. Do not put secrets on the command line.

Current priorities:

1. keep the Cycle 001 evidence contract stable;
2. finish human review/merge of Cycle 002 discovery;
3. human review of Cycle 003 COAZ authorization-integrity vectors and upstream package;
4. publish the first reproducible benchmark methodology;
5. integrate with CI through a GitHub Action for authorized environments.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions should be small, reproducible, standards-referenced where applicable, and backed by tests.

Security vulnerabilities in this project must **not** be reported through a public issue. See [SECURITY.md](SECURITY.md).

## Trademarks

The Apache-2.0 license covers the software in this repository. It does not grant rights to DARE Labs names, logos, or trademarks. See [TRADEMARKS.md](TRADEMARKS.md).

## License

Licensed under the [Apache License 2.0](LICENSE).

Copyright 2026 DARE Labs and contributors.
