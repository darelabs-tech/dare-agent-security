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

**Stage:** v1.0 release readiness (Cycle 011) — product UX over Cycles 001–010 core (feature freeze)

### Product quick start

```bash
cargo run -p dare-agent-security -- init
cargo run -p dare-agent-security -- doctor
cargo run -p dare-agent-security -- assess examples/vulnerable-mcp --offline --confidential
cargo run -p dare-agent-security -- report --path examples/vulnerable-mcp
cargo run -p dare-agent-security -- assess examples/secure-mcp --offline
```

See [docs/quickstart.md](docs/quickstart.md) and [docs/product/v1-contract.md](docs/product/v1-contract.md). Power-user commands (`discover`, `validate *`, `ci`) remain available.

Cycle 001 shipped the protocol-neutral evidence kernel (`crates/dare-security-evidence`, schema at [`schemas/evidence/v1/evidence.schema.json`](schemas/evidence/v1/evidence.schema.json)). Cycle 002 adds `dare-agent-security discover`: passive inventory of an operator-supplied MCP target. Cycle 003 adds `validate coaz-integrity`: deterministic authorization-to-execution integrity vectors (built-in synthetic fixtures only). **Cycle 004** adds a repository-local GitHub Action (`action.yml`) that invokes the CLI with deterministic aggregate verdicts for CI — see [docs/ci-gate.md](docs/ci-gate.md). **Cycle 005** adds a synthetic MCP security lab and scenario corpus (`crates/dare-mcp-lab`, `labs/scenarios/`) — see [docs/mcp-security-lab.md](docs/mcp-security-lab.md). **Cycle 006** adds assessment profiles and coverage (`crates/dare-coverage`) — see [docs/assessment-coverage.md](docs/assessment-coverage.md). **Cycle 007** adds benchmark corpus methodology (`crates/dare-benchmark`) — see [docs/benchmark-methodology.md](docs/benchmark-methodology.md). **Cycle 008** adds deterministic bounded attack-graph analysis (`crates/dare-attack-graph`) — see [docs/attack-graph.md](docs/attack-graph.md). **Cycle 009** adds ROE-gated, budgeted, offline-first controlled validation (`crates/dare-adversarial`) — see [docs/adversarial-validation.md](docs/adversarial-validation.md). **Cycle 010** adds immutable snapshots, safe incremental planning, drift gates, and fail-closed fallback (`crates/dare-continuous`) — see [docs/continuous-validation.md](docs/continuous-validation.md). **Cycle 011** productizes the core (`crates/dare-product`: `init` / `assess` / `report` / `doctor`). Validate JSON contracts locally from committed schema files; do not fetch `$id` from the network.

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

### Validate coverage quick start

```bash
cargo run -p dare-agent-security -- validate coverage \
  --profile mcp-security-baseline \
  --facts fixtures/coverage/fixture-a-tools-static-roe.json \
  --output-dir .dare-agent-security/coverage \
  --json
```

This produces `coverage-report.json`. It does not replace discovery or integrity validation. See [docs/assessment-coverage.md](docs/assessment-coverage.md).

### Validate benchmark quick start

```bash
cargo run -p dare-agent-security -- validate benchmark \
  --corpus benchmark/corpus/pilot-methodology-v1/corpus-manifest.json \
  --output-dir .dare-agent-security/benchmark \
  --mode local-passive
```

Pilot corpus validates methodology (25–50 fixtures), not ecosystem prevalence. See [docs/benchmark-methodology.md](docs/benchmark-methodology.md).

### Validate attack-graph quick start

```bash
cargo run -p dare-agent-security -- validate attack-graph \
  --facts fixtures/attack-graph/safe-read.json \
  --output-dir .dare-agent-security/attack-graph
```

This produces canonical JSON plus bounded path, Mermaid, DOT, and summary artifacts. It performs analysis only and never executes an attack path. See [docs/attack-graph.md](docs/attack-graph.md).

### Validate adversarial quick start

```bash
cargo run -p dare-agent-security -- validate adversarial \
  --fixture fixtures/adversarial/confused-deputy.json \
  --mode local-synthetic \
  --output-dir .dare-agent-security/adversarial
```

The default mode is `plan-only`. Local synthetic mode is in-memory and offline. `authorized-dynamic` requires a valid ROE, and remote dynamic execution remains disabled in the MVP.

### Validate continuous quick start

```bash
cargo run -p dare-agent-security -- validate continuous \
  --fixture fixtures/continuous/unrelated-change.json \
  --mode plan-only \
  --output-dir .dare-agent-security/continuous
```

Continuous validation is offline and never grants `AUTHORIZED_DYNAMIC`; Cycle 009 ROE remains mandatory.

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
2. preserve Cycle 009 ROE controls and Cycle 010 fail-closed reuse semantics;
3. stabilize installation, diagnostics, reports, and compatibility for v1.0;
4. expand coverage and fixtures only from demonstrated operator needs;
5. honor the Cycle 010 core feature freeze before productization.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions should be small, reproducible, standards-referenced where applicable, and backed by tests.

Security vulnerabilities in this project must **not** be reported through a public issue. See [SECURITY.md](SECURITY.md).

## Trademarks

The Apache-2.0 license covers the software in this repository. It does not grant rights to DARE Labs names, logos, or trademarks. See [TRADEMARKS.md](TRADEMARKS.md).

## License

Licensed under the [Apache License 2.0](LICENSE).

Copyright 2026 DARE Labs and contributors.
