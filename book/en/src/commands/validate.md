# `validate`

Power-user command group. Offline, deterministic validation harnesses — each
subcommand is what the product `assess` command orchestrates under the hood.

```bash
dare-agent-security validate <SUBCOMMAND> [OPTIONS]
```

## `validate coaz-integrity`

Built-in COAZ authorization-to-execution integrity vectors (Cycle 003,
synthetic fixtures only).

```bash
dare-agent-security validate coaz-integrity --all
dare-agent-security validate coaz-integrity --fixture COAZ-INTEGRITY-003 --json
dare-agent-security validate coaz-integrity --all --reference-mode vulnerable
```

`--all` / `--fixture <ID>` are mutually exclusive. `--reference-mode
vulnerable` proves stale-permit forwarding on mutation vectors using the
intentionally vulnerable reference PEP — it never accepts arbitrary URL/stdio
targets. See [`docs/coaz-integrity.md`](https://github.com/darelabs-tech/dare-agent-security/blob/main/docs/coaz-integrity.md).

## `validate coverage`

Evaluate an assessment profile against typed facts (Cycle 006). Does not
replace `discover` or `validate coaz-integrity`.

```bash
dare-agent-security validate coverage \
  --profile mcp-security-baseline \
  --facts fixtures/coverage/fixture-a-tools-static-roe.json \
  --output-dir .dare-agent-security/coverage \
  --json
```

`--profile` accepts a built-in profile id or a path to a profile JSON.
`--min-required-coverage` (0.0–1.0) and `--fail-on-required-blocked` gate the
exit code. See [Assessment Coverage](../concepts/assessment-coverage.md).

## `validate benchmark`

Offline benchmark corpus methodology runner (Cycle 007).

```bash
dare-agent-security validate benchmark \
  --corpus benchmark/corpus/pilot-methodology-v1/corpus-manifest.json \
  --output-dir .dare-agent-security/benchmark \
  --mode local-passive
```

The pilot corpus validates *methodology*, not ecosystem prevalence.
`AUTHORIZED_DYNAMIC` mode requires `--authorized-dynamic-roe` and is refused
without it.

## `validate attack-graph`

Build and validate a deterministic bounded Agent Attack Graph (Cycle 008).

```bash
dare-agent-security validate attack-graph \
  --facts fixtures/attack-graph/safe-read.json \
  --output-dir .dare-agent-security/attack-graph
```

`--max-depth` (default 8, hard limit 64) and `--max-paths` (default 64, hard
limit 10000) bound the analysis. Analysis only — no attack path is executed.
See [Attack Graph](../concepts/attack-graph.md).

## `validate adversarial`

Controlled, offline-first adversarial validation (Cycle 009).

```bash
dare-agent-security validate adversarial \
  --fixture fixtures/adversarial/confused-deputy.json \
  --mode local-synthetic \
  --output-dir .dare-agent-security/adversarial
```

Default mode is `plan-only`. `local-synthetic` is in-memory and offline.
`authorized-dynamic` requires a valid ROE; remote dynamic execution remains
disabled in the MVP. See [Validation Modes](../concepts/validation.md) and
[Adversarial Validation](../assessments/adversarial.md).

## `validate continuous`

Plan deterministic continuous security revalidation (Cycle 010).

```bash
dare-agent-security validate continuous \
  --fixture fixtures/continuous/unrelated-change.json \
  --mode plan-only \
  --output-dir .dare-agent-security/continuous
```

Offline and never grants `AUTHORIZED_DYNAMIC`; the Cycle 009 ROE requirement
still applies. See [Continuous Validation](../assessments/continuous.md).

## `validate identity-security`

Run bounded local identity, privilege and delegation validation (Cycle 015).

```bash
dare-agent-security validate identity-security   --scenario IDENTITY-LAB-001   --mode simulated   --output-dir .dare-agent-security/identity-security
```

Modes are `replay`, `simulated` and `local-synthetic`; all three are local and
offline. There is no `--url`, `--endpoint`, `--issuer`, `--jwks`, `--token`,
`--bearer`, `--client-secret`, `--api-key`, `--pdp-url`, `--authzen-url`,
`--remote` or `--command` flag, and no credential is read from the environment.

Operations are observed and never dispatched: no identity provider,
authorization server or resource is contacted, no token is parsed, and no real
tenant data is touched to demonstrate a boundary crossing. See
[Identity, Privilege and Delegation Validation](../concepts/identity-security.md).

## Exit codes

Each subcommand has its own table — see [Exit Codes](../reference/exit-codes.md).
