# Synthetic MCP Security Lab (Cycle 005)

Deterministic scenario corpus with **secure** and **vulnerable** variants for known security properties.

## Layout

```text
labs/scenarios/MCP-LAB-NNN/scenario.json
schemas/lab/v1/scenario.schema.json
crates/dare-mcp-lab/   # manifest loader, lab framework, thin runner
```

## Corpus (MCP-LAB-001..010)

| ID | Family | Property |
|----|--------|----------|
| 001 | passive-boundary | Passive discovery never dispatches active ops |
| 002 | authorization-presence | Authn ≠ per-tool authz |
| 003 | confused-deputy | Principal/agent/service identity binding |
| 004 | authorization-integrity | Tool name mutation (via COAZ-INTEGRITY-002) |
| 005 | authorization-integrity | Argument mutation (via COAZ-INTEGRITY-003) |
| 006 | authorization-integrity | Trusted-context mutation (via COAZ-INTEGRITY-005) |
| 007 | mcp-routing | Header/body semantic divergence |
| 008 | modern-authorization | Issuer validation failure |
| 009 | modern-authorization | Credential issuer reuse |
| 010 | mrtr | MRTR authorization mutation |

Every scenario declares:

```text
secure     => expected PASS
vulnerable => expected FAIL
```

Assertion semantics (mandatory):

```text
expected FAIL + observed FAIL = scenario assertion PASS
```

## Run locally

```bash
cargo test -p dare-mcp-lab
cargo test -p dare-mcp-lab --test corpus_scenarios
```

## Safety

- `external_network: false`
- `real_credentials: false`
- `destructive: false`
- Local `lab://` endpoints only

## Engine reuse

| Scenario | Engine |
|----------|--------|
| 004–006 | `dare-coaz-integrity` (secure vs vulnerable reference PEP) |
| 001–003, 007–010 | Synthetic property probes emitting Cycle 001 evidence |

No second evidence / CI / integrity model is introduced.

## Limitations

- Not a prevalence study or production coverage claim
- Not a Marketplace release
- Probes for non-integrity families are synthetic oracles pending deeper MCP surface coverage
