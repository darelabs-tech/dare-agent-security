# Cycle 003 — Implementation Notes (task-001 reconciliation)

> Generated: 2026-08-19
> Branch: `agent/cycle-003-coaz-authorization-integrity`
> Baseline: Cycle 001 + Cycle 002 merged (`f290a24`)

This document records the actual merged repository integration points selected for tasks 002–012. It supersedes planning placeholders where Cycle 002 names already match production layout.

## Merged workspace layout (confirmed)

```text
crates/dare-security-evidence/     # Cycle 001 — dependency leaf
crates/dare-mcp-discovery/         # Cycle 002 passive discovery library
crates/dare-coaz-integrity/        # Cycle 003 — NEW (bootstrapped task-001)
crates/dare-agent-security-cli/    # bin dare-agent-security
labs/synthetic-mcp/                # synthetic MCP lab (extend, do not fork)
```

No duplicate discovery/CLI/lab crates were created.

## Dependency direction (enforced)

```text
dare-agent-security-cli
        |
        +--> dare-mcp-discovery ----> dare-security-evidence
        |
        +--> dare-coaz-integrity ---> dare-security-evidence
```

- `dare-coaz-integrity` MUST NOT be referenced from `dare-mcp-discovery` or `dare-security-evidence`.
- CLI gains `dare-coaz-integrity` in **task-010** only.

## Cycle 002 surfaces reused vs not reused

| Need | Merged source | Cycle 003 action |
|------|---------------|------------------|
| Secret redaction / safe errors | `dare_mcp_discovery::sanitize` | Reuse in result redaction (task-007+) |
| Evidence emission pattern | `dare_mcp_discovery::evidence_bridge` | Mirror in `dare-coaz-integrity` bridge (task-009) |
| MCP wire revision constant | `CURRENT_WIRE_REVISION` (`2026-07-28`) | Reference in vector metadata; vectors scope to `tools/call` only |
| Passive discovery inventory | `DiscoveryInventory` | **Not** reused — integrity uses separate vector/result contracts (task-002) |
| `tools/call` operation model | *not present* | **New** `McpOperation` in `dare-coaz-integrity` (task-003+) |
| Synthetic lab | `labs/synthetic-mcp` | Extend with integrity sink/trace hooks (task-007/008) |
| CLI structure | `crates/dare-agent-security-cli/src/{args,main,exit_code,output}.rs` | Add `validate coaz-integrity` subcommand tree (task-010) |

## Standards snapshot (machine-readable)

- Rust: `dare_coaz_integrity::cycle003_standards_snapshot()`
- Fixture: `examples/coaz-integrity/cycle003-standards-v1.json`
- Test: `crates/dare-coaz-integrity/tests/standards_snapshot.rs`

`openid/authzen#603` is recorded as **OPEN_PROPOSAL**, not normative COAZ-MCP text.

Executable scope is pinned to **`tools/call`** because COAZ-MCP Draft 1 lifecycle examples are not aligned with MCP `2026-07-28` transport behavior in this repository.

## Task path map (002–012)

| Task | Primary paths |
|------|----------------|
| 002 | `schemas/vectors/coaz-integrity/v1/`, `crates/dare-coaz-integrity/src/{vector,result}*.rs` |
| 003 | `crates/dare-coaz-integrity/src/canonical*.rs` |
| 004 | `crates/dare-coaz-integrity/src/binding*.rs` |
| 005 | `crates/dare-coaz-integrity/src/projector*.rs` |
| 006 | `crates/dare-coaz-integrity/src/pdp*.rs` |
| 007 | `crates/dare-coaz-integrity/src/{mutation,sink}*.rs`, extend `labs/synthetic-mcp` |
| 008 | `vectors/coaz-mcp/authorization-integrity/v1/COAZ-INTEGRITY-*.json`, runner |
| 009 | `crates/dare-coaz-integrity/src/evidence_bridge*.rs` |
| 010 | `crates/dare-agent-security-cli/src/validate*.rs`, CLI help/exit docs |
| 011 | `crates/dare-coaz-integrity/tests/e2e_*.rs`, CLI matrix tests |
| 012 | `docs/coaz-integrity*.md`, `PROOF.md`, CI audit step |

## CLI command target (task-010)

```bash
dare-agent-security validate coaz-integrity --all
dare-agent-security validate coaz-integrity --fixture COAZ-INTEGRITY-003
dare-agent-security validate coaz-integrity --all --json
dare-agent-security validate coaz-integrity --all --reference-mode vulnerable
```

Vulnerable mode: built-in synthetic fixtures only — no arbitrary URL/stdio targets.
