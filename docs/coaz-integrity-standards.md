# COAZ integrity — standards snapshot

Cycle 003 pins the standards baseline in every vector and result artifact.
The canonical fixture is
[`examples/coaz-integrity/cycle003-standards-v1.json`](../examples/coaz-integrity/cycle003-standards-v1.json).

Rust API: `dare_coaz_integrity::cycle003_standards_snapshot()`.

## Referenced standards

| Family | Document | Version | Status |
|---|---|---|---|
| OpenID AuthZEN | Authorization API | 1.0 | NORMATIVE |
| COAZ | Framework | 1.0 Draft 1 | DRAFT |
| COAZ-MCP | Binding | 1.0 Draft 1 §9 PEP Behavior | DRAFT |
| COAZ-MCP | Binding | 1.0 Draft 1 §11.5 Mapping Integrity | DRAFT |
| OpenID AuthZEN | COAZ-MCP authorization-to-execution binding | proposal | OPEN_PROPOSAL (`openid/authzen#603`) |
| MCP | Model Context Protocol | 2026-07-28 (`tools/call`) | NORMATIVE |

## Open proposal vs normative text

Issue **#603** is the research target for Cycle 003. Vector metadata marks it
as `OPEN_PROPOSAL`. The repository **must not** claim the proposal is normative
COAZ-MCP text while the upstream issue remains unresolved.

Current COAZ-MCP Draft 1 already defines PEP mapping/evaluation/enforcement and
a Mapping Integrity security consideration. Issue #603 proposes an additional
authorization-to-execution binding clarification that Cycle 003 tests
deterministically.

## MCP / COAZ lifecycle version skew

COAZ-MCP Draft 1 lifecycle examples may not align with MCP `2026-07-28`
transport behavior in this repository. Cycle 003 therefore scopes executable
conformance to **`tools/call` only** and records this note in every vector:

```json
"executable_scope": {
  "mcp_method_scope": "tools/call",
  "lifecycle_skew_note": "COAZ-MCP Draft 1 lifecycle examples may differ from MCP 2026-07-28; Cycle 003 vectors execute only tools/call against the repository MCP revision."
}
```

Legacy lifecycle examples are **not** treated as authoritative for current MCP
transport in this harness.

## Validation

The standards snapshot is tested offline:

```bash
cargo test -p dare-coaz-integrity standards_snapshot
```

Test file: [`crates/dare-coaz-integrity/tests/standards_snapshot.rs`](../crates/dare-coaz-integrity/tests/standards_snapshot.rs)

When upstream documents change status (e.g. #603 accepted), update the fixture,
Rust snapshot in `crates/dare-coaz-integrity/src/standards.rs`, and re-run the
full workspace Ralph Loop.
