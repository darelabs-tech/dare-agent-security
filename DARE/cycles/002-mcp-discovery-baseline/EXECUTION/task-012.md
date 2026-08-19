# task-012 — Documentation, CI, compatibility matrix and final proof

> Status: DONE
> Depends on: task-011
> Complexity: MEDIUM

## Objective
Close Cycle 002 with enforceable CI, operator documentation and an auditable proof against the approved Design.

## Required deliverables
- root README quick start for `discover`;
- discovery crate README;
- Inventory v1 schema/versioning documentation;
- passive method policy documentation;
- synthetic lab instructions;
- MCP compatibility matrix with current and selected legacy revision;
- CI coverage for fmt/clippy/tests, schema fixtures, passive method trace and secret canaries;
- dependency audit/disposition for HIGH/CRITICAL findings.

## Final proof
Produce a cycle verification report mapping every Design acceptance criterion to concrete file/test/command evidence and a PASS/FAIL result.

Minimum gates:
```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
plus Inventory v1 offline validation, E2E passive trace and secret-redaction proof.

## Invariants
Do not weaken tests or security rules to achieve green CI. Any architectural deviation discovered here returns to DARE Review instead of being silently normalized.

## DONE when
All approved Design acceptance criteria are evidenced, all required gates pass, unresolved risks/deviations are documented, and the cycle is ready for human final review/merge.

## Execution result

- Status: DONE
- Proof: `DARE/cycles/002-mcp-discovery-baseline/PROOF.md`
- Files:
  - `README.md`
  - `crates/dare-mcp-discovery/README.md`
  - `docs/inventory-v1.md`
  - `docs/passive-policy.md`
  - `docs/synthetic-lab.md`
  - `docs/mcp-compatibility.md`
  - `.github/workflows/ci.yml`
  - `crates/dare-agent-security-cli/tests/discover_cli.rs` (`cycle_002_operator_docs_exist`)
  - `crates/dare-security-evidence/tests/e2e_proof.rs` (CI now requires `cargo audit`)
- Gates: `cargo fmt --all --check` PASS; `cargo clippy --workspace --all-targets -- -D warnings` PASS; `cargo test --workspace` PASS; `cargo audit` PASS (exit 0, no HIGH/CRITICAL)
- Did not run `dare execute --complete`
