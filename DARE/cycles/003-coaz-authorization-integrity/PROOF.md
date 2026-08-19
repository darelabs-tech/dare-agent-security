# Cycle 003 — Acceptance proof matrix

> Generated: 2026-08-19 (task-012)
> Design: [`DESIGN.md`](DESIGN.md) §21 Acceptance criteria
> Human review checklist: [`DESIGN.md`](DESIGN.md) §22

This document maps every Design acceptance criterion to concrete file, test, and
command evidence. Reproduce the proof with the Ralph Loop at the bottom.

## Acceptance criteria

| # | Criterion | Evidence |
|---|---|---|
| 1 | All five vectors from issue #4/#603 implemented | [`vectors/coaz-mcp/authorization-integrity/v1/COAZ-INTEGRITY-001.json`](../../../vectors/coaz-mcp/authorization-integrity/v1/COAZ-INTEGRITY-001.json) … [`005`](../../../vectors/coaz-mcp/authorization-integrity/v1/COAZ-INTEGRITY-005.json); runner [`crates/dare-coaz-integrity/src/runner.rs`](../../../crates/dare-coaz-integrity/src/runner.rs) `BUILTIN_VECTOR_IDS` |
| 2 | Semantic-control vectors prove canonicalization is not raw-byte equality | [`COAZ-INTEGRITY-006.json`](../../../vectors/coaz-mcp/authorization-integrity/v1/COAZ-INTEGRITY-006.json), [`007`](../../../vectors/coaz-mcp/authorization-integrity/v1/COAZ-INTEGRITY-007.json); [`crates/dare-coaz-integrity/tests/canonical.rs`](../../../crates/dare-coaz-integrity/tests/canonical.rs); e2e control assertions in [`e2e_integrity.rs`](../../../crates/dare-coaz-integrity/tests/e2e_integrity.rs) |
| 3 | Mapped argument changes tested with declared synthetic mapping | [`COAZ-INTEGRITY-003.json`](../../../vectors/coaz-mcp/authorization-integrity/v1/COAZ-INTEGRITY-003.json) (`projector_fixture.id`: `declared-rental-quote`); [`projector_rental.rs`](../../../crates/dare-coaz-integrity/src/projector_rental.rs) |
| 4 | PASS and FAIL reference fixtures exist | [`examples/coaz-integrity/secure/result-pass-v1.json`](../../../examples/coaz-integrity/secure/result-pass-v1.json); [`examples/coaz-integrity/vulnerable/result-stale-permit-fail-v1.json`](../../../examples/coaz-integrity/vulnerable/result-stale-permit-fail-v1.json) |
| 5 | Each run emits versioned machine-readable vector result | [`schemas/vectors/coaz-integrity/v1/result.schema.json`](../../../schemas/vectors/coaz-integrity/v1/result.schema.json); CLI `--json` test [`validate_cli.rs`](../../../crates/dare-agent-security-cli/tests/validate_cli.rs) `single_fixture_json_stdout_is_only_json_object` |
| 6 | Each vector can emit valid Cycle 001 evidence | [`crates/dare-coaz-integrity/src/evidence_bridge.rs`](../../../crates/dare-coaz-integrity/src/evidence_bridge.rs); [`examples/coaz-integrity/evidence/`](../../../examples/coaz-integrity/evidence/); CLI test `evidence_dir_writes_result_and_evidence_artifacts` |
| 7 | Stale-permit forwarding provable from synthetic trace | [`e2e_integrity.rs`](../../../crates/dare-coaz-integrity/tests/e2e_integrity.rs) `assert_vulnerable_stale_permit_proof`; CLI [`e2e_coaz_integrity.rs`](../../../crates/dare-agent-security-cli/tests/e2e_coaz_integrity.rs); vulnerable fixture above |
| 8 | No raw credential or customer data committed | [`secret_safety.rs`](../../../crates/dare-coaz-integrity/src/secret_safety.rs); canary tests in e2e suites; synthetic `*-synthetic-*` identifiers in vectors |
| 9 | Docs distinguish normative COAZ-MCP from unresolved #603 proposal | [`docs/coaz-integrity-policy.md`](../../../docs/coaz-integrity-policy.md); [`docs/coaz-integrity-standards.md`](../../../docs/coaz-integrity-standards.md); standards fixture `OPEN_PROPOSAL` entry |
| 10 | Workspace format/lint/test gates pass | [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml); Ralph Loop below |

## Human review checklist (Design §22)

| Item | Status | Evidence |
|---|---|---|
| Issue #603 remains exact research target | ✓ | Standards snapshot `upstream_issue`: `openid/authzen#603`; upstream package [`upstream/README.md`](upstream/README.md) |
| Cycle 003 does not expand into full COAZ implementation | ✓ | Scope in [`DESIGN.md`](DESIGN.md) §5 Out of scope; in-process fixtures only |
| Semantic binding based on mapping-relevant values | ✓ | [`binding.rs`](../../../crates/dare-coaz-integrity/src/binding.rs); vectors 006–007 positive controls |
| Unchanged/irrelevant changes have positive control vectors | ✓ | COAZ-INTEGRITY-006, 007 |
| Vulnerable reference mode is synthetic and non-destructive | ✓ | [`sink.rs`](../../../crates/dare-coaz-integrity/src/sink.rs) `VULNERABLE_REUSE_PERMIT`; CLI refuses arbitrary targets |
| Generic evidence contract remains MCP/COAZ-agnostic | ✓ | [`schemas/evidence/v1/evidence.schema.json`](../../../schemas/evidence/v1/evidence.schema.json) unchanged; extension key `dare.coaz.integrity` |
| Standards status represented as Draft/Open Issue | ✓ | [`cycle003-standards-v1.json`](../../../examples/coaz-integrity/cycle003-standards-v1.json) |
| No production or customer endpoint in scope | ✓ | Built-in vectors only; safety docs [`coaz-integrity-policy.md`](../../../docs/coaz-integrity-policy.md) |
| Cycle 002 interfaces reused rather than forked | ✓ | [`IMPLEMENTATION-NOTES.md`](IMPLEMENTATION-NOTES.md) reconciliation table |

## CI gates (Blueprint §21)

| Gate | Evidence |
|---|---|
| `cargo fmt --all --check` | `.github/workflows/ci.yml` Format step |
| `cargo clippy --workspace --all-targets -- -D warnings` | CI Clippy step |
| `cargo test --workspace` | CI Test step |
| Offline vector/result schema validation | `vector_result_contract.rs`, `vectors.rs` |
| Secret canary checks | `e2e_integrity.rs`, `e2e_coaz_integrity.rs` |
| All seven vectors secure PASS | `validate_cli.rs` `all_fixtures_secure_pass_exits_zero` |
| Vulnerable FAIL matrix 002–005 | `e2e_integrity.rs`, `e2e_coaz_integrity.rs` |
| Standards snapshot present | `standards_snapshot.rs` |
| No-network harness (in-process PDP/sink) | PDP/sink modules; no socket usage in `dare-coaz-integrity` tests |
| `cargo audit` | CI Audit step |

## Ralph Loop (reproduce proof)

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
cargo run -p dare-agent-security -- validate coaz-integrity --all
cargo run -p dare-agent-security -- validate coaz-integrity --all --reference-mode vulnerable
```

Expected: first four commands exit 0; secure `--all` exits 0; vulnerable `--all`
exits 2 (intentional FAIL proof).

## Upstream contribution

Neutral materials for human-reviewed OpenID AuthZEN discussion:
[`upstream/`](upstream/)

Do not automatically open an upstream PR or claim IPR approval.
