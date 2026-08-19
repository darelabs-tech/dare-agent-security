# task-012 — Documentation, CI, Final Proof and Upstream Contribution Package

> Status: **DONE**
> Depends on: task-011

## Objective

Finish Cycle 003 with reproducible documentation, CI gates, an acceptance proof and a neutral standards-contribution package.

## Documentation

Explain:

- issue #603 authorization-to-execution problem;
- current COAZ-MCP PEP flow and Mapping Integrity context;
- open/proposed status of the additional binding property;
- semantic equality versus byte equality;
- vector 001–007 matrix;
- secure/vulnerable traces;
- CLI usage;
- result/evidence schemas;
- safety boundary;
- standards version snapshot and MCP/COAZ lifecycle version-skew note.

## CI

Require:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Plus offline schema validation, all secure vector runs, expected vulnerable FAIL runs, secret-canary checks and no-network test-harness assertion where feasible.

## Final proof

Produce an acceptance matrix mapping every Design criterion to concrete file/test/command evidence.

## Upstream package

Prepare neutral, synthetic materials suitable for human-reviewed discussion in OpenID AuthZEN:

```text
vector id
authorization input semantics
mutation
expected enforcement
reference secure trace
reference vulnerable trace
```

Do not automatically open an upstream PR or claim IPR approval.

## DONE when

Cycle 003 has deterministic proof, documentation and an upstream-ready artifact set with no customer/private data.
