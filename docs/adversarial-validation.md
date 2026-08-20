# Controlled adversarial validation

Cycle 009 converts an approved attack-path hypothesis into the smallest deterministic proof that can run safely. It reuses Cycle 008 paths, Cycle 006 property IDs, and Cycle 001 verdicts; it is not an exploit or autonomous exploration framework.

## Modes

- `PLAN_ONLY` (default): validates schemas, bindings, preconditions, proof metadata, and authorization; executes zero operations.
- `SIMULATED`: evaluates the approved steps as dry runs and marks outcomes simulated.
- `LOCAL_SYNTHETIC`: evaluates deterministic in-memory fixture observations. The runner has no network adapter.
- `AUTHORIZED_DYNAMIC`: requires a valid, digest-bound ROE. The MVP accepts only `local_only: true` and executes the same synthetic local path. Remote dynamic execution is refused with `remote dynamic not enabled in MVP`.

Lab success never grants dynamic authorization.

## Rules of Engagement

Dynamic plans bind the ROE identifier and canonical SHA-256 digest. The gate checks target, environment, validity window, property category, capabilities, identities, synthetic data classes, state/egress permissions, and prohibited operations. Missing, expired, altered, mismatched, or remote-enabled ROE documents produce a safety refusal before any operation.

## Runtime boundaries

Vectors are JSON data. `shell`, `python`, `eval`, `callback`, and `script` fields are rejected recursively. Every step must exactly equal the step at the same index in the approved vector. Extra steps, argument changes, target substitution, and capability changes are denied; the runner never creates a stronger follow-up.

Preconditions fail closed. Canonical plan/vector/budget/ROE digests bind approvals. Supported proof classes are `READ_ONLY`, `SYNTHETIC_NOOP`, and `DRY_RUN`.

## Budgets and kill switch

The fixed budget limits operations, duration, state changes, bytes read/written, external egress, retries, and chain depth. The next step that would exceed a bound is not executed. Exhaustion produces `STOPPED`; bounds are never expanded.

The kill switch aborts on unexpected state, egress, target, identity, secrets, instability, evidence failure, or operator stop. Kill evidence is emitted before return. Operators should terminate the process for an emergency stop; no background worker or network session survives the process.

## CLI

```bash
cargo run -p dare-agent-security -- validate adversarial \
  --fixture fixtures/adversarial/confused-deputy.json \
  --mode local-synthetic \
  --output-dir .dare-agent-security/adversarial
```

`--plan` currently accepts the same self-contained JSON bundle as `--fixture`. `--mode authorized-dynamic` additionally requires `--roe PATH`.

Artifacts are `validation-result.json` and `evidence.json`. Exit codes: `0` pass/planned, `1` harness error, `2` blocked/stopped/killed/fail/inconclusive, `3` usage or safety refusal.

## Limitations

The MVP does not open sockets, call remote MCP targets, mutate real state, extract credentials, use customer data, recursively discover steps, or execute code embedded in vectors. Path reclassification emits a new revision digest and never changes Cycle 008 history.
