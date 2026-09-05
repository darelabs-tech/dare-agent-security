# Cycle 012 — Compatibility Baseline

> Task: `task-001`
> Status: **DONE**
> Recorded: 2026-09-03
> Baseline branch: `main`
> Baseline commit: `717aece1c75145f0d1048618afd95e98a36634ba`
> Product version: `1.0.0-rc1`

## 1. Public product contract frozen for Cycle 012

Cycle 012 must preserve the Cycle 011 v1 public surface:

```text
dare-agent-security init [PATH] [--force] [--name NAME] [--confidential]
dare-agent-security assess <PATH> [--confidential] [--offline] [--config PATH] [--run ID] [--json]
dare-agent-security report [--path PATH] [--run ID] [--refresh] [--json]
dare-agent-security doctor [PATH] [--json]
```

Power-user commands remain `discover`, `validate *`, and `ci`.

Canonical public-contract files:

- `docs/product/v1-contract.md`
- `schemas/product/v1/config.schema.json`
- `schemas/product/v1/summary.schema.json`
- `schemas/product/v1/findings.schema.json`
- `crates/dare-agent-security-cli/EXIT.md`
- `crates/dare-agent-security-cli/src/args.rs`

Cycle 012 may add metadata/profile values only in a backward-compatible way. It must not break existing command names, exit-code meanings, product artifact paths, privacy defaults, or config v1 loading.

## 2. Product artifact layout frozen

```text
.dare-security/runs/<run-id>/
  summary.json
  findings.json
  coverage.json
  attack-graph.json
  validation.json
  drift.json
  evidence/
  reports/executive.html
  reports/technical.html
```

`ci-result.json` remains a sibling Cycle 004 contract and must not be silently reinterpreted.

## 3. Config/privacy compatibility

Config schema v1 is `schemas/product/v1/config.schema.json`.

Current relevant defaults/semantics:

- version major remains `1`;
- assessment profile is a string and therefore can accept an additive `agentic-security-baseline-2026` value without changing the public schema shape;
- privacy modes remain `standard` / `confidential`;
- network policy remains `restricted` / `denied` / `allowlisted`;
- offline/confidential remain fail-closed;
- reporting formats remain `html` / `json`.

## 4. Existing MCP property contract

Canonical schema:

- `schemas/coverage/v1/property.schema.json`

Current property IDs are constrained to `^MCP\.[A-Z][A-Z0-9_.]+$`.

Current closed category set:

```text
DISCOVERY
IDENTITY
AUTHENTICATION
AUTHORIZATION
AUTHZ_EXECUTION_INTEGRITY
CAPABILITY_EXPOSURE
CREDENTIAL_BOUNDARIES
EVIDENCE
```

Current closed predicate set:

```text
tools_present
resources_present
prompts_present
transport_http
transport_stdio
authorization_present
dynamic_authorization_allowed
execution_integrity_supported
confused_deputy_supported
```

Current validation modes:

```text
static
dynamic
passive
```

Existing serialized MCP property entries must remain semantically unchanged.

## 5. Existing MCP registry/profile inventory

Canonical registry:

- `schemas/coverage/v1/registry.json`

Canonical profile:

- `profiles/mcp-security-baseline.json`

The current baseline contains these 10 property IDs, which are frozen for compatibility:

```text
MCP.DISCOVERY.PASSIVE_BOUNDARY
MCP.DISCOVERY.EXPLICIT_TARGET
MCP.AUTHZ.PER_OPERATION
MCP.AUTHZ.EXECUTION_INTEGRITY.TOOL_NAME
MCP.AUTHZ.EXECUTION_INTEGRITY.ARGUMENTS
MCP.AUTHZ.EXECUTION_INTEGRITY.CONTEXT
MCP.EVIDENCE.REDACTION
MCP.IDENTITY.CONFUSED_DEPUTY
MCP.DISCOVERY.STREAMABLE_HTTP
MCP.AUTHZ.DYNAMIC_VALIDATION
```

Cycle 012 must not rename these IDs for taxonomy aesthetics.

## 6. Coverage semantics frozen

Authoritative implementation:

- `crates/dare-coverage/src/math.rs`
- `crates/dare-coverage/src/status.rs`
- `crates/dare-coverage/src/report.rs`
- `crates/dare-coverage/src/property.rs`
- `crates/dare-coverage/src/profile.rs`
- `crates/dare-coverage/src/applicability.rs`

Frozen finalization rule:

```text
APPLICABLE without verdict -> NOT_TESTED
```

Frozen denominator:

```text
eligible = finalized properties with a verdict + NOT_TESTED + BLOCKED
tested = eligible properties that have a Cycle 001 verdict
coverage = tested / eligible (1.0 when eligible is 0)
NOT_APPLICABLE and OUT_OF_SCOPE are excluded
required_coverage uses the same formula restricted to REQUIRED properties
```

A verdict is invalid for `NOT_APPLICABLE`, `OUT_OF_SCOPE`, `NOT_TESTED`, or `BLOCKED` rows.

Cycle 012 may add risk-family grouping only as additive metadata; it must not change this denominator.

## 7. Backward-compatibility test anchors

Coverage regression anchors:

- `crates/dare-coverage/tests/adversarial.rs`
- `crates/dare-coverage/tests/coverage_fixtures.rs`
- `crates/dare-coverage/tests/cycle005_adapter.rs`
- unit tests in `crates/dare-coverage/src/math.rs`
- unit tests in `crates/dare-coverage/src/property.rs`
- unit tests in `crates/dare-coverage/src/profile.rs`
- unit tests in `crates/dare-coverage/src/applicability.rs`

Product compatibility anchors:

- `crates/dare-product/src/config.rs`
- `crates/dare-product/src/assess.rs`
- `crates/dare-product/src/store.rs`
- `crates/dare-product/src/view_model.rs`
- `crates/dare-product/src/report/`
- product tests under `crates/dare-product/tests/`

Global release gates remain:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
```

## 8. CI baseline evidence

`main` at `717aece1c75145f0d1048618afd95e98a36634ba` has successful GitHub Actions runs for the repository CI and action-e2e workflows. The Cycle 012 branch was created from this baseline and initially contains governance/documentation-only changes.

## 9. Drift assessment

No material drift was found between the approved Cycle 012 planning assumptions and current `main`.

Confirmed planning assumptions:

- `main` is v1.0-rc1 after Cycle 011 productization;
- property schema is still MCP-only and closed;
- the MCP baseline contains 10 existing properties;
- coverage math retains fail-closed `NOT_TESTED` behavior;
- config v1 can carry an additive profile identifier without changing the config schema shape;
- reports already expose profile/profile-version and coverage fields suitable for additive Agentic metadata;
- offline/confidential behavior remains a required invariant.

One implementation constraint is therefore explicit: Cycle 012 must evolve the coverage/property contracts additively while preserving existing v1 schema consumers and MCP profile behavior.

## 10. Task path map for tasks 002–024

| Workstream | Primary paths |
|---|---|
| standards provenance | `standards/`, `schemas/coverage/`, Cycle 012 docs |
| property schema | `schemas/coverage/v1/property.schema.json`, `crates/dare-coverage/src/property.rs` |
| predicates/facts | `crates/dare-coverage/src/facts.rs`, `applicability.rs` |
| registry | `schemas/coverage/v1/registry.json`, new Agentic registry assets |
| profiles | `profiles/`, `crates/dare-coverage/src/profile.rs` |
| coverage compatibility | `crates/dare-coverage/src/{plan,math,report,correlate}.rs` |
| fixtures/tests | `fixtures/coverage/`, `crates/dare-coverage/tests/` |
| CLI | `crates/dare-agent-security-cli/src/coverage.rs`, `args.rs` |
| product reporting | `crates/dare-product/src/{assess,view_model}.rs`, `report/` |
| CI | `.github/workflows/ci.yml` |
| documentation | `docs/`, `book/en/`, `book/pt/` |

## 11. Task-001 decision

**PASS.** Baseline reconciled. No schema/runtime behavior changed. Compatibility constraints are frozen for tasks 002–024.
