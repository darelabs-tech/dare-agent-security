# Cycle 018 — Frozen baseline and inherited contracts

**Baseline:** `main @ f5906e8b24679b7affffcdc9db5d6116ba9b045d`
**Branch:** `agent/cycle-018-mcp-2026-security-auth-hardening`
**Branch head at freeze:** `eb4721b589ae7ee52cb087d11bea9b099a04375e`
**Frozen at:** 2026-09-06

Everything below was measured on this branch at the head above, not quoted from a
previous cycle's document.

## 1. Test baseline

`cargo test --workspace` — **2442 passing, 0 failing.**

| Crate | Passing |
|---|---|
| `dare-security-evidence` | 75 |
| `dare-coaz-integrity` | 124 |
| `dare-coverage` | 233 |
| `dare-adversarial` | 14 |
| `dare-prompt-injection` | 271 |
| `dare-tool-security` | 276 |
| `dare-identity-security` | 323 |
| `dare-memory-security` | 265 |
| `dare-rag-security` | 283 |
| `dare-product` | 80 |
| `dare-agent-security` (CLI) | 269 |
| `dare-mcp-discovery` | 146 |
| `dare-mcp-lab` | 28 |
| `dare-attack-graph` | 10 |
| `dare-benchmark` | 15 |
| `dare-continuous` | 13 |

Any number Cycle 018 reports later is measured against 2442, and a drop is a
regression rather than a rounding difference.

## 2. Registry and profile inventory

| Item | Value |
|---|---|
| v1 (MCP) registry properties | 10 |
| v2 (Agentic) registry properties | 40 |
| Agentic risk families | 10 |
| Profile files | 7 |
| CI jobs | 15 |

The ten v1 MCP properties, which Cycle 018 must not rename or re-scope:

`MCP.DISCOVERY.PASSIVE_BOUNDARY`, `MCP.DISCOVERY.EXPLICIT_TARGET`,
`MCP.AUTHZ.PER_OPERATION`, `MCP.AUTHZ.EXECUTION_INTEGRITY.TOOL_NAME`,
`MCP.AUTHZ.EXECUTION_INTEGRITY.ARGUMENTS`, `MCP.AUTHZ.EXECUTION_INTEGRITY.CONTEXT`,
`MCP.EVIDENCE.REDACTION`, `MCP.IDENTITY.CONFUSED_DEPUTY`,
`MCP.DISCOVERY.STREAMABLE_HTTP`, `MCP.AUTHZ.DYNAMIC_VALIDATION`.

Cycle 018's ten new properties are additive into this same v1 MCP namespace. They do
**not** enter the v2 Agentic registry, which is what keeps the Agentic risk family
count at 10 without needing an exclusion rule.

## 3. Inherited contracts Cycle 018 must reuse, not re-derive

### Cycle 001 — `dare-security-evidence`

`Verdict` (`PASS` / `FAIL` / `INCONCLUSIVE` / `ERROR`), `SecurityEvidence`, `TargetRef`,
`Decision`, `ObservationSource`, redaction helpers and `validate_secret_safety`. Cycle 018
re-exports `Verdict` rather than defining a parallel one, and files every evidence record
against a synthetic target.

### Cycle 002 — `dare-mcp-discovery`

`CURRENT_WIRE_REVISION = "2026-07-28"` and `LEGACY_WIRE_REVISION = "2024-11-05"` are
defined in `crates/dare-mcp-discovery/src/adapter_session.rs` and re-exported through
`adapter`. Cycle 018 **imports** both constants. Writing the literal `"2026-07-28"` into
the new crate would create a second source of truth that could drift silently, so the
revision model is built on the imported constants and a test asserts the identity.

Also inherited: `PolicyProfile::{Current2026_07_28, Legacy2024_11_05}`, the fail-closed
handling of unsupported revisions, HTTPS-only production defaults and disabled redirects.
Cycle 018 does not reimplement discovery, handshake or transport policy.

### Cycle 003 — `dare-coaz-integrity`

`compute_authorization_binding`, `bindings_equal`, `BindingMaterialV1`,
`changed_operation_fields`, `changed_trusted_fields`, `apply_mutation`, `bind_decision`,
`AuthorizationProjector`. This is the authorization-to-execution engine. Cycle 018
composes with it for `FINAL_OPERATION_AUTHORIZATION_BINDING_PRESERVED` and does **not**
build a second stale-permit engine.

### Cycle 006 — `dare-coverage`

`PropertyRegistry`, `Predicate`, `AssessmentProfile`, `RequirementLevel`,
`validate_profile`, `profile_digest_sha256`. Denominator mathematics are untouched: a
coverage percentage is a fraction over a profile's property count, and no existing
profile's count may move.

### Cycle 009 — `dare-adversarial`

`ExecutionBudget`, `budget_enforce::BudgetState`, `kill_switch::inspect_step`,
`ProofClass::SyntheticNoop`, `canonical::digest`. Local-synthetic execution is gated
through these.

### Cycle 015 — `dare-identity-security`

`PrincipalKind` (`Human`, `Agent`, `Workload`, `Service`), `Principal`, `PrincipalSet`,
`DelegationChain`, `Operation`, `OperationField`. Cycle 018 re-exports `PrincipalKind`
rather than defining a parallel identity model, and refuses where the two models describe
the same principal differently.

### Cycle 017 — `dare-rag-security`

Independent surface. The one thing Cycle 018 inherits is the **lesson**, recorded in §4.

## 4. The Cycle 017 replay-binding defect, and what Cycle 018 must do differently

Cycle 017 shipped `RagTrace::assert_matches` comparing only `scenario_id`. The trace's own
query and candidate declarations were then evaluated as though the scenario had approved
them, so a trace could widen `collection_ids`, `requested_top_k`, the mandatory filter,
the objective and candidate membership while keeping the same `scenario_id`. It was fixed
on `main` in `940b920` by comparing every authorization-relevant field before any
evaluator sees the observation, and refusing unknown references.

The general form of the defect:

> **Observed evidence is evidence. It is not the authority that defines what was approved.**

Cycle 018's replay surface is much wider than Cycle 017's — identity, issuer, resource,
audience, scope, PKCE, redirect, registration, credential flow and final operation are all
authorization-relevant. Every one of them must be bound to the approved scenario before
evaluation, and `scenario_id` equality is explicitly **not** sufficient. This is designed
in from task-014/015 rather than retrofitted, and it is why the approved DESIGN states
`same scenario_id != same authorization semantics`.

The exclusion rule is equally important: prose does not widen authority. A human-readable
label, title or description may differ between the trace and the scenario without being a
binding violation, because changing prose cannot change what was authorized.

## 5. CI contract

The workflow trigger is:

```yaml
on:
  pull_request:
    branches: [main]
    types: [opened]
```

Fifteen jobs exist today. Cycle 018 adds `mcp-auth-security-2026` as a sixteenth. The
trigger is not modified and no push trigger is added: the PR-open event is the real CI
validation event, which is why the branch must be complete and locally validated first.

## 6. Predicted movement

| Item | Before | After Cycle 018 |
|---|---|---|
| Workspace tests | 2442 | higher |
| v1 MCP properties | 10 | 20 |
| v1 predicates | 9 | 20 |
| v2 Agentic properties | 40 | **40 (unchanged)** |
| Agentic risk families | 10 | **10 (unchanged)** |
| Profiles | 7 | 8 |
| CI jobs | 15 | 16 |
| Crates | 16 + 1 lab | 17 + 1 lab |

## 7. Residual risks carried into the cycle

1. **The engine reasons about recorded evidence, never a live authorization server.** A
   clean Cycle 018 result says the recorded flow was internally consistent. It says
   nothing about whether a production IdP is configured correctly, whether a real
   signature was verified, or whether a live MCP server enforces what the trace shows.
2. **Token validity is a fixture-declared enum, not a cryptographic result.** Cycle 018
   verifies binding *around* that declaration — issuer, audience, resource, scope — and
   never verifies a signature, because doing so would require a live JWKS.
3. **`clientInfo` / `serverInfo` are self-reported.** The engine's job is to refuse to
   promote them to identity, not to determine whether they are true.
4. **The corpus is finite.** An MCP auth failure mode outside the approved scenarios is
   untested, and the report must say "not tested" rather than passing it by absence.
