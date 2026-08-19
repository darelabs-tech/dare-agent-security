# COAZ integrity — policy and PEP flow

## Security property under test

A permit is bound to the **final normalized operation** that was authorized.

If an input that either:

1. selects the applicable mapping, or
2. contributes to the constructed authorization request

changes semantically after authorization, the earlier permit **must not** be
reused by the DARE reference enforcement model. The final operation must be
re-evaluated or refused.

This property is derived from [OpenID AuthZEN issue #603](https://github.com/openid/authzen/issues/603)
(`[COAZ-MCP] Bind a permit to the MCP operation actually forwarded`). It is
recorded as `OPEN_PROPOSAL` in vector metadata — not normative COAZ-MCP text.

## Current COAZ-MCP vs the proposal

| Source | Status | What it covers |
|---|---|---|
| COAZ-MCP Draft 1 §9 PEP Behavior | DRAFT | Mapping, evaluation, enforcement flow |
| COAZ-MCP Draft 1 §11.5 Mapping Integrity | DRAFT | Security consideration for mapping integrity |
| AuthZEN issue #603 | OPEN_PROPOSAL | Additional authorization-to-execution binding clarification |

Cycle 003 tests the **proposed** binding without claiming OpenID endorsement.
When upstream status changes, update
[`examples/coaz-integrity/cycle003-standards-v1.json`](../examples/coaz-integrity/cycle003-standards-v1.json)
and re-run the standards snapshot test.

## Reference PEP flow

```text
┌─────────────────┐
│ Vector fixture  │  initial_operation + trusted_context
└────────┬────────┘
         v
┌─────────────────┐
│ Projector       │  MCP → AuthZEN-shaped projection (mapping identity)
└────────┬────────┘
         v
┌─────────────────┐
│ Deterministic   │  synthetic in-process PDP (no network)
│ PDP             │
└────────┬────────┘
         v
┌─────────────────┐
│ Binding digest  │  BindingMaterialV1 over mapping-relevant fields
└────────┬────────┘
         v
┌─────────────────┐
│ Mutation stage  │  explicit, fixture-controlled post-permit change
└────────┬────────┘
         v
┌─────────────────┐
│ Recompute       │  final projection + final binding
│ final binding   │
└────────┬────────┘
         v
┌─────────────────┐
│ Reference PEP   │  secure: re-evaluate/refuse on binding change
│ gateway + sink  │  vulnerable: forward with stale permit (synthetic only)
└─────────────────┘
```

### Secure reference modes

- **`SECURE_REEVALUATE`** (default): re-evaluates when binding changes; may
  forward after re-evaluation if policy still permits.
- **`SECURE_REFUSE_ON_CHANGE`**: refuses without forwarding when binding changes.

Both secure modes **never** produce `FORWARDED_WITH_STALE_PERMIT`.

### Vulnerable reference mode

- **`VULNERABLE_REUSE_PERMIT`**: intentionally forwards using the original permit
  even when `final_binding != initial_binding`.
- Available only for built-in synthetic fixtures via `--reference-mode vulnerable`.
- Cannot target arbitrary URL/stdio MCP servers.

## Binding material

`BindingMaterialV1` binds:

- MCP method (scoped to `tools/call` in Cycle 003);
- operation/tool name where applicable;
- mapping identity (projector fixture id);
- mapped inputs and mapped trusted inputs;
- AuthZEN projection digest.

Only **mapping-relevant** semantic changes invalidate the permit. Harmless JSON
reordering (vector 006) and unmapped field additions (vector 007) preserve the
binding.

## Safety boundary

Cycle 003 enforces these invariants in code and tests:

| Invariant | Enforcement |
|---|---|
| Synthetic targets only | Built-in vectors; no third-party endpoint execution |
| No credential serialization | Secret canary tests; vector/result validation rejects prohibited fields |
| No production token acquisition | In-process PDP; no OAuth or live AuthZEN calls |
| No customer-derived fixtures | Fictional rental domain with `*-synthetic-*` identifiers |
| Vulnerable mode is non-destructive | In-process sink trace only; no real `tools/call` to external systems |
| Accurate upstream status | Standards snapshot marks #603 as `OPEN_PROPOSAL` |
| Generic evidence contract | Cycle 001 `SecurityEvidence` schema unchanged; COAZ details in extensions |

Mutations occur only inside the instrumented local authorization-to-execution
pipeline. The harness does not perform network I/O during vector execution.
