# Upstream contribution package — COAZ authorization-to-execution integrity

> Cycle 003 task-012
> Status: **neutral synthetic materials for human review**
> Target forum: OpenID AuthZEN (issue #603 discussion)

This package is suitable for standards-community review. It contains **no**
DARE-private data, customer fixtures, credentials, or production endpoints.

**Do not** treat this directory as an automatic upstream PR or IPR submission.
A human maintainer must review content, licensing, and contribution process
before any upstream publication.

## Purpose

Demonstrate deterministic conformance vectors for the authorization-to-use
property proposed in [openid/authzen#603](https://github.com/openid/authzen/issues/603):

> Bind a permit to the MCP operation actually forwarded.

The current COAZ-MCP Draft 1 defines PEP behavior and Mapping Integrity (§11.5).
Issue #603 proposes an additional authorization-to-execution binding
clarification. These vectors test that proposed property without claiming it is
already normative.

## Package contents

| File | Description |
|---|---|
| [`vectors-matrix.md`](vectors-matrix.md) | Neutral vector summary table |
| [`trace-secure-001.txt`](trace-secure-001.txt) | Reference secure PASS trace (unchanged operation) |
| [`trace-vulnerable-003.txt`](trace-vulnerable-003.txt) | Reference vulnerable FAIL trace (stale permit) |
| [`../vectors/`](../../../vectors/coaz-mcp/authorization-integrity/v1/) | Full portable vector JSON (001–007) |
| [`../examples/`](../../../examples/coaz-integrity/) | Reference result and evidence fixtures |

## Per-vector upstream summary

Each row follows the contribution template from task-012:

| Vector ID | Authorization input semantics | Mutation | Expected enforcement | Secure trace | Vulnerable trace |
|---|---|---|---|---|---|
| COAZ-INTEGRITY-001 | Unchanged `tools/call` after permit | None | Forward with existing permit | [`trace-secure-001.txt`](trace-secure-001.txt) | N/A (no binding change) |
| COAZ-INTEGRITY-002 | Default mapping on `rental.quote` | Tool name → `rental.confirm` | Re-evaluate or refuse | Secure: binding change → refuse/re-evaluate | Forward with stale permit → FAIL |
| COAZ-INTEGRITY-003 | Declared mapping includes `daily_rate` | `daily_rate` 50 → 5000 | Re-evaluate or refuse | Secure: refuse/re-evaluate | [`trace-vulnerable-003.txt`](trace-vulnerable-003.txt) |
| COAZ-INTEGRITY-004 | Default mapping on method + tool | Method change | Re-evaluate or refuse | Secure: refuse/re-evaluate | Forward with stale permit → FAIL |
| COAZ-INTEGRITY-005 | Trusted context claim `role` mapped | `role` standard → elevated | Re-evaluate or refuse | Secure: refuse/re-evaluate | Forward with stale permit → FAIL |
| COAZ-INTEGRITY-006 | Declared mapping; JSON reorder only | Key order/format only | Permit remains bound | Binding unchanged → PASS | N/A |
| COAZ-INTEGRITY-007 | Declared mapping; unmapped field | Add non-mapped field | Permit remains bound | Binding unchanged → PASS | N/A |

## Semantic equality note

Binding uses normalized semantic values, not raw JSON bytes. Vectors 006–007 are
positive controls for this requirement.

## Executable scope

Vectors scope to MCP `tools/call` (revision `2026-07-28`). COAZ-MCP Draft 1
lifecycle examples may differ; see
[`docs/coaz-integrity-standards.md`](../../../docs/coaz-integrity-standards.md).

## Suggested upstream workflow

1. Review vector JSON and traces in this package with AuthZEN/COAZ-MCP editors.
2. Confirm synthetic domain (`rental.quote`) is acceptable or propose neutral rename.
3. Align expected enforcement vocabulary with COAZ-MCP Draft 1 terms.
4. If accepted, update standards snapshot status from `OPEN_PROPOSAL` to normative reference.
5. Submit through the project's official contribution process (not automated from this repo).

## IPR reminder

Contributors must follow OpenID Foundation IPR policies for any normative text
proposal. This repository's Apache-2.0 license covers the **software and synthetic
fixtures** here; it does not substitute for upstream IPR declarations.
