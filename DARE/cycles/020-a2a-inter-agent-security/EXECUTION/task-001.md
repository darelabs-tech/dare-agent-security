# task-001 — Freeze Cycle 020 baseline, scope and compatibility contracts

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Establish the measured repository state Cycle 020 starts from, so every later claim about what this cycle added is a difference against a number that was actually observed rather than one that was assumed.

## Files changed

- `DARE/cycles/020-a2a-inter-agent-security/EXECUTION/task-001.md` (this record)

## Commands executed

```
git checkout agent/cycle-020-a2a-inter-agent-security
git merge-base --is-ancestor d2bff1d3789074dffaae45a7ce57a3563daeb1ff HEAD
cargo test --workspace
python -c "<count profiles, registries, CI jobs>"
```

## Result

**Branch and baseline verified.** The approved branch `agent/cycle-020-a2a-inter-agent-security` already existed on the remote carrying the seven planning artifacts, and `git merge-base --is-ancestor` confirms `d2bff1d` is an ancestor of its head. The planning head reviewed in `APPROVAL.md` (`058ca8d`) is in this branch's history.

**Measured baseline:**

| Measure | Value |
|---|---|
| Workspace tests passing | **3343** |
| Workspace tests failing | **0** |
| Test binaries reporting FAILED | **0** |
| v1 (MCP) registry properties | 20 |
| v2 (Agentic) registry properties | 48 |
| Agentic risk families | 10 |
| Profiles | 9 |
| CI jobs | 17 |
| Existing `AGENT.A2A.*` properties | 2 |

The two existing A2A properties are `AGENT.A2A.MESSAGE_AUTHENTICITY` (predicates `agent_present`, `multi_agent_present`) and `AGENT.A2A.AUTHORITY_PROPAGATION` (predicates `agent_present`, `multi_agent_present`, `delegated_identity_present`), both in family `INSECURE_INTER_AGENT_COMMUNICATION`. Those predicate sets are recorded here because they are frozen: `the_two_inherited_properties_are_unchanged` asserts them verbatim, and a later edit to either would change what every assessment already filed against them meant.

## Compatibility contracts entering the cycle

Recorded from the approved documents, and each one has a test behind it by the end of the cycle:

1. Cycle 001 owns evidence, verdict and redaction primitives.
2. Cycle 006 owns applicability and coverage math.
3. Cycle 013 owns generalized prompt injection.
4. Cycle 014 owns runtime tool authorization.
5. Cycle 015 owns principal, delegation, privilege and tenant identity semantics.
6. Cycle 018 owns deterministic concrete-FAIL aggregation.
7. Cycle 019 owns AI-BOM, supply chain and external-agent inventory.
8. Cycle 020 owns the A2A projection of all of the above, and absorbs none of them.

## Evidence

The baseline number is the one every later count in `REGRESSION.md` is measured against: 3343 before this cycle began.

## Deviations

None. The Cycle 020 planning artifacts were not present on `main` or on the Cycle 019 branch; they live on the approved execution branch, which is where the cycle is executed from.

## Review result

**REVIEW PASS** — baseline frozen and measured.
