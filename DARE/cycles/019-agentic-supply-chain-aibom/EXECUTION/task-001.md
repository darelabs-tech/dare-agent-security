# task-001 — Freeze Cycle 019 baseline and compatibility contracts

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-01, AC-02, AC-03, AC-04, AC-06, AC-14, AC-71, AC-72

Freeze the measured pre-cycle state and the contracts Cycle 019 must not disturb.

## Evidence

`BASELINE.md`, written from measurements rather than from the previous cycle's record.

| Item | Measured | Command |
|---|---|---|
| Workspace tests | **2852 passing, 0 failing** | `cargo test --workspace` |
| v1 registry properties | 20 | registry JSON |
| v2 registry properties | 40 | registry JSON |
| Agentic risk families | 10 | distinct `risk_family` in v2 |
| Profiles | 8 | `profiles/*.json` |
| CI jobs | 16 | `.github/workflows/ci.yml` |
| Applicability predicates | 48 | `Predicate` enum |

**AC-01 — baseline pinned.** `git merge-base --is-ancestor 83fee819ef07f29a8d27cedd95db809b34829fd9 HEAD` returns true. The branch descends from the approved baseline, and it also carries both Cycle 018 post-merge hotfixes (PR #29 and PR #33), so the aggregation and admission semantics Cycle 019 must reuse are the corrected ones.

**AC-02, AC-03, AC-04, AC-06 — checked mechanically, not read:**

```
AC-01: baseline 83fee819 IS an ancestor of HEAD
AC-06 parallel AGENT.SUPPLY.* namespace present? False
AC-03 COMPONENT_PROVENANCE present? True
AC-04 CAPABILITY_DRIFT present? True
AC-02 AGENTIC_SUPPLY_CHAIN family present? True | families: 10
```

**AC-71 — the baseline profile's contract is recorded, not just its existence.** `agentic-security-baseline-2026` selects `AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE` at `CONDITIONAL`. Both the selection and the level are frozen: a count alone would not catch `CONDITIONAL` becoming `REQUIRED`, and that change would alter what every assessment already filed against the baseline means without moving any denominator.

**AC-14, AC-72 — Cycle 006 semantics are inherited unchanged.** No applicability or denominator maths is touched by this task; the predicates Cycle 019 adds are recorded in task-004 and must classify as target-shape or evidence in the same way Cycle 018's did.

## Where the eight new properties go

Into the **v2** Agentic registry, taking it 40 → 48. Supply-chain properties are agent behaviours, unlike Cycle 018's MCP protocol and OAuth surfaces, which went into v1 precisely because they were not.

The number to watch is the family count. Cycle 017 added six `AGENT.RAG.*` properties to v2 carrying **no** risk family, because retrieval is not an Agentic risk family. Cycle 019 is the opposite case: `AGENTIC_SUPPLY_CHAIN` already exists, so its eight properties carry it and the count must still read 10 afterwards. Task-003 asserts that from both directions.

## Inherited lessons recorded rather than assumed

`BASELINE.md` §4 records four defects that shipped in Cycles 017 and 018, each with the shape Cycle 019 could repeat: a trace manufacturing authority, budget accounting that bounded nothing, a primary invariant hiding another concrete FAIL, and a finding filed under a name that did not describe it. A fifth is the reason the corpus is paired at all — nine false-PASS paths shipped with 2799 tests green, two of which asserted the defect outright.
