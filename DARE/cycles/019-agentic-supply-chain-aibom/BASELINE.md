# Cycle 019 — Frozen baseline

Measured on the execution branch before any Cycle 019 code was written. Every
number here was produced by running the command beside it, not by reading a
previous cycle's record.

- **Branch:** `agent/cycle-019-agentic-supply-chain-aibom`
- **Baseline:** `main @ 83fee819ef07f29a8d27cedd95db809b34829fd9`
- **Planning head:** `6b1df9dedca44d8a3fed4b92a755d9850ea6c1b3`
- **Toolchain:** rustc/cargo 1.94.1, Windows 11 msvc; Git Bash for the local
  workflow runner; mdBook 0.5.4

`git merge-base --is-ancestor 83fee819… HEAD` returns true, so the branch
descends from the approved baseline.

## 1. Measured state

| Item | Value | Command |
|---|---|---|
| Workspace tests | **2852 passing, 0 failing** | `cargo test --workspace` |
| v1 (MCP) registry properties | 20 | `schemas/coverage/v1/registry.json` |
| v2 (Agentic) registry properties | 40 | `schemas/coverage/v2/registry.json` |
| Agentic risk families | 10 | distinct `risk_family` across v2 |
| Assessment profiles | 8 | `profiles/*.json` |
| CI jobs | 16 | `.github/workflows/ci.yml` |
| Applicability predicates | 48 | `Predicate` enum in `dare-coverage` |

## 2. The two supply-chain properties Cycle 019 must not disturb

Both already exist in the **v2** Agentic registry under the
`AGENTIC_SUPPLY_CHAIN` risk family, and both are reused rather than replaced:

| Property | Risk family | Predicates |
|---|---|---|
| `AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE` | `AGENTIC_SUPPLY_CHAIN` | `agent_present`, `external_components_present` |
| `AGENT.SUPPLY_CHAIN.CAPABILITY_DRIFT` | `AGENTIC_SUPPLY_CHAIN` | `agent_present`, `external_components_present` |

`AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE` is also selected by
`agentic-security-baseline-2026` at requirement level `CONDITIONAL`. That
selection and that level are part of the frozen contract: changing either would
alter what an assessment already filed against the baseline profile means.

Cycle 019 adds **eight** properties into this same namespace, taking v2 from 40
to 48. It creates no risk family, so the count stays at 10, and it introduces no
`AGENT.SUPPLY.*` parallel namespace.

## 3. Where Cycle 019's properties go, and why it matters

Supply-chain properties are **Agentic** properties, so they belong in the v2
registry — unlike Cycle 018, whose MCP protocol and OAuth surfaces went into v1
precisely because they were not agent behaviours.

The consequence to watch is the risk-family count. Cycle 017 added six
`AGENT.RAG.*` properties to v2 with no risk family, deliberately, because
retrieval is not an Agentic risk family. Cycle 019 is the opposite case: its
properties belong to a family that already exists, so they carry
`AGENTIC_SUPPLY_CHAIN` and the count must still read 10 afterwards. A test
asserts that from both directions.

## 4. Lessons inherited from Cycles 017 and 018

These are recorded here because each was a defect that shipped, and each has a
shape Cycle 019 could repeat.

**A trace must not manufacture authority (Cycle 017, fixed in `940b920`).** A
replayed observation could change identity-relevant fields while keeping the
same `scenario_id`, and the widened version was judged as though approved.
Cycle 019's equivalent: an imported BOM or attestation is *evidence about* a
component, never the authority that says which component was approved. A REPLAY
trace must bind to the approved scenario semantically, not by id.

**Admission must happen before normalization (Cycle 018, PR #29 F08).** The
budget ledger counted bytes it did not bound: over-budget material was still
normalized and persisted, so the artifact described a smaller run than the one
that happened. Cycle 019 freezes the order in `BLUEPRINT.md` — byte admission,
then parse, then component/relationship admission, then persistence — and an
over-budget object must never produce deciding evidence.

**A primary invariant must not hide another concrete FAIL (Cycle 018, PR #33).**
`collect_observed_violations` now evaluates every applicable invariant over the
retained evidence and keeps every concrete FAIL, while leaving secondary PASS,
INCONCLUSIVE and ERROR outcomes out of the aggregate. Cycle 019 reuses that
semantic rather than inventing a second aggregation rule.

**A finding must name what it is about (Cycle 018, PR #29 F06).** A promoted
`clientInfo` was filed under an invariant about credential forwarding, because
the property existed and no invariant reported under it. Cycle 019 has ten
properties and twelve invariants; the mapping in `DESIGN.md` §19 is total in
both directions, and a test asserts it.

**A test written after the implementation describes it (Cycle 018 post-merge).**
Nine false-PASS paths shipped with 2799 tests green, two of which asserted the
defect outright. Cycle 019's paired corpus exists so that each vulnerable
fixture differs from its control by exactly one mutation, and each is registered
with its expected outcome outside the fixture.

## 5. What a later cycle will measure against this

Any number Cycle 019 reports is measured against **2852**, and a drop is a
regression rather than a rounding difference. The v2 count should read 48, the
family count 10, profiles 9 and CI jobs 17 when the cycle closes.
