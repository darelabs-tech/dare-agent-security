# Cycle 023 — Approval

**Cycle:** 023 — Attack-Path Construction  
**Approval:** DESIGN APPROVED — Blueprint pending  
**Approved at:** 2026-09-28  
**Approved by:** Product Owner  
**Base:** `main @ 32909ea`  
**Branch:** `claude/loving-newton-113zme`

## Approval decision

`DESIGN.md` is approved as the scope contract for Cycle 023, including the Review
decisions recorded in its §13:

1. **Crate.** A new crate, `dare-attack-path`, holds the projectors, the system model and
   path engine v2. `dare-attack-graph` keeps the model, the builder and v1. The other
   placement is not buildable (engine crates → `dare-adversarial` → `dare-attack-graph`
   would be a cycle).
2. **Pinned inputs.** A relationship read from an input document whose digest the engine
   result pins is `STATICALLY_PROVEN`, citing that digest. A relationship declared only
   in the system model is `INFERRED`, with a mandatory rationale.
3. **Supply chain.** The 019 relationship graph is rebuilt from the pinned SBOM and
   manifest inputs through the engine's public normalization API. No engine changes.
4. **Taxonomy.** The Cycle 008 node and edge enums are kept and mapped through a closed
   table. Provenance records each engine's original kind.
5. **v1 path engine.** Silent truncation, sink-only emission and linear lookups are fixed
   in v2 only. v1 output stays byte-identical. The `unwrap()` in `make_path` is removed in
   v1 as well, without changing output.
6. **Evidence schema id.** The four bridges that cite the nonexistent
   `…/evidence/v1/security-evidence.schema.json` are out of scope. They go to a separate
   hotfix.
7. **Chokepoints.** MUST, as counts over the enumerated paths, flagged `partial` when
   enumeration was truncated.

Also approved with the Design: the 022 projector reads `remote-result.json` as
schema-validated JSON and does not depend on `dare-remote-validation`. `dare-attack-path`
has no network dependency (RF-02, RNF-04).

## Frozen boundaries

Neither the Blueprint nor execution may, without a new Review:
- change an engine crate (013–022), its verdict semantics or its artifacts;
- change the output of `validate attack-graph --facts` or any Cycle 008 v1 fixture;
- change `Path`, `PathStatus` or the eligibility and drift behaviour that
  `dare-adversarial` and `dare-continuous` build on them;
- merge two engine-local identifiers without an explicit system-model alias;
- let a path's control state be better than its weakest guard, or report
  `CONTROLS_HELD` for a path with an unassessed edge;
- give `dare-attack-path` a network dependency, or let it execute, send or schedule
  anything;
- add a risk score, probability or weighting;
- add or change a property ID or a profile denominator.

## Next step

`/dare-blueprint` produces `BLUEPRINT.md` for Review. Tasks are not generated until the
Blueprint is approved, and execution is **not** authorized until the task set is
approved.
