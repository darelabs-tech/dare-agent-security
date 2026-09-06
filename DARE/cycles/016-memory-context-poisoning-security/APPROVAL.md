# Cycle 016 — Product Owner Approval

**Status:** APPROVED FOR EXECUTION  
**Cycle:** 016 — Memory & Context Poisoning Security  
**Approved at:** 2026-09-05  
**Base:** `main @ 9d543ae0ec202b7ad05a852179ca5703857a317a`  
**Planning head:** `32c9a9bea84575e5db9a78b9b8fe94d02077ad71`  
**Branch:** `agent/cycle-016-memory-context-poisoning-security`

## Approval

The Product Owner explicitly approves all artifacts currently frozen in this cycle:

- `EVALUATION.md`
- `DESIGN.md`
- `BLUEPRINT.md`
- `TASKS.md`
- `dare-dag.yaml`
- all 63 acceptance criteria in `DESIGN.md`
- all 37 execution tasks derived from the approved DAG

Execution may proceed without intermediate approval while remaining inside this frozen scope.

## Authorized scope

Implement deterministic, evidence-first Memory & Context Poisoning validation using only:

- `REPLAY`
- `SIMULATED`
- `LOCAL_SYNTHETIC`

Approved surfaces include memory provenance, trust classification, write/overwrite integrity, principal/tenant/namespace boundaries, lifecycle validity, recall behavior, memory influence on objective/tool/arguments/protected fields, evidence integration, bounded CLI/reporting, coverage/profile integration and local CI.

## Required reuse

- Cycle 001 evidence/verdict contracts;
- Cycle 009 budget/kill-switch controls where execution occurs;
- Cycle 013 trust-boundary semantics without duplicating the prompt-injection engine;
- Cycle 015 principal/tenant conventions without duplicating the identity engine;
- Cycle 006 coverage denominator semantics unchanged.

## Explicit exclusions

Not authorized in Cycle 016:

- live/remote memory stores;
- Redis/PostgreSQL/vector DB/SaaS memory connections;
- production agents or customer memory;
- RAG retrieval/vector ACL/document isolation (Cycle 017);
- OAuth/JWT/live identity/PDP work (Cycle 018);
- credentials, token acquisition or secret handling beyond synthetic redaction tests;
- remote MCP invocation;
- arbitrary model-generated shell or executable callbacks;
- destructive, persistent or production state-changing actions.

## Security invariants

No LLM, embedding model, semantic-similarity score or prose heuristic may be the final security judge. PASS requires invariant-specific positive evidence. Missing required evidence yields `INCONCLUSIVE`, never PASS. Independent violations must remain independently observable.

## Release gate

Before a PR may be opened:

1. tasks 001–037 complete;
2. all 63 acceptance criteria mapped to executed evidence;
3. `cargo fmt --all --check` green;
4. `cargo clippy --workspace --all-targets -- -D warnings` green;
5. `cargo test --workspace` green;
6. `cargo audit` resolved under project policy;
7. Cycle 013/014/015 and MCP/Agentic compatibility regressions green;
8. English/Portuguese documentation builds handled consistently with repository policy;
9. the actual workflow job passes locally:

```text
python scripts/run-ci-job-locally.py .github/workflows/ci.yml memory-security-2026
```

10. `REGRESSION.md` and `PROOF.md` complete;
11. final branch head pushed before opening the PR;
12. PR opened once, preserving the `pull_request: types: [opened]` workflow policy.

Execution is authorized subject to these boundaries.
