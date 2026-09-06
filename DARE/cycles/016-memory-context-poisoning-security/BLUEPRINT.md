# Cycle 016 — Memory & Context Poisoning Security — Blueprint

**Status:** READY FOR REVIEW  
**Approval:** PENDING

## Architecture

```text
Scenario / Corpus / Replay Trace
        |
        v
Memory Store Model
        |
        +--> Memory Item Provenance
        +--> Principal / Tenant / Namespace Context
        +--> Memory Policy
        +--> Lifecycle State
        |
        v
Harness Adapter
  REPLAY | SIMULATED | LOCAL_SYNTHETIC
        |
        v
Normalized Memory Events
        |
        v
Coverage Contract Evaluator
        |
        v
Deterministic Memory Invariants
        |
        +--> violation set (all independent facts retained)
        |
        v
Cycle 001 SecurityEvidence
        |
        +--> Coverage / Profile
        +--> Product / Report
        +--> CLI Artifacts
```

## Planned crate

Preferred new crate:

`crates/dare-memory-security`

Responsibilities:

- typed memory/store/policy/scenario/trace models;
- schema validation;
- canonical digests;
- adapters;
- bounded trial ledger;
- normalized observations;
- invariant registry;
- positive coverage contracts;
- evidence bridge;
- deterministic result/report model.

Do not add transport, HTTP, OAuth, vector DB, embedding, LLM or remote-provider dependencies.

## Reuse map

- `dare-security-evidence`: verdict/evidence contract.
- `dare-adversarial`: local-synthetic budgets/kill-switch where useful.
- `dare-identity-security`: reuse principal/tenant conventions, not its evaluator.
- prompt-injection concepts: reuse the untrusted-data-vs-authority rule, not the prompt engine.
- `dare-coverage`: additive property/profile integration.

## Schemas

Under:

`schemas/memory-security/v1/`

Expected files:

- `memory-item.schema.json`
- `memory-store.schema.json`
- `memory-policy.schema.json`
- `scenario.schema.json`
- `corpus-entry.schema.json`
- `trace.schema.json`
- `event.schema.json`
- `result.schema.json`

All schemas: closed fields, bounded strings/arrays, no remote URLs/credentials/executable callbacks, all `$ref` local/compiled-in.

## Canonical identity

Use deterministic canonicalization and SHA-256 bindings for:

- scenario;
- store snapshot;
- each memory item;
- memory policy;
- principal/tenant/namespace context;
- normalized event set;
- recalled-memory set;
- decision/action influence observation.

Do not trust caller-supplied result digests when they can be recomputed.

## Evaluator flow

1. parse + schema validate;
2. hostile-field/secret-shape sweep;
3. structural validation;
4. enforce hard bounds;
5. canonicalize and bind digests;
6. build adapter observations;
7. validate positive coverage per invariant;
8. evaluate deterministic invariants;
9. preserve all simultaneous violations;
10. aggregate verdict `FAIL > ERROR > INCONCLUSIVE > PASS` consistent with existing product semantics;
11. redact before evidence persistence;
12. write bounded artifacts.

## Safety boundaries

- no state-changing production operations;
- no live memory deletion/update;
- no external egress;
- no provider credentials;
- synthetic text/canaries only;
- any requested dangerous action is represented as intent/observation only;
- hard limits are refusal boundaries.

## CI

Dedicated job: `memory-security-2026`.

Required pre-PR command:

`python scripts/run-ci-job-locally.py .github/workflows/ci.yml memory-security-2026`

PR only after all local gates and proof artifacts are complete.
