# Cycle 015 — Blueprint

**Status:** READY FOR REVIEW
**Cycle:** 015 — Identity, Privilege & Delegation Security

## Architecture intent

Implement `crates/dare-identity-security/` as a narrow engine for deterministic authority validation.

### Proposed module shape

```text
src/
  lib.rs
  model.rs
  schema.rs
  source.rs
  principal.rs
  authority.rs
  delegation.rs
  resource.rs
  authorization.rs
  operation.rs
  observation.rs
  coverage.rs
  invariant.rs
  canonical.rs
  trials.rs
  replay.rs
  simulated.rs
  local_synthetic.rs
  harness.rs
  evidence_bridge.rs
  result.rs
  error.rs
```

## Reuse map

- Cycle 001: `SecurityEvidence`, evidence IDs, verdict vocabulary.
- Cycle 003: normalized authorization projection, final-operation recomputation, stale-permit mutation semantics.
- Cycle 005: confused-deputy and authorization mutation fixture patterns.
- Cycle 006: property applicability/profile coverage math.
- Cycle 008: synthetic principal→agent→service→tenant graph patterns.
- Cycle 009: ROE, budgets, kill switch, bounded local execution.
- Cycle 011: CLI/product/report integration.
- Cycle 012: `IDENTITY_PRIVILEGE_ABUSE` registry family.
- Cycle 013/014: versioned corpus, replay/simulated/local-synthetic engine patterns, positive PASS coverage and local CI job execution.

## Implementation sequence

### Phase A — Baseline and standards

1. Freeze main/Cycle 014 baseline.
2. Commit standards snapshot for ASI03/AuthZEN/COAZ with statuses.
3. Add specialized properties/predicates additively.

### Phase B — Schemas and canonical model

4. Principal-set schema.
5. Delegation-chain schema.
6. Authority/policy/decision schema.
7. Resource/tenant schema.
8. Operation schema.
9. Scenario/corpus/trace schemas.
10. Closed enums and input refusal rules.
11. Canonical digests and cross-object binding.

### Phase C — Evaluation core

12. Normalized identity event model.
13. Positive coverage contracts.
14. Deterministic invariant registry.
15. Authority subset/ceiling evaluation.
16. Delegation-chain validation.
17. Authorization→final-operation semantic binding via Cycle 003 reuse.
18. Trial/count/depth/budget enforcement.

### Phase D — Safe harness

19. Replay adapter.
20. Simulated adapter.
21. Local-synthetic integration with Cycle 009.

### Phase E — Corpus and adversarial validation

22. Principal/delegation/privilege corpus.
23. Tenant/resource and confused-deputy corpus.
24. Authorization mutation/stale-permit corpus.
25. Benign controls.
26. Hostile parser/schema/credential-smuggling fixtures.
27. Multi-violation and redaction tests.

### Phase F — Product integration

28. Cycle 001 evidence bridge/result artifacts.
29. Identity profile/coverage integration.
30. `validate identity-security` CLI.
31. Product/report integration.
32. Offline/confidential/no-live-identity regressions.
33. Dedicated Cycle 015 CI job and actual local workflow execution.
34. Operator/contributor docs.
35. Full compatibility regression and final proof.

## Key data contracts

### Principal set

Must uniquely bind known synthetic principals and distinguish initiating/effective/agent/delegated roles.

### Authority ceiling

Deterministic set/constraint representation only. No policy language or executable callbacks.

### Delegation chain

Each edge must be referentially valid, acyclic, bounded and authority-non-expanding.

### Authorization decision

Must bind to a canonical authorization-relevant operation identity. A later final operation with changed policy-relevant semantics cannot inherit a stale permit without re-evaluation/refusal.

### Evidence

Never stores tokens; stores synthetic identifiers and canonical digests.

## Safety gates

- No network dependency required by identity engine.
- No process/shell execution.
- No real OAuth/JWT/IdP/PDP interaction.
- No state-changing business operation.
- Every risky operation is inert structured data.
- Any secret-shaped field/value is refused or redacted before persistence.

## CI gate

Add `identity-security-2026` and run the shipped job locally:

```bash
python scripts/run-ci-job-locally.py .github/workflows/ci.yml identity-security-2026
```

PR is opened only after local green gates and final proof.
