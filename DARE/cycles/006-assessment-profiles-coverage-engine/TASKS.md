# Cycle 006 — Tasks

**Status:** DONE  
**Approval:** APPROVED FOR EXECUTION (2026-08-20)

## task-001 — Reconcile post-Cycle-004 `main`

Confirm actual contracts delivered by Cycles 001–004:

- evidence types/schema;
- discovery inventory;
- authorization-integrity outputs;
- CLI;
- GitHub Action/CI contract;
- current test conventions.

Do not assume Cycle 005 files exist.

---

## task-002 — Define Security Property Registry

Create versioned stable property definitions based on capabilities actually present on `main`.

---

## task-003 — Define Assessment Profile schema

Create versioned profile declarations with REQUIRED / CONDITIONAL / OPTIONAL property references.

Profiles must remain data, not executable code.

---

## task-004 — Define CoverageStatus domain model

Implement:

```text
APPLICABLE
NOT_APPLICABLE
NOT_TESTED
OUT_OF_SCOPE
BLOCKED
```

separately from Cycle 001 verdicts.

---

## task-005 — Define coverage math and finalization semantics

Specify denominators, required coverage, state transitions, and invalid combinations.

---

## task-006 — Implement deterministic Applicability Engine

Use typed facts and known predicates.

No arbitrary expressions or LLM-only applicability decisions.

---

## task-007 — Implement Assessment Plan artifact

Generate complete pre-execution expected-property plan before security analyzers run.

---

## task-008 — Implement coverage/evidence correlation

Join Assessment Plan with existing execution results and Cycle 001 evidence.

---

## task-009 — Build deterministic local coverage fixtures

Create minimal fixtures for applicability, ROE blocking, not-applicable transports, missing execution, and finalization.

These are coverage-engine fixtures, not a replacement for Cycle 005 lab scenarios.

---

## task-010 — Build coverage reports and machine output

Expose property-level states, reasons, verdicts, evidence references, overall coverage, and required coverage.

---

## task-011 — Extend CLI and Cycle 004 CI gate

Add profile/coverage execution to existing interfaces with deterministic threshold behavior.

---

## task-012 — Add adversarial profile and denominator tests

Test property injection, duplicate IDs, applicability bypass, status relabeling, denominator manipulation, profile tampering, and silent property deletion.

---

## task-013 — Optional Cycle 005 integration adapter

**Conditional.**

Execute only if Cycle 005 has been merged into `main` before this task starts.

Map lab scenarios to security-property IDs without changing Cycle 006 core semantics.

If Cycle 005 is absent, mark this task `NOT_APPLICABLE`, not BLOCKED.

---

## task-014 — Documentation and final DARE proof

Document the registry, profiles, coverage model, denominator, CLI/CI behavior, optional Cycle 005 integration, limitations, and map all acceptance criteria to evidence.
