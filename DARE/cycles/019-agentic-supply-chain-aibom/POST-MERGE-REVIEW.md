# Cycle 019 — Post-Merge Security Review

**Baseline reviewed:** `3fcf3bb8177dbca3d5cbf49df9d9d8923d5681c1`  
**Corrective branch:** `fix/cycle-019-post-merge-security-review`  
**Status:** CORRECTIVE IMPLEMENTATION — CI PENDING

## Review rule

The corrective pass preserves Cycle 019 scope: local/offline evidence only, zero external egress, zero target state changes, no registry/model/Git/OCI fetch, no real credentials, no artifact/model execution, and deterministic verdict authority in the evaluator.

## Findings and corrective contracts

| ID | Severity | Finding | Corrective contract |
|---|---|---|---|
| F01 | BLOCKER | Same component id with contradictory semantics could be union-merged, allowing an approved digest to hide a substituted digest. | Complementary descriptions may merge; contradictory digest/origin/type/name/version evidence is retained independently and evaluated. |
| F02 | HIGH | Attestation subject/signer checks could pass with non-favourable verification evidence. | `INVALID` is a concrete FAIL; `INDETERMINATE`/`UNRECORDED` cannot satisfy PASS coverage; only `VALID` supplies positive verification evidence. |
| F03 | HIGH | Multiple provenance records used a best-case digest/builder summary. | Any comparable digest mismatch survives; every builder id is retained and evaluated independently. |
| F04 | HIGH | Missing provenance/source channels could make required controls appear not applicable. | Artifact provenance and component source trust remain applicable when their subject exists; missing deciding evidence is `INCONCLUSIVE`. |
| F05 | HIGH | Output limits existed in the ledger but real CLI artifact writes bypassed `admit_output`. | Every persisted output is serialized, admitted, then written; the result artifact records final output accounting including itself. |
| F06 | HIGH | Replay accepted partial component overlap between capture and local policy. | Without an explicit subset policy, replay requires exact declared component-set binding. |
| F07 | MEDIUM | One approved origin claim could mask a conflicting unapproved source/supplier/publisher claim. | Every present origin dimension must be approved by its corresponding policy set. |
| F08 | MEDIUM | Provenance/attestation record ceilings and local-synthetic control evidence were incomplete. | Per-component record ceilings are enforced; ancillary input documents join the run-wide byte budget; local-synthetic control/kill-switch state is persisted. |

## Required regression evidence

The corrective PR must demonstrate at minimum:

- same id + approved digest + conflicting digest cannot PASS identity/integrity;
- good provenance beside wrong-digest/unapproved-builder provenance retains both violations;
- valid attestation beside explicitly invalid verification cannot hide the invalid record;
- indeterminate/unrecorded attestation verification is INCONCLUSIVE, not PASS;
- missing provenance and missing source claims remain applicable and cannot yield a clean aggregate PASS;
- partial replay overlap is refused;
- every written artifact contributes to `budget.output_bytes_used`;
- per-component provenance/attestation ceilings refuse over-limit evidence;
- local-synthetic results persist the actual control snapshot;
- existing Cycle 012–019 regression surfaces remain green.

No CI result is claimed in this document until GitHub Actions executes the corrective PR.
