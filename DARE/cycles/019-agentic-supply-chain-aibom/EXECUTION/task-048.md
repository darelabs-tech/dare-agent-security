# task-048 — Add `supply-chain-security-2026` CI job and execute real job locally before PR

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-76, AC-77

## Evidence

`.github/workflows/ci.yml` — the `supply-chain-security-2026` job, 18 steps.

**AC-76 — additive, and the trigger is unchanged.** The workflow still runs on `pull_request: types: [opened]` against `main`. The job was inserted before `docs-build` and touches no existing job.

**AC-77 — executed locally, for real, before any PR.**

```
python scripts/run-ci-job-locally.py .github/workflows/ci.yml supply-chain-security-2026
```

18 of 18 steps passing. Recorded in `REGRESSION.md` §6 with the per-step assertions.

The offline CLI steps assert **exit codes and parsed JSON fields**, never substrings. A gate that greps is how a healthy run gets failed by a coincidence — `SECURE` matching inside `INSECURE_INTER_AGENT_COMMUNICATION` cost Cycle 013 a red build.

Seven real invocations: a compliant bundle (exit 0), a substituted artifact (exit 2), an unapproved signer (exit 2), a substituted base model (exit 2), evidence too thin to decide (exit 2, `INCONCLUSIVE`, zero violations), a bundle crossing three boundaries (exit 2, three invariants retained), a dangling edge (exit 1, `ERROR`), and an unknown vector (exit 3).

## What the first run found

The job was run before it was green, and it found something no unit test had.

**The compliant vector reported `INCONCLUSIVE`.** SUPPLY-LAB-001 stages a package with its approvals, provenance and attestation — and no model, no dataset, no capabilities and no dependency edges. Four invariants were being counted as *undecided* when the system had raised no question at all.

That is the engine claiming a gap that does not exist. The fix distinguishes **inapplicable** from **undecided**:

- an invariant with no subject in the evidence is marked `applicable: false` and left out of the aggregate — `an_invariant_with_no_subject_is_inapplicable_rather_than_undecided`;
- an invariant *with* a subject and missing deciding evidence stays `INCONCLUSIVE` — `an_applicable_invariant_with_thin_evidence_stays_undecided`.

Applicability is read from the observations rather than declared, so it cannot drift from what was actually seen.

Without the distinction, a clean result would have been unreachable for any deployment that did not contain one of everything, and an operator who never sees `PASS` stops reading the difference between `PASS` and `INCONCLUSIVE`.

The same run also caught `violations` being omitted from the artifact when empty, which broke a `--count violations=0` assertion and would have let a reader treat missing as unknown.
