# task-052 — Produce `REGRESSION.md` with exact executed evidence

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-84

## Evidence

`DARE/cycles/019-agentic-supply-chain-aibom/REGRESSION.md`.

**AC-84 — every figure comes from a command that ran.** No number is estimated, projected or carried over. Ten sections:

1. the workspace suite (3249 passed, 0 failed, against a 2852 baseline);
2. the seven Cycle 019 suites, individually (397 total);
3. Cycle 012–018 regressions with per-crate counts, plus the pinned denominators;
4. the four workspace gates, including what the audit warning actually is;
5. both book builds;
6. the real local CI job execution, step by step, with the assertions each step makes;
7. **what the first local run found** — the applicability gap and the omitted `violations` field;
8. **eight corrections made during execution**, each with what caught it;
9. one flaky pre-existing test, named rather than omitted;
10. the security posture, as measured zeros.

Sections 7 and 8 are the ones worth reading. A regression record that listed only what passed would hide the part that matters: the job was run before it was green, and the run is what found that a compliant bundle was reporting `INCONCLUSIVE` because four invariants with no subject in the evidence were being counted as undecided.

Section 9 records a failure this cycle did not cause and did not fix. Leaving it out would have made the record cleaner and less true.
