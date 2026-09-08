# task-053 — Produce `PROOF.md` mapping all 85 ACs to executed evidence and final pre-PR review

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-85

## Evidence

`DARE/cycles/019-agentic-supply-chain-aibom/PROOF.md`.

**AC-85 — 85 of 85 criteria mapped**, each to a named test, a named function or a file in this cycle's directory.

**The citations are checked mechanically.** `scripts/k19/verify_proof_citations.py` runs as a step of the `supply-chain-security-2026` CI job:

```
PROOF.md cites 156 names against 698 tests in the tree
  18 function citations, 6 historical names
every cited name is verified
```

A proof document whose citations are unchecked is a claim about a claim. Cycle 016 shipped three citations naming tests that did not exist, and the Cycle 018 post-merge review found two more that had gone stale when their tests were renamed.

**The check caught eleven of mine.** Names written from memory for modules built earlier in the cycle — `exactly_eight_properties_were_added` for `exactly_the_eight_approved_properties_were_added`, `a_version_is_not_an_immutable_artifact` for `a_name_and_version_are_not_an_immutable_artifact`, and nine others. Every one was corrected to the name the tree actually holds. Without the gate, all eleven would have shipped as confident citations of tests that do not exist.

The verifier also holds six **historical names** — tests this cycle renamed or replaced — and asserts they are *absent*. A name recorded as removed that still exists means the record is wrong in the other direction.

## What the document says before the table

The boundary, because a proof document is exactly where a reader is most likely to conclude more than was established: a PASS covers the invariants that **applied** under the documents **actually read**; nothing was fetched, signed or executed; licence, PII, copyright, bias and fairness were not assessed; and Cycles 014 and 020 are not answered here.

## What it says after the table

Three claims that were wrong first and were corrected by something that ran — the applicability gap found by the CI job, the two invariants that passed having compared nothing, and identity ambiguity being refused instead of reported. Then the frozen contracts, restated as a table so a reviewer can check them without reading the cycle.
