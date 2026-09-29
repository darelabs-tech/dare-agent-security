# Cycle 024 — Regression and refinement record

**Status:** IN PROGRESS. This record is completed by task-028.

## Blueprint refinements made during execution

Each entry fixes a rule the Blueprint stated in a form the actual behaviour of the code
could not satisfy. None crosses a frozen boundary in `APPROVAL.md`.

| # | Blueprint text | What the code does, and why | Task |
|---|---|---|---|
| R-1 | §7.3 / task-001: the goldens are the SHA-256 of the six outputs of each ATTACK-PATH-LAB scenario, run fresh through the engines | The engines stamp evidence with the wall clock, and the prompt-injection, multi-turn and static supply-chain results differ between runs. A fresh run's outputs are therefore stable within one run (the lab's double run) but not across runs. The goldens run `validate attack-paths` over a frozen snapshot of the 35 unique engine runs, taken at the baseline before any code change (`tests/fixtures/attack-path-lab-frozen/`, 2.3 MB). They pin the same 156 files. The fresh lab still runs in CI, so the snapshot cannot drift from what the engines emit without the lab noticing | 001, 002 |
