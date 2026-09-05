# task-016 — Add benign-control corpus and false-positive regressions

**Status:** READY FOR EXECUTION

## Objective
Prove the engine does not classify benign adversarial-looking text as a deterministic violation without evidence.

## Acceptance
- benign controls for direct and indirect sources;
- no false deterministic FAIL from keywords/prose alone;
- unsupported ambiguity -> INCONCLUSIVE when evidence is insufficient;
- regression tests are stable/offline.
