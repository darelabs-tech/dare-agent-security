# task-036 — Write EN/PT concept and extension docs

**Status:** DONE  
**Complexity:** LOW

## Files changed

- `book/en/src/concepts/multi-turn-security.md` (new)
- `book/en/src/reference/extending-multi-turn-security.md` (new)
- `book/pt/src/concepts/multi-turn-security.md` (new)
- `book/en/src/SUMMARY.md` and `book/pt/src/SUMMARY.md`: linked

## Deviation recorded

The Blueprint listed a PT extension page. The Portuguese book has **no** "Extending …"
pages for any cycle (its `reference/` holds only configuration, exit codes,
environment and artifacts). Adding one for Cycle 021 alone would break the book's
structure, so the PT book gets the concept page, matching every earlier cycle.

## Result

The concept pages explain:
- the question answered and the seven properties;
- the closed meaning of "adaptive";
- the verdicts and the delegation to Cycle 013;
- the modes;
- what a result does not claim;
- two runnable examples.

The EN extension page covers the schemas, the admission path, graph-writing rules,
replay of a user's own transcript, adding corpus entries and the exit codes.

## Verification

- `mdbook build book/en` with v0.4.40 (the CI version, downloaded from its GitHub release): exit 0, no warnings; the three new pages were rendered to HTML
- `mdbook build book/pt`: exit 0, no warnings
- `python scripts/regen-canvas.py --check` was failing: `DARE/.canvas.md` had drifted to the Cycle 021 task list. It was regenerated with `scripts/regen-canvas.py`, and the check passes. The canvas is regenerated again after task-037.
