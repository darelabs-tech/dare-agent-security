# task-027 — Write the EN/PT documentation

**Status:** DONE  
**Complexity:** LOW

- **`book/en/src/concepts/blast-radius.md`** and **`book/pt/src/concepts/blast-radius.md`**
  cover:
  - the question the command answers and its inputs, with an example scenario and a
    bounds table;
  - the seed kinds, with the node types each fits and how an entry-point class maps to a
    kind;
  - the component-compromise wording from R-3: no principal is gained that was never
    acquired, and an access under a named principal is refused and counted;
  - how reach is computed: continuity, the two views, the three exposure states, walks,
    the frontier and the delta;
  - the outputs, the exit codes, and the four statements of what a result does not
    claim.
- **Both `SUMMARY.md` files** list the new page after the attack-paths page.
- **EN `commands/validate.md`** has a new `validate blast-radius` section.
- **EN `reference/exit-codes.md`** has a new `validate blast-radius` table.

`mdbook build book/en` and `mdbook build book/pt` both succeed.
