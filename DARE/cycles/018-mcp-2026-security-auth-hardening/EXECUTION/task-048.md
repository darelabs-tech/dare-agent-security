# task-048 — Full regression and proof

**Status:** DONE - REVIEW PASS

Run the full regression suite and produce `REGRESSION.md` and `PROOF.md` mapping all 76 acceptance criteria to executed evidence.

## Evidence

`REGRESSION.md` and `PROOF.md`, both in this cycle directory.

**Every gate ran, and the results are recorded as they ran:**

| Gate | Result |
|---|---|
| `cargo fmt --all --check` | clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 warnings |
| `cargo test --workspace` | **2799 passing, 0 failing** |
| `cargo audit` | exit 0, 0 vulnerabilities, 1 pre-existing allowed warning |
| `mcp-auth-security-2026` (real workflow, local runner) | **all 27 steps PASSED** |
| Cycles 012–017 gates | 5 / 22 / 28 / 36 / 39 / 41 steps, all PASSED |
| 5 generators `--check` + credential sweep | all current |
| `mdbook build book/en` and `book/pt` | both built |

2799 is 2442 + 357 exactly — the frozen baseline plus this cycle's own suites. No earlier test was removed, renamed away or made to count differently.

**PROOF.md's citations were verified mechanically, not from memory.** Every test-shaped name in the document was matched against the compiled test list: 250 names, 246 resolving to a test and 4 to a named function (`assert_no_conformance_claim`, `assert_no_status_promotion`, `compute_authorization_binding`, `changed_operation_fields`), each confirmed present at its cited location. Cycle 016 shipped three citations naming tests that did not exist; that is why this is a step rather than a habit.

## Two defects the gates found

Recorded in `REGRESSION.md` §4 in full. Both were found by running things rather than by reading them.

**A promoted self-report reported PASS.** Lab 030 — a deployment deriving its acting principal from `clientInfo` — exited 0. The boundary was modelled and tested, but no *run* consulted it, and the lab suite checked it by reading a scenario field rather than by running the engine. An operator would have got PASS on an already-broken target. Fixed by checking the identity boundary on every trial; one verdict changed, from a wrong PASS to a correct FAIL.

**A false claim about the dependency graph.** The crate manifest claimed no transport stack existed "here or transitively". The transitive half was false — `dare-mcp-discovery` carries `rmcp` and through it `reqwest`, `hyper` and `rustls` — and the overclaim had been copied into the crate docs, the CLI docs and the book. The dependency exists for two protocol-revision constants, and removing it would mean restating `"2026-07-28"` in a second crate. So the claim was corrected and the boundary made enforceable: one test scans the crate's source and fails if any reference to Cycle 002 other than the constants re-export appears, another checks the manifest against fourteen transport, OAuth and JWT crate names.

## Baseline note

The local `main` ref was stale at `09e1279c`, which would have made a naive `main...HEAD` diff report 1270 changed files. The approved baseline `f5906e8b…` is `origin/main`, `git merge-base --is-ancestor f5906e8b… HEAD` returns true, and against that head the branch changes **297** files. Every count in `REGRESSION.md` is measured against the approved head, not the stale ref.

## What is recorded as not done

`REGRESSION.md` §6 states two things plainly rather than leaving them to be inferred:

- The Portuguese **capability pages** do not exist. AC-72 requires the EN/PT documentation *builds* to pass, and both do; the Portuguese book has carried no per-cycle capability page since Cycle 013, and adding one for Cycle 018 alone would leave a reader with one of six. This is a scope decision, not work reported as complete.
- No upstream standards re-verification was performed. The statuses are pinned as of this cycle and the provenance record says so in its own `reverification_note`.

`PROOF.md` closes with a "What this cycle does not establish" section for the same reason: a proof document that lists only what was shown invites the reader to assume the rest.
