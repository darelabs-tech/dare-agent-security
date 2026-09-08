# task-008 — Implement raw-byte, component, relationship and run-wide admission ledger

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-29, AC-30, AC-64, AC-65

## Evidence

`src/budget.rs`. Every bound is an **admission** boundary, not a metric — the distinction is the module, and it is Cycle 018's most expensive lesson.

Cycle 018 shipped a ledger that counted bytes it did not bound: over-budget material was normalized, evaluated and persisted while the artifact reported a number under the ceiling. The count described a run that had not happened.

**AC-29 — bytes are admitted before anything parses.** `an_oversized_document_is_refused_before_it_is_parsed`. First in the frozen order for a reason: a 40 MB document refused *after* parsing has already been parsed, and parsing is where a graph bomb does its work.

**AC-30 — component and relationship ceilings are admission boundaries.** `the_component_ceiling_is_refused_rather_than_clamped` also asserts the snapshot still reports the admitted count, so a refused run cannot look like a smaller successful one.

**AC-65 — run-wide limits never reset.** Two tests, because the failure has two shapes:

- `input_bytes_do_not_reset_between_documents` — otherwise a document split into ten parts passes ten times over.
- `run_wide_output_totals_do_not_reset_between_trials` — only the per-trial counter resets on `begin_trial`; a run-wide counter that reset with it would be a rolling average wearing a bound's name.

**AC-64 — deep and cyclic graphs fail closed.** `a_deep_dependency_path_is_refused` here, and `a_dependency_cycle_is_refused_rather_than_walked` in `relationship.rs`.

`exhaustion_is_recorded_and_never_cleared` asserts the flag survives `begin_trial`. A run that hit a bound and carried on must still say so, or the artifact describes a clean run that was not one.
