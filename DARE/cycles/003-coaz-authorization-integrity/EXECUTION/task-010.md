# task-010 — Integrate `validate coaz-integrity` CLI

> Status: **DONE**
> Depends on: task-008, task-009

## Objective

Expose Cycle 003 through the merged CLI without changing the Cycle 002 discovery contract.

## Preferred commands

```bash
dare-agent-security validate coaz-integrity --all
dare-agent-security validate coaz-integrity --fixture COAZ-INTEGRITY-003
dare-agent-security validate coaz-integrity --all --json
dare-agent-security validate coaz-integrity --all --reference-mode vulnerable
```

Task-001 may adapt exact subcommand wiring to the merged CLI architecture while preserving these semantics.

## Requirements

- built-in synthetic fixtures only;
- no arbitrary URL/stdio target for vulnerable mode;
- `--json` emits machine JSON only to stdout;
- diagnostics stderr;
- optional evidence output directory;
- stable exit code documentation for success, vector FAIL, usage, harness error and safety refusal;
- deterministic ordering of multi-vector results.

## Tests

- help/usage;
- single fixture;
- all fixtures;
- JSON cleanliness;
- vulnerable synthetic-only guard;
- exit-code matrix.

## DONE when

A user can reproduce every Cycle 003 vector from the CLI and obtain machine-readable result/evidence artifacts.
