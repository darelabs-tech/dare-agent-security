# Cycle 014 — Regression Record

Every result below was produced by running the stated command on this machine at
the stated commit. Nothing here is recorded as passing because it was expected
to; anything not executed is marked as such.

## Environment

| Field | Value |
|---|---|
| Head SHA at execution | `9456abb3c8f99811c45978a25f6ffb42e870f491` |
| Branch | `agent/cycle-014-tool-poisoning-tool-misuse-validation` |
| Toolchain | `rustc 1.94.1 (e408947bf 2026-03-25)` |
| Cargo | `cargo 1.94.1 (29ea6fb6a 2026-03-24)` |
| Platform | Windows 11 (x86_64-pc-windows-msvc) |
| Local CI shell | Git Bash (`C:\Program Files\Git\bin\bash.exe`) |
| Date | 2026-09-05 |

The commits made after this record — `REGRESSION.md` and `PROOF.md` themselves —
touch documentation only and change no code, schema, fixture or workflow.

## Workspace gates

| Gate | Command | Result |
|---|---|---|
| Format | `cargo fmt --all --check` | **PASS** — exit 0, no diff |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | **PASS** — exit 0, 0 warnings, 0 errors |
| Tests | `cargo test --workspace` | **PASS** — exit 0, **1315 passing, 0 failing, 0 failed suites** |
| Audit | `cargo audit` | **PASS** — exit 0, 0 vulnerabilities, 1 allowed warning (see below) |

### `cargo audit` warning

One allowed warning, pre-existing and not introduced by this cycle:

```
Crate:   chacha20
Warning: yanked
```

It arrives transitively through `dare-mcp-discovery -> reqwest -> quinn ->
quinn-proto -> chacha20`. It is a yank notice, not a vulnerability advisory, and
no CVE is reported. `dare-tool-security` does not depend on `reqwest`, `quinn`
or any transport crate — a fact asserted by
`the_engine_declares_no_transport_or_provider_dependency` — so nothing added in
Cycle 014 contributes to it.

## Cycle 014 test suites

Each run individually with `cargo test <spec>`.

| Suite | Command | Passing |
|---|---|---|
| Engine unit tests | `-p dare-tool-security --lib` | **242** |
| Corpus integration | `-p dare-tool-security --test corpus_integration` | **12** |
| Hostile parser fixtures | `-p dare-tool-security --test hostile_fixtures` | **11** |
| Offline / confidential | `-p dare-tool-security --test offline_confidential` | **11** |
| Profile and coverage | `-p dare-coverage --test tool_security_profile` | **9** |
| Properties, additive growth | `-p dare-coverage --test tool_security_properties` | **12** |
| Product metadata | `-p dare-product --lib tool_security_metadata` | **12** |
| CLI flag surface | `-p dare-agent-security --lib tool_security` | **8** |
| CLI end-to-end matrix | `-p dare-agent-security --test tool_security_cli` | **16** |
| Product reporting bridge | `-p dare-agent-security --test tool_security_product` | **7** |
| | | **340 total** |

All ran green; none was skipped or ignored.

## Regression suites

| Cycle | Command | Result |
|---|---|---|
| 013 Prompt Injection | `cargo test -p dare-prompt-injection` | **PASS** — 271 passing |
| 013 profile | `cargo test -p dare-coverage --test prompt_injection_profile` | **PASS** — 8 passing |
| 012 Agentic registry | `cargo test -p dare-coverage --test agentic_registry` | **PASS** — 3 passing |
| 012 Agentic properties | `cargo test -p dare-coverage --test prompt_injection_properties` | **PASS** — 11 passing |
| MCP lab | `cargo test -p dare-mcp-lab` | **PASS** — 28 passing |

The MCP and Agentic coverage baselines are additionally exercised end to end
through the CLI inside the workflow job (see below), which is where their
artifacts are actually compared.

## Generated-artifact drift checks

| Check | Command | Result |
|---|---|---|
| Corpus | `python scripts/gen-tool-security-corpus.py --check` | **PASS** — 28 entries, no drift |
| Hostile fixtures | `python scripts/gen-tool-security-hostile-fixtures.py --check` | **PASS** — 37 cases, no drift |
| Scenarios and traces | `python scripts/gen-tool-security-scenarios.py --check` | **PASS** — 20 scenarios, 6 support files, no drift |

## Documentation

| Check | Command | Result |
|---|---|---|
| English book | `mdbook build book/en` | **PASS** — HTML written, no warnings |
| Portuguese book | `mdbook build book/pt` | **PASS** — HTML written, no warnings |

Cycle 014 adds two English pages, matching the Cycle 013 precedent of
English-only capability documentation. The Portuguese book is unchanged and
still builds.

## Local workflow-job execution (mandatory gate)

```
python scripts/run-ci-job-locally.py .github/workflows/ci.yml tool-security-2026
```

**Result: all 28 steps PASSED.**

This extracts the `run:` steps from the shipped `.github/workflows/ci.yml` and
executes them verbatim, so what was verified is the artifact that will run in
CI — not a hand-written approximation of it.

| # | Step | Result |
|---|---|---|
| 1 | Engine unit tests (schemas, enums, invariants, bounds, adapters) | PASS |
| 2 | Corpus, paired vectors, benign controls and false-positive regressions | PASS |
| 3 | Hostile parser fixtures fail closed | PASS |
| 4 | Offline, confidential and no-remote-tool regressions | PASS |
| 5 | Tool-security profile and coverage integration | PASS |
| 6 | Tool-security properties and standards provenance | PASS |
| 7 | Additive product metadata and bounded-claim wording | PASS |
| 8 | CLI flag surface (no remote, provider, credential or live-MCP flag) | PASS |
| 9 | CLI end-to-end matrix and product reporting bridge | PASS |
| 10 | Corpus and fixtures are generated, not hand-edited | PASS |
| 11 | Offline CLI - benign control passes | PASS |
| 12 | Offline CLI - tool poisoning vector fails deterministically | PASS |
| 13 | Offline CLI - tool misuse vector fails deterministically | PASS |
| 14 | A risky operation is observed and never dispatched | PASS |
| 15 | Absence of evidence is INCONCLUSIVE, never PASS and never FAIL | PASS |
| 16 | Independent violations are all recorded, never masked | PASS |
| 17 | Offline CLI - replay reads only a local trace | PASS |
| 18 | A poisoned or substituted corpus is refused before execution | PASS |
| 19 | Trial hard maximum is enforced and never clamped upward | PASS |
| 20 | Remote, credential and live-MCP flags do not exist | PASS |
| 21 | Report wording carries no universal tool-security claim | PASS |
| 22 | The approved bounded wording is used verbatim on a pass | PASS |
| 23 | Summaries separate poisoning from misuse and name untested surfaces | PASS |
| 24 | No artifact leaks a canary or credential | PASS |
| 25 | Prompt Injection regression (Cycle 013) | PASS |
| 26 | Agentic baseline regression (Cycle 012) | PASS |
| 27 | No untested risk family renders as SECURE | PASS |
| 28 | MCP baseline regression | PASS |

### Defects this gate caught before CI

The first local run failed 3 of 28 steps and the second failed 1. All four were
defects in assertions I had written, and none would have been visible without
executing the shipped YAML:

1. `--min-total "trials.*.violations=2"` on TOOL-LAB-019 expected two violations
   under a single invariant. That vector's independence spans several
   invariants, which one CLI run cannot show. Corrected to assert multiplicity
   on TOOL-LAB-008, where one unapproved tool genuinely crosses
   `APPROVED_TOOL_ONLY` twice.
2. Secret markers beginning with `-` (`-----BEGIN`) were parsed by argparse as
   flags. Moved into a canonical `--secret-markers` set.
3. `--count "=10"` could not address a top-level array; an empty path now names
   the document root.
4. The `cycle014-*` glob also matched the Cycle 012 and 013 regression outputs
   and demanded a tool-security scope note from them. Regression runs now write
   under `regression-*`, and the leak sweep widened to every artifact the job
   writes.

## Workflow trigger preservation

Verified by parsing the shipped YAML:

```
triggers: {'pull_request': {'branches': ['main'], 'types': ['opened']}}
jobs: 12
```

No `push:` trigger exists. The `pull_request` block is byte-identical to its
prior state; the only change to the file is the added `tool-security-2026` job.

## Not executed

Recorded so the record is honest about its own boundaries:

- **CI on PR open.** The workflow only fires on `pull_request: types: [opened]`,
  so it cannot run before the pull request exists. Its result is recorded in
  `PROOF.md` after the PR is opened.
- **Live MCP, remote provider or production target validation.** Out of scope for
  this cycle by approval, and structurally impossible in this engine.
- **Portuguese translations of the two new pages.** Following the Cycle 013
  precedent; the Portuguese book is unchanged and still builds.
