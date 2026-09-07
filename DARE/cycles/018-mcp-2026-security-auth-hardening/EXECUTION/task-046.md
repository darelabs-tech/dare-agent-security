# task-046 — Dedicated CI job and real local workflow execution

**Status:** DONE - REVIEW PASS

Add `mcp-auth-security-2026` to the existing PR-open-only CI workflow. Before opening the PR, execute the real YAML job locally with `scripts/run-ci-job-locally.py`; also run fmt, clippy, workspace tests, audit and required regressions.

## Evidence

`.github/workflows/ci.yml` gains `mcp-auth-security-2026` (26 steps, 24 of them `run:` steps), inserted before `docs-build`. The workflow trigger is untouched and verified by parsing the YAML rather than by reading it: `pull_request` / `branches: [main]` / `types: [opened]`. Sixteen jobs now, and the fifteen that existed before are unchanged.

**Executed locally, for real:**

```
python scripts/run-ci-job-locally.py .github/workflows/ci.yml mcp-auth-security-2026
running 24 run-steps from .github\workflows\ci.yml:mcp-auth-security-2026
...
all 24 steps PASSED
```

The job runs the five test suites, the profile and property suites, the CLI flag-surface suite, all five generator `--check` invocations, twelve real CLI invocations asserting exit codes and structured result fields, three coverage runs against new facts fixtures, and the Cycle 001/002/003/012/017 regressions.

Three new facts fixtures under `fixtures/coverage/` make the AC-08 distinction checkable from CI rather than only from a unit test: `mcp-auth-all-surfaces.json` (everything present), `mcp-auth-controls-absent.json` (target shape present, all seven controls absent → `NOT_APPLICABLE=0`, `NOT_TESTED=10`, still 10 eligible), and `mcp-auth-legacy-revision.json` (legacy revision on stdio → `NOT_APPLICABLE=10`, 0 eligible).

## The defect this task found

The first local run failed one step, and the failure was real. **Lab 030 — a deployment that derives its acting principal from `clientInfo` — exited 0, PASS.**

The self-reported identity boundary was modelled correctly (`IdentityContext::boundary_holds`) and tested correctly, but nothing in a *run* consulted it. The fourteen invariants each judge a request, one is selected per scenario, and lab 030 selected `INBOUND_CREDENTIAL_NOT_REUSED_AS_UPSTREAM_AUTHORITY` — which genuinely held there. The lab suite caught the difference only by reading a scenario field directly, never by running the engine, so the test agreed with the fixture instead of judging it.

The consequence: an operator running `validate mcp-auth-security` against a target that had already promoted a self-reported name into an authenticated principal would get PASS, with no gap reported. That is the self-report evasion this cycle exists to refuse, and it contradicts the mandatory distinction "protocol metadata != authenticated identity".

**Fix**: `invariant::identity_boundary_violation` is checked by `run_scenario` on **every** trial, not only where a scenario selects it. It is not a fifteenth invariant — DESIGN §18 fixes the count at fourteen, and Review has passed — because promotion of self-description is a property of the identity evidence rather than of a request, and it is wrong in any scenario that carries it. If it were selectable, every scenario that did not select it would keep reporting PASS on an already-broken target.

The violation is appended to whatever the selected invariant found rather than replacing it, so a run that breaches a request-level boundary *and* this one reports both. Three regression tests cover it: the run of lab 030 now fails with a finding naming `user-7`; lab 001, whose invariant is protocol binding, fails once its identity evidence is mutated to promote a self-report; and a scenario with no self-description at all still passes, because `None` is a third answer and a target that reports no `clientInfo` has nothing to have promoted.

Exactly one of the 35 labs breaks the boundary, so this changed one verdict — from a wrong PASS to a correct FAIL.

`cargo test -p dare-mcp-auth-security`: 290 passed, 0 failed. fmt and clippy clean across the workspace.
