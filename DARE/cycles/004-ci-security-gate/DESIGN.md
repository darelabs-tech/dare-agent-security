# Cycle 004 — CI Security Gate

**Status:** DESIGN READY FOR REVIEW  
**Cycle:** 004  
**Name:** CI Security Gate  
**Proposed branch:** `agent/cycle-004-ci-security-gate`  
**Approval:** PENDING — do not create `APPROVAL.md` before explicit human approval.

## Context

Cycle 001 established the protocol-neutral evidence kernel.

Cycle 002 established passive MCP discovery and enterprise security baseline behavior.

Cycle 003 established authorization-to-execution integrity validation, including semantic operation binding and deterministic integrity vectors.

With those foundations merged, the next highest-leverage capability is distribution and continuous enforcement: make the existing deterministic security capabilities consumable as a GitHub Actions gate without introducing a new security-analysis engine.

The cycle deliberately does **not** begin the full Agent Attack Graph. Attack-path modeling becomes more valuable after the existing evidence, discovery, and authorization validation surfaces can run repeatably in CI.

## Problem

A security capability that only runs manually has limited adoption and weak regression protection.

Teams need to be able to express:

```text
pull request
    ->
DARE Agent Security
    ->
explicit target / safe fixture
    ->
discover / validate
    ->
machine-readable evidence
    ->
deterministic aggregate verdict
    ->
CI pass or fail
```

The CI integration must preserve the project's safety properties.

It must not turn a passive scanner into an implicitly active tester.

It must not require repository write permission.

It must not use an LLM as the final judge.

It must not silently broaden scope.

It must not leak credentials into logs, outputs, summaries, or artifacts.

## Goal

Package DARE Agent Security as a reusable, deterministic GitHub Action security gate that:

1. invokes already-delivered CLI/security capabilities rather than duplicating domain logic;
2. uses explicit inputs and explicit target scope;
3. produces stable machine-readable evidence;
4. maps aggregate verdicts to deterministic process exit behavior;
5. writes a concise GitHub job summary;
6. exposes output paths/results to later workflow steps;
7. runs safely against synthetic/local fixtures in repository CI;
8. requires no write-capable `GITHUB_TOKEN`;
9. treats active remote testing as out of scope for the default action surface.

## Product outcome

The intended public consumption direction is:

```yaml
- uses: darelabs-tech/dare-agent-security@<pinned-ref>
  with:
    mode: discover
    target: <explicit-target>
```

Cycle 004 must make the repository action-ready, but it must **not** claim a stable `v1` release or publish to GitHub Marketplace unless that release is separately approved.

## Design principles

### 1. The Action is an adapter, not a second engine

Security behavior belongs in the Rust CLI/crates.

The GitHub Action layer should only:

- parse typed action inputs;
- invoke the CLI safely;
- preserve exit semantics;
- write GitHub outputs;
- write a job summary;
- leave evidence in the mapped workspace.

Do not duplicate discovery, authorization mapping, binding, classification, or evidence logic in shell/YAML.

### 2. Deterministic CI semantics

The action must expose a documented aggregate outcome model.

At minimum:

```text
PASS
FAIL
INCONCLUSIVE
ERROR
```

The relationship between evidence verdicts, aggregate outcome, action outputs, and process exit code must be explicit and tested.

No string matching against human prose may determine CI pass/fail.

### 3. Passive by default

The default action surface must not perform adversarial mutation or state-changing operations.

For Cycle 004, CI execution should be limited to:

- passive discovery of an explicit authorized target; and/or
- deterministic local/synthetic validation supported by the merged CLI.

If the current Cycle 003 CLI exposes active-target validation, it must not become implicitly enabled by the Action.

### 4. Explicit target only

The action must never:

- enumerate hosts;
- expand scope through redirects;
- discover neighboring services;
- infer a target from repository metadata;
- reuse credentials for unrelated endpoints.

### 5. No repository write permission required

The action's core execution must work with:

```yaml
permissions:
  contents: read
```

or less, depending on the calling workflow.

The action itself must not require issue, pull-request, checks, contents-write, or security-events-write permissions.

Optional future integrations that require elevated permissions belong in later cycles.

### 6. Evidence survives CI

Evidence must be written under the GitHub workspace so the caller can upload it as a workflow artifact.

The Action should expose paths; it should not hide evidence only inside console logs.

### 7. Untrusted inputs remain data

Do not execute action inputs through `eval`, `sh -c`, generated shell, or equivalent command construction.

Targets and mode values must be passed as bounded/validated arguments.

### 8. Release is separate from implementation

Cycle completion proves that the Action is technically usable and tested.

Moving a mutable major tag, publishing Marketplace metadata, or declaring stable `v1` is a release decision outside this cycle.

## Proposed action contract

The exact names must be reconciled against the merged CLI in Task 001 before implementation.

Candidate inputs:

```text
mode
target
output-dir
fail-on-inconclusive
```

Candidate outputs:

```text
verdict
evidence-path
summary-path
```

Do not add credentials as ordinary action inputs if a standard environment/secret mechanism can be used.

Never echo secret-bearing values.

## Architecture

```text
GitHub workflow
      |
      v
action.yml
      |
      v
thin action entrypoint
      |
      v
dare-agent-security CLI
      |
      +-------------------+
      |                   |
      v                   v
discover              validate
      |                   |
      +---------+---------+
                |
                v
      deterministic evidence
                |
                v
        aggregate CI result
          /           \
         v             v
 GitHub outputs   job summary
         \             /
          +-----+-----+
                |
                v
       workspace evidence
```

## Scope

### In scope

- reconcile the real post-Cycle-003 `main`;
- freeze the Action-to-CLI contract;
- deterministic aggregate verdict and exit semantics;
- GitHub Action metadata;
- containerized or otherwise self-contained action packaging selected after Task 003 verification;
- safe entrypoint;
- evidence paths under `GITHUB_WORKSPACE`;
- GitHub outputs;
- `GITHUB_STEP_SUMMARY`;
- synthetic secure/vulnerable E2E workflow;
- untrusted-input tests;
- minimal-permission examples;
- documentation and pre-release usage example;
- project-status documentation refresh.

### Out of scope

- GitHub Marketplace publication;
- stable `v1` promise;
- moving release tags;
- SARIF/code-scanning upload;
- PR review comments;
- Check Runs;
- repository write operations;
- remote adversarial testing by default;
- production-target testing;
- full benchmark corpus;
- full Agent Attack Graph;
- enterprise control plane.

## GitHub Actions packaging direction

A Docker container action is the initial preferred candidate because the project is Rust-based and the action can ship the exact CLI/runtime it needs without depending on the consuming repository's language toolchain.

Task 003 must verify this choice against the current repository, build time, runner constraints, and action metadata requirements before implementation is locked.

If a thinner packaging strategy is demonstrably safer and faster without introducing an external runtime dependency, document the decision in the blueprint before changing direction.

## Security invariants

The following are mandatory:

- no active state-changing MCP method in default Action mode;
- no implicit host discovery;
- no redirect-based scope expansion;
- unsupported protocol semantics fail closed;
- no secret-bearing CLI/action value is printed;
- no action input is shell-evaluated;
- evidence redaction remains active;
- action result is derived from machine evidence;
- no repository write permission is necessary;
- CI tests use only synthetic/local targets;
- an intentionally vulnerable fixture can make the gate fail deterministically;
- a secure fixture can make the gate pass deterministically.

## Acceptance criteria

Cycle 004 is complete only when all of the following are proven:

1. The post-Cycle-003 CLI contract is explicitly documented.
2. A repository-local invocation of the Action succeeds against a secure synthetic fixture.
3. The Action deterministically fails against an intentionally failing fixture/vector.
4. The same evidence schema/contract used outside CI is used inside CI.
5. `PASS`, `FAIL`, `INCONCLUSIVE`, and `ERROR` aggregation semantics are tested.
6. Evidence is written to a stable workspace path.
7. Action outputs expose verdict and evidence location.
8. A job summary identifies tested scope, verdict, and evidence path without leaking secrets.
9. Inputs containing shell metacharacters are treated as data, not executed.
10. Default Action mode does not invoke active/state-changing MCP operations.
11. Example workflow uses minimum required permissions and documents pinning guidance.
12. CI E2E requires no real customer/system target.
13. Public project-status docs are reconciled with Cycles 001–003 being delivered before Cycle 004 is represented as current work.
14. No stable release/Marketplace claim is made as part of implementation completion.

## Exit gate

Before creating `APPROVAL.md`, human review must confirm:

- Cycle 004 is the correct capability to prioritize;
- GitHub Action is the desired distribution surface;
- active remote validation remains outside the default Action contract;
- SARIF/Check Runs remain deferred;
- release/tagging is a separate decision.

