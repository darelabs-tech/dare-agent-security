# Cycle 004 — Blueprint

**Status:** ARCHITECTURE PROPOSED  
**Approval:** PENDING

## Dependency statement

Cycle 004 requires the stable merged outputs of:

```text
Cycle 001 — Evidence Kernel
Cycle 002 — Passive MCP Discovery / Baseline
Cycle 003 — Authorization-to-Execution Integrity
```

Cycle 004 must not copy those implementations into the Action layer.

## First gate: reconcile `main`

The first task is mandatory because implementation names and CLI surfaces may have changed during Cycle 003.

Before touching Action code, inspect:

- workspace crates;
- CLI package and binary name;
- merged Cycle 003 commands;
- evidence output format;
- evidence schema version;
- current synthetic labs;
- current CI workflows;
- Rust MSRV/toolchain;
- README/ROADMAP project status.

If Cycle 003 acceptance is not actually present on `main`, stop and report the discrepancy.

## Component boundaries

### A. Existing domain engine

Owns:

- MCP protocol behavior;
- passive policy;
- inventory;
- classification;
- authorization projection;
- semantic normalization;
- operation binding;
- vector execution;
- evidence generation;
- redaction.

The Action must not reimplement any of these.

### B. CLI machine contract

Owns:

- selecting a supported operation;
- deterministic output directory;
- aggregate result;
- process exit semantics;
- non-interactive execution;
- machine-readable result metadata.

If the current CLI already satisfies this contract, do not create a new command merely for CI.

If a small CLI extension is necessary, prefer an additive machine-output flag/contract over a GitHub-specific domain command.

### C. GitHub Action adapter

Owns:

- Action input validation;
- CLI invocation;
- output file location;
- GitHub environment-file writes;
- job summary;
- passing through deterministic exit status.

The adapter must stay thin.

### D. Container/package boundary

Initial candidate:

```text
action metadata
    ->
container image built from repository
    ->
compiled Rust CLI
    ->
thin entrypoint
```

The final packaging choice must be verified in Task 003.

### E. CI fixture boundary

Use only synthetic/local fixtures.

Required matrix:

```text
secure fixture
  expected aggregate: PASS

vulnerable/failing fixture
  expected aggregate: FAIL

invalid configuration
  expected aggregate: ERROR

insufficient/ambiguous evidence fixture
  expected aggregate: INCONCLUSIVE
```

The workflow must explicitly assert expected outcomes rather than allowing an expected failure to look like a broken test suite.

## Candidate repository layout

Final paths must be reconciled with `main`.

```text
action.yml
action/
├── Dockerfile
└── entrypoint.sh

.github/workflows/
└── action-e2e.yml

docs/
└── github-action.md

examples/
└── github-actions/
    └── passive-discovery.yml
```

If repository conventions favor another location, preserve the conventions.

## Action input model

Keep v0 input surface intentionally small.

### `mode`

Allowed values must be enumerated from capabilities actually present on `main`.

Expected v0 direction:

```text
discover
validate
```

Do not accept arbitrary subcommands.

### `target`

Explicit target only.

Requirements:

- required for target-based discovery;
- never interpreted as shell;
- never auto-expanded;
- never redirected to a new host without the engine's explicit approved behavior.

### `output-dir`

Default to a path under `GITHUB_WORKSPACE`, such as:

```text
.dare-agent-security
```

Reject traversal outside the workspace.

### `fail-on-inconclusive`

Default should be conservative and documented.

The exact policy must be approved with Task 002.

## Aggregate outcome model

The Action requires one aggregate outcome.

Proposed precedence:

```text
ERROR > FAIL > INCONCLUSIVE > PASS
```

Example:

- any `ERROR` => aggregate `ERROR`;
- else any `FAIL` => aggregate `FAIL`;
- else any `INCONCLUSIVE` => aggregate `INCONCLUSIVE`;
- else all applicable evidence `PASS` => aggregate `PASS`.

Task 002 must validate this against Cycle 001 semantics.

Do not silently reinterpret `INCONCLUSIVE` as `PASS`.

## Exit semantics

Proposed conceptual contract:

```text
PASS         -> successful process
FAIL         -> failing process
ERROR        -> failing process
INCONCLUSIVE -> configurable, conservative default
```

Do not freeze numeric codes until Task 002 confirms existing CLI behavior.

Avoid breaking existing exit behavior.

## GitHub outputs

Candidate:

```text
verdict
evidence-path
summary-path
```

Write only non-secret values.

Use GitHub environment files rather than deprecated command syntaxes.

## Job summary

Summary should contain:

- DARE Agent Security version;
- mode;
- target identifier in redacted/safe form;
- protocol revision when known;
- aggregate verdict;
- counts by evidence verdict if available;
- evidence path;
- clear `NOT TESTED` statements.

Do not dump raw request/response bodies into the summary.

## Action permissions

The core Action must not use GitHub APIs.

Caller example should declare minimal permissions.

Expected example:

```yaml
permissions:
  contents: read
```

No `pull_request_target`.

No write token requirement.

## Supply-chain constraints

- do not curl-pipe arbitrary installers;
- do not fetch the DARE binary from an unverified moving URL inside the action;
- build/package the version contained by the referenced Action commit;
- document that consumers should pin the Action to an immutable commit SHA for high-assurance use;
- pin third-party actions in hardened examples when practical;
- do not introduce unnecessary third-party actions into the Action implementation.

## Threat model

### Untrusted PR content

A pull request can control repository files and possibly workflow-derived values.

The Action must assume:

- target values may contain metacharacters;
- filenames may be malicious;
- evidence content may contain terminal/control strings;
- MCP metadata may be attacker-controlled.

Mitigations:

- no `eval`;
- no `sh -c` with user values;
- quote all arguments;
- validate enumerations;
- canonicalize output path under workspace;
- escape/sanitize job-summary rendering;
- no execution of discovered tool names;
- no dynamic dispatch from untrusted MCP metadata.

### Secret exposure

The action must not:

- print all environment variables;
- echo bearer tokens;
- include credentials in process arguments where avoidable;
- include secret material in evidence;
- write secret values to `GITHUB_OUTPUT` or `GITHUB_STEP_SUMMARY`.

### Scope expansion

The action must not infer or enumerate additional targets.

## E2E strategy

The Action must test itself as an Action, not only its wrapper script.

At least one repository workflow should invoke:

```text
uses: ./
```

against local/synthetic fixtures.

Expected-failure tests should use workflow control deliberately and then assert the step outcome.

## Documentation

Documentation must distinguish:

```text
implemented Action
pre-release / unstable interface
released version tag
Marketplace publication
```

These are not equivalent milestones.

## Deferred architecture

Explicitly deferred:

- SARIF adapter;
- Check Runs;
- PR inline annotations/comments;
- remote staging adversarial mode;
- benchmark matrix;
- multi-target fleet scan;
- Agent Attack Graph.

