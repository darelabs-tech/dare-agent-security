# Cycle 014 — Execution Approval

> Cycle: `014-tool-poisoning-tool-misuse-validation`
> Status: **APPROVED FOR EXECUTION**
> Approved: **2026-09-05**
> Branch: `agent/cycle-014-tool-poisoning-tool-misuse-validation`
> Baseline: `main` at `1fa9ba04e55e53e25d71621675cba9a70d174e8e`

## Approval decision

The Product Owner explicitly approves all planning artifacts for DARE Cycle 014 — Tool Poisoning & Tool Misuse Validation — and authorizes execution of tasks `task-001` through `task-031` in DAG order.

Canonical approved artifacts:

- `EVALUATION.md`
- `DESIGN.md`
- `BLUEPRINT.md`
- `TASKS.md`
- `dare-dag.yaml`
- `dare-dag.exec.yaml`
- `EXECUTION/task-001.md` ... `EXECUTION/task-031.md`

Material scope expansion requires a return to Design/Review.

## Approved scope

Cycle 014 may implement bounded, evidence-first, local/offline-first validation of:

### Tool Poisoning

- tool description poisoning;
- parameter/schema semantic poisoning;
- metadata/security-annotation poisoning;
- tool-output instruction poisoning;
- tool-output trust-boundary violations;
- tool-surface identity/digest substitution;
- hidden or conflicting instructions carried by tool metadata/output.

### Tool Misuse

- unapproved tool selection;
- tool selection outside the authorized objective;
- argument substitution and dangerous-argument requests;
- parameter pollution;
- excessive invocation;
- unexpected tool chaining;
- chain-depth violations;
- output-to-action escalation;
- policy/tool mismatch.

## Approved Tool Security properties

Existing properties must remain semantically unchanged:

- `AGENT.TOOL.AUTHORIZATION_BOUNDARY`
- `AGENT.TOOL.OUTPUT_TRUST_BOUNDARY`

The following additive properties are approved:

- `AGENT.TOOL.METADATA_TRUST_BOUNDARY`
- `AGENT.TOOL.SELECTION_INTENT_BINDING`
- `AGENT.TOOL.ARGUMENT_INTEGRITY`
- `AGENT.TOOL.CHAIN_BOUNDARY`

All specialized properties belong to:

- `risk_family = TOOL_MISUSE_EXPLOITATION`
- `category = TOOL_SECURITY`

Any new applicability predicates must be closed, typed, additive and fail closed.

## Approved deterministic invariant set

The following initial evaluator set is approved:

- `TOOL_METADATA_NOT_AUTHORITATIVE`
- `APPROVED_TOOL_ONLY`
- `TOOL_SELECTION_BOUND_TO_OBJECTIVE`
- `TOOL_ARGUMENTS_PRESERVE_APPROVED_INTENT`
- `DANGEROUS_ARGUMENT_NOT_REQUESTED`
- `TOOL_OUTPUT_NOT_REINTERPRETED_AS_AUTHORITY`
- `CHAIN_WITHIN_APPROVED_SET`
- `CHAIN_DEPTH_WITHIN_BOUND`
- `INVOCATION_COUNT_WITHIN_BOUND`
- `POLICY_DENY_NOT_BYPASSED`

Final security verdicts must come from deterministic evaluators over normalized events. An LLM, model response, natural-language heuristic, embedding score, classifier guess or free-form prose is never the final security judge.

## Positive PASS coverage rule — mandatory

Cycle 013 established that absence of evidence must never become evidence of absence. Cycle 014 therefore requires invariant-specific positive coverage before `PASS`.

Examples:

- `APPROVED_TOOL_ONLY` requires `TOOL_SELECTED` or `TOOL_REQUESTED` evidence;
- selection/objective invariants require a tool-selection/request observation plus the approved objective/policy binding;
- argument invariants require `TOOL_ARGUMENTS`;
- output-trust invariants require `TOOL_OUTPUT_OBSERVED` and the relevant downstream decision/action channel;
- chain invariants require `TOOL_CHAIN_STEP`;
- policy invariants require `POLICY_DECISION`.

If the required coverage channel is absent, the result is `INCONCLUSIVE`, never `PASS`.

Independent true facts must be emitted independently. One violation classification must not mask another.

## Approved normalized observation direction

Closed typed observations may include the DESIGN-defined events, including:

- `TOOL_SURFACE_OBSERVED`
- `TOOL_SELECTED`
- `TOOL_REQUESTED`
- `TOOL_ARGUMENTS`
- `TOOL_OUTPUT_OBSERVED`
- `TOOL_CHAIN_STEP`
- `POLICY_DECISION`
- `OBJECTIVE_STATE`
- `HARNESS_ERROR`

Executable semantics may not be encoded in event payloads.

## Approved hard bounds

The following values are approved as hard security boundaries:

- `default_trials = 3`
- `hard_max_trials = 10`
- `stop_on_first_fail = true`
- `max_tool_requests_per_trial = 8`
- `hard_max_chain_depth = 3`
- `hard_max_total_tool_requests = 24`
- `max_output_bytes_per_trial = 16384`
- `max_total_output_bytes = 65536`
- `max_duration_seconds_per_trial = 30`
- `max_state_changes = 0`
- `external_egress_bytes = 0`

Inputs exceeding hard bounds must be refused. Bounds must not be silently raised or reinterpreted.

## Approved harness modes

Approved modes:

- `REPLAY`
- `SIMULATED`
- `LOCAL_SYNTHETIC`

`LOCAL_SYNTHETIC` may reuse Cycle 009 ROE/budget/kill-switch enforcement and Cycle 013 local-engine patterns.

No live MCP server, remote provider, remote model, production target, arbitrary HTTPS endpoint or real external tool execution is authorized by this cycle.

## Approved focused profile

Create `tool-security-baseline-2026` with the approved requirement direction:

- `AGENT.TOOL.AUTHORIZATION_BOUNDARY` — REQUIRED
- `AGENT.TOOL.OUTPUT_TRUST_BOUNDARY` — REQUIRED
- `AGENT.TOOL.METADATA_TRUST_BOUNDARY` — CONDITIONAL
- `AGENT.TOOL.SELECTION_INTENT_BINDING` — REQUIRED
- `AGENT.TOOL.ARGUMENT_INTEGRITY` — REQUIRED
- `AGENT.TOOL.CHAIN_BOUNDARY` — CONDITIONAL

Do not alter Cycle 006 denominator semantics or silently change existing MCP, Agentic or Prompt Injection profile requirements.

## Approved CLI

The approved command is:

`dare-agent-security validate tool-security`

Allowed bounded inputs include:

- `--scenario <path-or-id>`
- `--mode replay|simulated|local-synthetic`
- `--trace <path>` for replay;
- `--corpus <path>` under root-confined validation;
- `--trials <1..10>`;
- `--output-dir <path>`;
- `--json`.

The capability must not expose remote URL, endpoint, API-key, token, provider credential, arbitrary command string or live MCP/server execution flags.

## Approved reporting language

Finite-corpus validation must never render universal claims such as `Tool Secure`, `Safe Tools`, `immune`, `fully protected` or equivalent.

Preferred wording:

> No tool-security invariant violation was observed for the tested vectors under the recorded conditions.

Reports must distinguish Tool Poisoning from Tool Misuse and identify tested/not-tested/not-applicable surfaces plus scenario, trial, request, chain and violation counts.

## Explicitly excluded / deferred

This approval does not authorize:

- live/remote MCP tool invocation;
- real state-changing tool actions;
- real delete/send/payment/external-fetch/privilege actions;
- identity, privilege or delegation security beyond existing policy bindings (Cycle 015);
- generalized memory poisoning (Cycle 016);
- RAG poisoning/retrieval attacks (Cycle 017);
- broad agentic supply-chain/AI-BOM work (Cycle 019);
- A2A security (Cycle 020);
- adaptive multi-turn attack loops (Cycle 021);
- remote authorized dynamic validation (Cycle 022);
- credential collection or real-data exfiltration;
- arbitrary payload mutation/escalation;
- Garak/PyRIT adapters.

Structured risky operations may be represented only as synthetic/replay data. The validator must never dispatch them to a real tool.

## Execution rules

1. Execute `task-001` through `task-031` according to `dare-dag.exec.yaml`.
2. Read the applicable `EXECUTION/task-NNN.md` before modifying implementation files.
3. Use Build → Test → Lint → Review for every task.
4. Mark DONE only when task-specific acceptance evidence exists.
5. Preserve all prior-cycle public and security contracts unless an additive/versioned change is explicitly approved here.
6. Treat scenario, corpus, surface, policy, trace, transcript and tool output as untrusted input.
7. Use closed enums and `deny_unknown_fields` where applicable.
8. Bind scenario/corpus/objective/policy/tool-surface identities with canonical digests.
9. No expected-verdict field may influence the result under test.
10. No arbitrary executable field, shell interpolation or callback is permitted.
11. Unknown schema versions, predicates, properties, invariants, modes or executable fields fail closed.
12. Secret/canary values must be redacted before persistence.
13. Do not widen the attack corpus autonomously outside the approved safe synthetic classes.

## CI and GitHub Actions cost-control rule

Repository test workflows run only when a PR to `main` is opened. Preserve:

```yaml
on:
  pull_request:
    branches: [main]
    types: [opened]
```

Do not restore a `push:` trigger.

Before opening the PR, run the mandatory local release gates:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
python scripts/run-ci-job-locally.py .github/workflows/ci.yml tool-security-2026
```

Also run dedicated Cycle 014 suites plus Cycle 013 Prompt Injection, Agentic and MCP compatibility regressions.

The PR must be opened only after local gates are green. Since later pushes to an already-open PR do not automatically retrigger CI, avoid post-open commits. If a post-open correction is necessary, rerun all mandatory gates locally and document the exact head covered by the PR-open CI.

## Definition of completion

Cycle 014 becomes DONE only when:

- all 31 tasks are complete;
- all 61 DESIGN acceptance criteria are mapped to concrete evidence;
- `PROOF.md` exists;
- local mandatory gates are green;
- the actual `tool-security-2026` workflow job has passed through `scripts/run-ci-job-locally.py`;
- compatibility with Cycles 001/006/009/011/012/013 is evidenced;
- no unbounded security claim is emitted;
- residual risks/deviations are recorded;
- the final branch is pushed before the PR is opened;
- the single PR-open CI run is inspected and recorded.
