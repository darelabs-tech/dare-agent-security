# Cycle 013 — Execution Approval

> Cycle: `013-direct-indirect-prompt-injection`
> Status: **APPROVED FOR EXECUTION**
> Approved: **2026-09-05**
> Branch: `agent/cycle-013-direct-indirect-prompt-injection`
> Baseline: Cycle 012 merged via PR #18 at `09e1279cd9ee2b2319d85272af35775b64ccba5c`

## Approval decision

The Product Owner explicitly approves Cycle 013 — Direct + Indirect Prompt Injection Validation — for implementation.

Canonical planning artifacts:

- `DESIGN.md`
- `BLUEPRINT.md`
- `TASKS.md`
- `dare-dag.yaml`

The approved scope is a bounded, evidence-first, local/offline-first Prompt Injection Validation Engine for direct and indirect prompt-injection scenarios. The engine may exercise only synthetic, replay, simulated, or otherwise explicitly local controlled paths defined by this cycle.

## Approved design decisions

The following Review Gate decisions are explicitly approved:

- properties:
  - `AGENT.GOAL.USER_INPUT_INSTRUCTION_BOUNDARY`
  - `AGENT.GOAL.EXTERNAL_CONTENT_INSTRUCTION_BOUNDARY`
- preserve `AGENT.GOAL.INSTRUCTION_INTEGRITY` unchanged;
- source classes and closed enums defined in `DESIGN.md` / `BLUEPRINT.md`;
- versioned `PromptInjectionScenario` and corpus-entry contracts;
- deterministic invariant evaluators with no LLM final judge;
- corpus scope covering direct, indirect, benign-control, and hostile parser fixtures;
- trial defaults/hard limits:
  - default trials: `3`;
  - hard maximum trials: `10`;
  - stop on first deterministic fail: enabled by default;
  - max output bytes/trial: `16384`;
  - max total output bytes: `65536`;
  - max duration/trial: `30s`;
- harness modes: `REPLAY`, `SIMULATED`, `LOCAL_SYNTHETIC`;
- `LOCAL_COMMAND` remains optional and may only be implemented if explicit argv/no-shell/root-confined/bounded-I/O safety can be proven;
- exact synthetic canary/sentinel semantics are approved;
- CLI name: `dare-agent-security validate prompt-injection`;
- report wording must describe finite tested vectors and must not claim universal Prompt Injection security;
- remote dynamic/provider execution remains deferred and unavailable in Cycle 013.

## Mandatory invariants

```text
LLM/prose is never the final security judge
PASS/FAIL requires deterministic invariant evaluation
ambiguous prose-only behavior -> INCONCLUSIVE
remote dynamic target/provider execution -> REFUSE
no arbitrary code fields in scenarios/corpus
no shell interpolation
no credential/API-key/token CLI flags
no real secrets/customer data in corpus
no state-changing action execution
no real-data exfiltration
no autonomous payload mutation/escalation
no adaptive attack loop
trial count and output/time budgets are hard bounded
first deterministic invariant violation may stop further trials
Cycle 001 evidence/verdict semantics are reused
Cycle 006 coverage denominator semantics are unchanged
Cycle 009 ROE/budget/kill-switch contracts are reused where applicable
Cycle 012 existing MCP.* and AGENT.* entries remain compatible
offline/confidential defaults remain fail closed
```

## Explicitly authorized implementation areas

- new `dare-prompt-injection` crate or an equally explicit prompt-injection module boundary;
- scenario and corpus schemas;
- trust-boundary/source enums;
- normalized observation model;
- deterministic invariant registry;
- canonical digest binding;
- bounded trial engine;
- replay and simulated adapters;
- local-synthetic integration with Cycle 009;
- direct/indirect paired corpus fixtures;
- benign controls and hostile parser fixtures;
- canary/protected-field/unauthorized-action deterministic checks;
- Cycle 001 evidence bridge;
- additive Cycle 012 registry properties/predicates;
- `prompt-injection-baseline-2026`;
- coverage integration without denominator change;
- `validate prompt-injection` CLI;
- product/report integration with bounded claims;
- offline/confidential regressions;
- dedicated Cycle 013 CI gate;
- operator/contributor documentation;
- final DARE proof.

## Explicitly excluded

This approval does **not** authorize:

- remote provider or arbitrary HTTPS model execution;
- production-target prompt-injection testing;
- API-key/token/credential handling for this engine;
- jailbreak testing unrelated to an application security invariant;
- tool-description/output poisoning (Cycle 014);
- generalized memory poisoning (Cycle 016);
- RAG poisoning/retrieval attacks (Cycle 017);
- A2A prompt injection (Cycle 020);
- multi-turn trust-grooming/adaptive attack loops (Cycle 021);
- Garak/PyRIT adapters;
- credential harvesting;
- destructive, persistent, denial-of-service, or real-data exfiltration behavior.

## Execution rules

1. Follow `dare-dag.exec.yaml` dependency order.
2. Read the applicable `EXECUTION/task-NNN.md` before modifying implementation files.
3. Preserve `DESIGN.md` and `BLUEPRINT.md`; material scope changes return to Design/Review.
4. Mark a task DONE only after its task-specific acceptance checks pass.
5. Use the Ralph Loop for implementation work: Build → Test → Lint → Review.
6. Prefer additive compatibility over destructive schema/API changes.
7. Corpus/scenario/transcript inputs are untrusted and must fail closed.
8. No runtime standards/schema fetch is required for validation.
9. Do not invent stronger payloads or wider scope when a vector is inconclusive.
10. Use synthetic canaries and synthetic structured actions only.

## Required validation baseline

Before the cycle can be marked DONE:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
```

Task-specific schema, corpus, hostile-fixture, prompt-injection, coverage, CLI, product, offline/confidential, and compatibility gates are additionally mandatory.

## GitHub Actions cost-control rule

Repository CI is configured to run test workflows only when a PR to `main` is **opened**.

Therefore execution must follow this order:

```text
implement on work branch
-> run all required gates locally
-> fix until green
-> commit/push final implementation
-> open PR only after local gates are green
-> inspect the one PR-open CI run
```

Do not rely on later pushes to an already-open PR to trigger a new CI run. If changes are required after PR opening, rerun the full gates locally and explicitly document that the PR-open CI corresponds to the earlier head.

## Completion handoff

Cycle 013 becomes DONE only after final DARE Review receives:

- all 28 task statuses;
- implementation diff;
- schema/corpus/profile artifacts;
- standards provenance;
- secure/vulnerable/benign/hostile fixture results;
- deterministic invariant evidence;
- legacy Agentic/MCP compatibility proof;
- offline/confidential proof;
- local full workspace gate results;
- PR-open CI result;
- task-028 `PROOF.md` mapping all 44 acceptance criteria to files/tests/results;
- residual risks and deviations.
