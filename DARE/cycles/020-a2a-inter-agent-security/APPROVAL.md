# Cycle 020 — Approval

**Cycle:** 020 — A2A / Inter-Agent Communication Security  
**Approval:** APPROVED  
**Approved at:** 2026-09-09  
**Base:** `main @ d2bff1d3789074dffaae45a7ce57a3563daeb1ff`  
**Planning head reviewed:** `058ca8d0ed2e7c72ee1506f29d5f7e9f976679d6`  
**Execution branch:** `agent/cycle-020-a2a-inter-agent-security`

## Approval decision

All Cycle 020 planning artifacts are approved as a single execution contract:

- `BASELINE.md`
- `DESIGN.md`
- `BLUEPRINT.md`
- `TASKS.md`
- `dare-dag.yaml`
- `dare-dag.exec.yaml`
- all `EXECUTION/task-NNN.md` evidence files required by the approved task set
- all additive implementation, test, fixture, corpus, schema, profile, CLI, CI and documentation artifacts required to satisfy the 57 approved tasks
- final `REGRESSION.md` and `PROOF.md`

No additional human approval is required between the 57 tasks while execution remains inside the frozen scope and safety boundary.

## Authorized execution

Tasks `task-001` through `task-057` are approved for execution in dependency/order discipline defined by the executable DAG.

The executor may:

- create the additive `crates/dare-a2a-security` crate;
- add local-only A2A schemas, normalized models and deterministic evaluators;
- extend the existing Agentic registry additively under `AGENT.A2A.*`;
- preserve and implement the existing `AGENT.A2A.MESSAGE_AUTHENTICITY` and `AGENT.A2A.AUTHORITY_PROPAGATION` properties;
- add the ten Cycle 020 properties proposed in `DESIGN.md` when compatibility tests prove the change is additive;
- add the `agentic-a2a-security-2026` profile;
- add the `validate a2a` CLI path with local-safe flags only;
- build the A2A-LAB and hostile/refusal corpora;
- add deterministic local adapters: STATIC, REPLAY, SIMULATED and LOCAL_SYNTHETIC;
- add the `a2a-security-2026` CI job;
- update EN/PT documentation;
- create focused tests, regression tests and proof-verification helpers needed to demonstrate the approved contracts;
- correct implementation defects discovered during execution when the correction preserves the approved semantics;
- make formatting, lint, compilation and test fixes required to keep the approved implementation green;
- generate exact execution evidence for every task.

## Frozen security boundary

Approval does **not** authorize network or state-changing expansion.

Cycle 020 remains local/offline only. The executor must not:

- connect to live A2A agents or endpoints;
- download Agent Cards from `.well-known`, registries or arbitrary URLs;
- fetch JWK/JWKS/JWS material remotely;
- acquire OAuth/OIDC tokens;
- use real API keys, passwords, bearer tokens, client secrets or private keys;
- perform live TLS/certificate validation;
- send real messages, tasks, cancellations or callbacks;
- probe or invoke real push-notification/webhook destinations;
- follow URLs found in evidence;
- execute arbitrary shell/process commands originating from analyzed evidence;
- execute/load analyzed artifacts or models;
- mutate a target application or external product state.

Endpoint, issuer, webhook, token endpoint, `jku`, key URL and Agent Card URL values imported from evidence are inert metadata.

## Frozen ownership boundaries

The executor must preserve these ownership lines:

- Cycle 001 owns common evidence/verdict/redaction primitives;
- Cycle 006 owns applicability/coverage math;
- Cycle 013 owns generalized direct/indirect prompt injection;
- Cycle 014 owns runtime tool authorization/tool misuse;
- Cycle 015 owns generalized principal/delegation/privilege/tenant identity semantics;
- Cycle 018 owns deterministic concrete-FAIL aggregation semantics;
- Cycle 019 owns AI-BOM/supply-chain and external-agent inventory semantics;
- Cycle 020 owns A2A discovery/authentication/message/authority/context/tenant/data/replay/protocol/extension/push-notification validation;
- Cycle 021 remains reserved for adaptive multi-turn adversarial execution;
- Cycle 022 remains reserved for remote authorized validation;
- Cycle 023 remains reserved for attack-path construction.

## Semantic approval rule

The executor may fix bugs but may not silently redesign an approved security contract.

If implementation would require any of the following, stop the affected task and record the discrepancy for Review instead of proceeding:

- adding live network capability;
- adding credential acquisition/use;
- changing an existing public property ID;
- changing earlier profile denominators without an explicit compatibility proof;
- weakening PASS requirements so missing/indeterminate evidence becomes PASS;
- allowing one invariant PASS to mask another concrete FAIL;
- folding A2A semantics into Cycle 013/014/015 in a way that removes their existing ownership boundaries;
- implementing Cycle 021, 022 or 023 functionality early;
- changing the approved 14-invariant meaning rather than correcting its implementation.

## Evidence requirement

Approval authorizes implementation; it does not pre-approve results.

A task is complete only when its `EXECUTION/task-NNN.md` records real executed evidence. Code existence, comments, LLM review or intended behavior are insufficient.

The final branch must produce:

- `REGRESSION.md` with exact commands/results and all discovered corrections;
- `PROOF.md` mapping every approved completion requirement to executed evidence;
- green focused tests and Cycle 012–019 compatibility regressions;
- green MCP baseline;
- green `cargo fmt --all --check`;
- green `cargo clippy --workspace --all-targets -- -D warnings`;
- green `cargo test --workspace`;
- `cargo audit` under repository policy;
- green local execution of `a2a-security-2026`;
- green EN and PT mdBook builds.

## PR rule

The implementation PR may be opened only after the final release gate is complete and evidence is committed. Preserve the repository's PR-open-only CI convention.

## Final authorization

**APPROVED FOR FULL EXECUTION.**

All 57 Cycle 020 tasks and their required artifacts may be executed by Claude Code without additional per-task approval, subject to the contracts above.