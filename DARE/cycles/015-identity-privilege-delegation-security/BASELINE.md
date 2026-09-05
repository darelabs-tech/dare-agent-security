# Cycle 015 — Frozen Baseline

Recorded before any Cycle 015 implementation change. Every number here was
measured by running the stated command at the stated commit, so later movement
is comparable rather than remembered.

task-001 makes no implementation change; this document is its whole output.

## 1. Commit and environment

| Field | Value |
|---|---|
| Baseline | `main` at `2f9c02b4f4f94daa5478a0785f74814fb2d021a2` |
| Branch head at freeze | `d714f8998b55fcc75c9bb2fd1af57fb424749cbd` |
| Branch | `agent/cycle-015-identity-privilege-delegation-security` |
| `origin/main` is an ancestor of the branch | yes |
| Toolchain | `rustc 1.94.1` / `cargo 1.94.1` |
| Platform | Windows 11, `x86_64-pc-windows-msvc` |
| Date | 2026-09-05 |

## 2. Test counts

`cargo test --workspace` — **1315 passing, 0 failing**.

Per-crate counts for the crates Cycle 015 must not regress:

| Crate | Passing |
|---|---|
| `dare-coaz-integrity` (Cycle 003) | 124 |
| `dare-prompt-injection` (Cycle 013) | 271 |
| `dare-tool-security` (Cycle 014) | 276 |
| `dare-coverage` | 102 |
| `dare-mcp-lab` | 28 |
| `dare-product` | 50 |

## 3. Registries

| Registry | Properties |
|---|---|
| `schemas/coverage/v1/registry.json` | 10 |
| `schemas/coverage/v2/registry.json` | 26 |

### The two identity properties that must not change

Pinned field by field, because criteria 4 and 5 are about these exact objects.

**`AGENT.IDENTITY.DELEGATION_INTEGRITY`**

| Field | Value |
|---|---|
| `title` | Delegated identity integrity |
| `risk_family` | `IDENTITY_PRIVILEGE_ABUSE` |
| `category` | `DELEGATION` |
| `description` | Delegated authority must remain bound to the original principal, purpose and permitted scope. |
| `applicability.predicates` | `agent_present`, `delegated_identity_present` |
| `supported_modes` | `static`, `passive` |
| `evidence.required_for_confirmed_verdict` | `true` |
| `evidence.accepted_classes` | `POLICY`, `TRACE` |
| `standards` | OWASP_AGENTIC_TOP10_2026 / ASI03 Identity and Privilege Abuse / NORMATIVE |
| `maturity` | `EXPERIMENTAL` |

**`AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION`**

| Field | Value |
|---|---|
| `title` | Privilege amplification prevention |
| `risk_family` | `IDENTITY_PRIVILEGE_ABUSE` |
| `category` | `PRIVILEGE` |
| `description` | Agent-mediated execution must not gain privileges beyond the authorized principal or explicitly delegated authority. |
| `applicability.predicates` | `agent_present`, `authorization_present` |
| `supported_modes` | `static`, `passive` |
| `evidence.required_for_confirmed_verdict` | `true` |
| `evidence.accepted_classes` | `POLICY`, `TRACE`, `CONFIGURATION` |
| `standards` | OWASP_AGENTIC_TOP10_2026 / ASI03 Identity and Privilege Abuse / NORMATIVE |
| `maturity` | `EXPERIMENTAL` |

### Applicability predicates (24, closed set)

`tools_present`, `resources_present`, `prompts_present`, `transport_http`,
`transport_stdio`, `authorization_present`, `dynamic_authorization_allowed`,
`execution_integrity_supported`, `confused_deputy_supported`, `agent_present`,
`memory_present`, `rag_present`, `multi_agent_present`,
`code_execution_present`, `human_approval_present`,
`delegated_identity_present`, `external_components_present`,
`stateful_agent_present`, `runtime_dynamic_allowed`, `user_prompt_present`,
`untrusted_external_content_present`, `tool_metadata_present`,
`tool_output_present`, `tool_chaining_present`.

## 4. Profiles (4)

| Profile | Properties |
|---|---|
| `mcp-security-baseline` | 10 |
| `agentic-security-baseline-2026` | 10 |
| `prompt-injection-baseline-2026` | 3 |
| `tool-security-baseline-2026` | 6 |

Requirement levels and property sets are frozen. Cycle 015 must not alter any of
them, and must not change Cycle 006 denominator semantics in `math.rs`.

Measured overlap with the identity properties, since this is the exact thing
criteria 4, 5 and 60 protect:

| Profile | Selects | At |
|---|---|---|
| `agentic-security-baseline-2026` | `AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION` | CONDITIONAL |
| `agentic-security-baseline-2026` | `AGENT.IDENTITY.DELEGATION_INTEGRITY` | not selected |
| `mcp-security-baseline` | `MCP.IDENTITY.CONFUSED_DEPUTY` (a v1 property, unrelated) | OPTIONAL |

The new identity profile selects `PRIVILEGE_AMPLIFICATION` at REQUIRED. That is
a second profile selecting one property at a different level, which is how
per-profile requirements are meant to work — and exactly the situation
`AGENT.TOOL.AUTHORIZATION_BOUNDARY` created in Cycle 014. Both levels must be
pinned by test so neither profile can quietly adopt the other's.

## 5. Crates (13)

`dare-adversarial`, `dare-agent-security-cli`, `dare-attack-graph`,
`dare-benchmark`, `dare-coaz-integrity`, `dare-continuous`, `dare-coverage`,
`dare-mcp-discovery`, `dare-mcp-lab`, `dare-product`, `dare-prompt-injection`,
`dare-security-evidence`, `dare-tool-security`.

## 6. CLI surface (8 validate subcommands)

`coaz-integrity`, `coverage`, `benchmark`, `attack-graph`, `adversarial`,
`continuous`, `prompt-injection`, `tool-security`.

## 7. CI jobs (12)

`rust`, `lab-corpus`, `coverage-engine`, `benchmark-methodology`,
`attack-graph-mvp`, `adversarial-validation`, `continuous-validation`,
`productization-v1`, `agentic-registry-2026`, `prompt-injection-2026`,
`tool-security-2026`, `docs-build`.

Trigger block, which must survive unchanged:

```yaml
on:
  pull_request:
    branches: [main]
    types: [opened]
```

## 8. Corpora

| Corpus | Entries |
|---|---|
| `corpus/prompt-injection/v1` | 16 |
| `corpus/tool-security/v1` | 28 (+37 adversarial parser fixtures) |

## 9. Cycle 003 components to reuse, not duplicate

`crates/dare-coaz-integrity/` already implements the authorization-to-execution
binding pattern. Criterion 53 requires reuse, and criterion 18's spec is
explicit that no competing binding engine may be introduced.

| Component | Module | What Cycle 015 uses it for |
|---|---|---|
| `CanonicalValue` | `canonical.rs` | semantic normalization and digests; the reason operation comparison is not raw-byte equality |
| `CanonicalValue::normalize` / `digest` | `canonical.rs` | canonical form of authorization-relevant projections |
| `AuthorizationProjection` | `result.rs` | the shape of an authorization-relevant subset of an operation |
| `BindingMaterialV1` / `AuthorizationBinding` | `binding.rs` | binding a decision to a canonical operation identity |
| `apply_mutation` / `MutationKind` | `mutation.rs` | post-permit mutation semantics and which fields are authorization-relevant |
| `validate_verdict_consistency` | `enforcement.rs` | verdict/decision consistency |
| `validate_result_secret_safety` | `secret_safety.rs` | secret-safety gate before persistence |

The `dare-coaz-integrity` public API and its 124 tests must remain green and
unchanged in behavior.

## 10. Other reuse contracts pinned

| Cycle | Contract |
|---|---|
| 001 | `dare-security-evidence`: `Verdict`, `SecurityEvidence`, `validate`, `validate_secret_safety`, `RedactionMetadata` |
| 005 | `dare-mcp-lab` confused-deputy fixtures — 28 tests |
| 006 | `dare-coverage` denominator semantics in `math.rs` — must not be edited |
| 008 | `dare-attack-graph` synthetic principal→agent→credential→tenant topology |
| 009 | `dare-adversarial`: `kill_switch::inspect_step`, `budget_enforce::BudgetState`, `ExecutionBudget`, `ProofClass::SyntheticNoop` |
| 011 | CLI/product conventions: exit codes, `validate_output_dir`, artifact naming |
| 012 | v2 registry, 10 closed `RiskFamily` values including `IDENTITY_PRIVILEGE_ABUSE` |
| 013 | `dare-prompt-injection` engine/profile/corpus — 271 tests |
| 014 | `dare-tool-security` engine/profile/corpus — 276 tests |

## 11. Expected additive movement

Stated in advance so that any *other* movement is visible as a defect rather
than absorbed as noise.

| Item | Baseline | Expected after Cycle 015 |
|---|---|---|
| v2 registry properties | 26 | 30 (+4 `AGENT.IDENTITY.*`) |
| Profiles | 4 | 5 (+`identity-security-baseline-2026`) |
| Crates | 13 | 14 (+`dare-identity-security`) |
| CLI validate subcommands | 8 | 9 (+`identity-security`) |
| CI jobs | 12 | 13 (+`identity-security-2026`) |
| Applicability predicates | 24 | up to 28, only if implementation requires |
| Workspace tests | 1315 | strictly greater |

Nothing in the v1 registry, `math.rs`, or any existing profile may move at all.

## 12. Lessons inherited from Cycles 013 and 014

Carried forward with their reasons, because each was paid for once already.

1. **Positive PASS coverage is mandatory.** Missing evidence is `INCONCLUSIVE`,
   never `PASS`. Absence of evidence is not evidence of absence.
2. **Facts are independent.** Principal substitution, tenant crossing and
   privilege amplification can all be true in one trace; a first-match evaluator
   would report one and silently lose the others.
3. **Synthetic observations are not production evidence.** Simulated and
   local-synthetic results must be marked synthetic in every artifact.
4. **Never execute the risky action to prove the violation.** A structured
   attempted operation decides the invariant; the operation never happens.
5. **Execute the actual CI job artifact locally before opening the PR.** Cycle
   013 shipped a gate whose assertions were hand-checked rather than run;
   `scripts/run-ci-job-locally.py` exists because of it, and in Cycle 014 it
   caught four defects before CI saw them.
6. **Exact structured assertions beat substring searches.** `grep -q 'SECURE'`
   matches inside `INSECURE_INTER_AGENT_COMMUNICATION`. Use
   `scripts/assert-json.py` and `scripts/assert-text.py`, which exist for this.
7. **No raw credentials in evidence.** Identity work raises this from a
   precaution to a central requirement: synthetic descriptors, capability
   labels and digests only, never bearer tokens or secret material.

## 13. Cycle 014 residual risks carried in

Recorded in Cycle 014's `PROOF.md` §10 and still true:

1. Synthetic observations describe a reference agent, not a production one.
2. A finite corpus is coverage of its families, not of the risk in general.
3. Replay trusts its recorder for facts it cannot re-derive.
4. A `chacha20` yank notice reaches the workspace through
   `dare-mcp-discovery -> reqwest`; not a vulnerability, not reachable from the
   validation engines.
5. No live-target validation is established by any cycle so far.

Cycle 015 adds a sixth, specific to this domain and recorded now so it is not
discovered late: **the engine validates authority *models*, not identity
infrastructure.** It proves nothing about whether a real IdP issued a claim
correctly, whether a JWT verifies, or whether a live PDP is trustworthy. That
boundary belongs to Cycle 018.
