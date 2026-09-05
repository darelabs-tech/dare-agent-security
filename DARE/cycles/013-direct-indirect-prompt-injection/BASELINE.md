# Cycle 013 — Compatibility Baseline

> Task: `task-001`
> Status: **DONE**
> Recorded: 2026-09-05
> Baseline branch: `main`
> Cycle 012 merge commit: `09e1279cd9ee2b2319d85272af35775b64ccba5c`
> Cycle 013 work branch head at freeze: `0bbab9d4e8734a4bd97dbf119cc5d3696a4df34a`
> Product version: `1.0.0-rc1`
> Toolchain observed: `cargo 1.94.1`

## 1. Purpose

Cycle 013 adds a bounded, evidence-first, local/offline-first Prompt Injection Validation
Engine. This document freezes the exact contracts Cycle 013 must not break, recorded before
any runtime change, so that compatibility can be proven rather than asserted at task-027.

No runtime behavior is modified by task-001.

## 2. Baseline gate state (measured before implementation)

| Gate | Command | Result |
|---|---|---|
| Build | `cargo build --workspace` | PASS |
| Test | `cargo test --workspace` | PASS — 647 tests passed, 0 failed |

The 647-test figure is the compatibility floor: Cycle 013 must not reduce it, and every
pre-existing test must remain green with unchanged semantics.

## 3. Cycle 001 — evidence and verdict semantics (frozen)

Crate: `crates/dare-security-evidence`.

Frozen contract:

```text
Verdict                 = PASS | FAIL | INCONCLUSIVE | ERROR   (SCREAMING_SNAKE wire tokens)
SecurityEvidence        = deny_unknown_fields, verdict required, no implicit default
RedactionMetadata       = mandatory on every record
ObservationSource       = PROTOCOL_RESPONSE | POLICY_ENGINE | RUNTIME_EVENT | FIXTURE
Decision                = ALLOW | DENY | RE_EVALUATE | REQUIRES_APPROVAL | NOT_APPLICABLE
schema id               = https://darelabs.tech/schemas/evidence/v1/evidence.schema.json
```

Cycle 013 constraints:

- reuse `dare_security_evidence::Verdict` — no second verdict enum;
- no new core evidence field; prompt-injection metadata goes into the namespaced
  `extensions` container or a Cycle-013-local result type that *references* evidence IDs;
- `severity` must never be inferred from verdict alone;
- credential-shaped keys remain forbidden anywhere in a record.

## 4. Cycle 006 — coverage denominator semantics (frozen)

Crate: `crates/dare-coverage`.

```text
CoverageStatus          = APPLICABLE | NOT_APPLICABLE | NOT_TESTED | OUT_OF_SCOPE | BLOCKED
CoverageStatus          is distinct from Verdict and must stay distinct
eligible/tested math    crates/dare-coverage/src/math.rs (DENOMINATOR_DOC)
applicability           closed Predicate enum only; unknown predicate => UnknownPredicate error
target-shape false      => NOT_APPLICABLE
ROE/runtime-policy false => BLOCKED (never NOT_APPLICABLE)
capability gap          => NOT_TESTED (never NOT_APPLICABLE)
```

Cycle 013 constraints:

- new predicates may be **added** to the closed enum, but no existing predicate may change
  meaning or `is_target_shape()` classification;
- the eligible/tested/denominator functions in `math.rs` must not be edited;
- adding properties to the registry must not change the property set of
  `agentic-security-baseline-2026` or `mcp-security-baseline`.

## 5. Cycle 009 — ROE, budget, kill-switch, canonicalization (frozen and reused)

Crate: `crates/dare-adversarial`.

```text
ValidationMode          = PLAN_ONLY | SIMULATED | LOCAL_SYNTHETIC | AUTHORIZED_DYNAMIC
canonical::digest       sha256 over key-sorted canonical JSON, "sha256:<hex>" form
canonical::verify_digest mismatch => AdversarialError::SafetyRefusal
kill_switch::inspect_step state change / egress / unexpected target / secret => KillTriggered
BudgetState             saturating accounting, exhaustion => BudgetExhausted (stop, never expand)
AdversarialError        Invalid | SafetyRefusal | BudgetExhausted | KillTriggered | Io | Json | Schema
```

Cycle 013 constraints:

- reuse the canonical digest form and the fail-closed refusal semantics;
- do not add prompt-injection heuristics to `ControlledRunner`;
- `LOCAL_SYNTHETIC` for Cycle 013 must go through the Cycle 009 controlled substrate,
  not a second unrestricted runner;
- `AUTHORIZED_DYNAMIC` remains unavailable to Cycle 013.

## 6. Cycle 011 — CLI/product/report contracts (frozen)

```text
dare-agent-security init | assess | report | doctor | discover | validate * | ci
validate subcommands: coaz-integrity, coverage, benchmark, attack-graph, adversarial, continuous
exit codes: 0 success | 1 scanner/internal error | 2 partial/gate failure | 3 unsupported/usage
product artifacts: .dare-security/runs/<run-id>/{summary,findings,coverage,attack-graph,validation,drift}.json
ci contract: ci-result.json (Cycle 004)
```

Cycle 013 constraints:

- `validate prompt-injection` is **added**; no existing subcommand, flag or exit meaning changes;
- `ProductViewModel` fields are `deny_unknown_fields` — prompt-injection product data must be
  additive metadata in the same style as `build_agentic_metadata`, not a new required field;
- no `--url`, `--endpoint`, `--api-key`, `--token`, `--provider-key`, `--remote`, or arbitrary
  command-string flag may be introduced for this capability.

## 7. Cycle 012 — Agentic registry, risk family, profiles (frozen)

```text
registry v2             schemas/coverage/v2/registry.json — 20 AGENT.* properties
property schema v2      schemas/coverage/v2/property.schema.json
registry schema v2      schemas/coverage/v2/registry.schema.json
RiskFamily              10 closed families; provenance requires exactly 10 and full representation
profiles                profiles/agentic-security-baseline-2026.json (10 properties)
                        profiles/mcp-security-baseline.json (v1 registry, 10 properties)
standards               standards/agentic/2026/provenance.json, mcp-crosswalk.json
```

Frozen property that Cycle 013 must preserve unchanged:

```text
AGENT.GOAL.INSTRUCTION_INTEGRITY
  risk_family = AGENT_GOAL_HIJACKING
  category    = GOAL_INTEGRITY
  predicates  = [agent_present]
  modes       = [static, passive]
  standards   = OWASP_AGENTIC_TOP10_2026 / ASI01 Agent Goal Hijacking / NORMATIVE
  maturity    = EXPERIMENTAL
```

Cycle 013 constraints:

- the two new properties are **appended**; no existing `MCP.*` or `AGENT.*` id is renamed,
  reordered in meaning, or re-scoped;
- `registry_for_profile` must keep selecting the v2 registry for `AGENT.*` profiles;
- `agentic_registry().properties.len()` rises from 20 to 22 — the two assertions that pin
  that count are the only Cycle 012 test expectations expected to change, and they change
  by addition only (existing ids still present, all 10 families still represented);
- `agentic-security-baseline-2026` keeps exactly its current 10 properties.

## 8. Known drift observed at freeze

| Item | Observation | Cycle 013 handling |
|---|---|---|
| `crates/dare-coverage/src/lib.rs` test `registry_selection_is_profile_aware` | asserts agentic registry has exactly 20 properties | update to 22 (additive); MCP registry stays 10 |
| `crates/dare-coverage/src/property.rs` test `agentic_registry_loads_and_all_families_are_represented` | asserts exactly 20 properties | update to 22 (additive); family count stays 10 |
| CI workflows | `ci.yml` and `action-e2e.yml` trigger only on `pull_request: types: [opened]` to `main` | Cycle 013 adds one job to `ci.yml`; no `push:` trigger is reintroduced |
| Untracked Cycle 011/012 state files | `.dare/state.cycle-011.json`, Cycle 012 `EXECUTION-2026-09-05.md` present on `main` working tree | out of Cycle 013 scope; not committed by this cycle |

No other drift between the planning baseline and the working tree was found.

## 9. Offline/confidential defaults frozen

```text
product offline mode    egress guard denies network class access; assess --offline must stay offline
confidential mode       redaction applied before persistence; no raw secret is written
no runtime standards fetch is required for validation
```

Cycle 013 must keep every mode (`REPLAY`, `SIMULATED`, `LOCAL_SYNTHETIC`) fully offline and
must not add any code path that can reach the network.
