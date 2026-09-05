# Cycle 014 — Compatibility Baseline

> Task: `task-001`
> Status: **DONE**
> Recorded: 2026-09-05
> Baseline branch: `main`
> Baseline commit: `1fa9ba04e55e53e25d71621675cba9a70d174e8e`
> Cycle 014 branch head at freeze: `c938a7cc2cd81d1e1335c3862dbfef71bbf7bd90`
> Product version: `1.0.0-rc1`
> Toolchain observed: `cargo 1.94.1 (29ea6fb6a 2026-03-24)`

## 1. Purpose

Cycle 014 adds a bounded, evidence-first, local/offline-first Tool Poisoning and
Tool Misuse validation engine. This document freezes the contracts Cycle 014
must not break, measured **before** any implementation change, so that
compatibility at task-030 is proven rather than asserted.

No runtime behavior is modified by task-001.

## 2. Baseline gate state (measured before implementation)

| Gate | Command | Result |
|---|---|---|
| Build | `cargo build --workspace` | PASS |
| Test | `cargo test --workspace` | PASS — **965 passed, 0 failed** |

The 965-test figure is the compatibility floor. Cycle 014 must not reduce it and
must not weaken any pre-existing test.

## 3. Measured contract counts (frozen)

| Contract | Value at baseline |
|---|---|
| `schemas/coverage/v1/registry.json` properties | 10 |
| `schemas/coverage/v2/registry.json` properties | 22 |
| `profiles/mcp-security-baseline.json` properties | 10 |
| `profiles/agentic-security-baseline-2026.json` properties | 10 |
| `profiles/prompt-injection-baseline-2026.json` properties | 3 |
| `corpus/prompt-injection/v1/registry.json` entries | 16 |
| Workspace crates | 12 + `labs/synthetic-mcp` |
| CI jobs | 11 |

Expected Cycle 014 movement, additive only:

- v2 registry 22 → 26 (four specialized `AGENT.TOOL.*` properties);
- profiles 3 → 4 (`tool-security-baseline-2026`);
- crates + 1 (`dare-tool-security`);
- CI jobs 11 → 12 (`tool-security-2026`).

Every existing profile keeps its exact property set. No existing denominator moves.

## 4. Cycle 001 — evidence and verdict semantics (frozen)

```text
Verdict            = PASS | FAIL | INCONCLUSIVE | ERROR (SCREAMING_SNAKE wire tokens)
SecurityEvidence   = deny_unknown_fields, verdict required, no implicit default
RedactionMetadata  = mandatory on every record
ObservationSource  = PROTOCOL_RESPONSE | POLICY_ENGINE | RUNTIME_EVENT | FIXTURE
Decision           = ALLOW | DENY | RE_EVALUATE | REQUIRES_APPROVAL | NOT_APPLICABLE
verdict/decision consistency enforced by validate_verdict_consistency
```

Cycle 014 constraints: reuse `dare_security_evidence::Verdict`; no second verdict
enum; tool-specific metadata goes in the namespaced `extensions` container;
severity is never inferred from verdict alone.

## 5. Cycle 006 — coverage denominator semantics (frozen)

```text
CoverageStatus            = APPLICABLE | NOT_APPLICABLE | NOT_TESTED | OUT_OF_SCOPE | BLOCKED
math.rs                   eligible/tested/denominator functions — must not be edited
target-shape predicate false      => NOT_APPLICABLE
ROE/runtime-policy false          => BLOCKED
capability gap                    => NOT_TESTED
```

New predicates may be appended to the closed `Predicate` enum. No existing
predicate may change meaning or `is_target_shape()` classification.

## 6. Cycle 009 — ROE, budget, kill switch (frozen and reused)

```text
canonical::digest          sha256 over key-sorted canonical JSON, "sha256:<hex>"
kill_switch::inspect_step  state change / egress / target substitution / secret => KillTriggered
BudgetState                saturating accounting; exhaustion => BudgetExhausted (stop, never widen)
AdversarialError           Invalid | SafetyRefusal | BudgetExhausted | KillTriggered | Io | Json | Schema
```

Cycle 014 reuses these for `LOCAL_SYNTHETIC`. `ControlledRunner` must not gain
tool-specific heuristics, and `AUTHORIZED_DYNAMIC` remains unavailable.

## 7. Cycle 011 — CLI/product contracts (frozen)

```text
commands: init | assess | report | doctor | discover | validate * | ci
validate subcommands: coaz-integrity, coverage, benchmark, attack-graph,
                      adversarial, continuous, prompt-injection
exit codes: 0 success | 1 scanner/internal | 2 partial/gate failure | 3 unsupported/usage
```

`validate tool-security` is **added**. No existing subcommand, flag or exit
meaning changes. Product metadata is additive, in the style of
`build_agentic_metadata` and `build_prompt_injection_metadata`.

## 8. Cycle 012 — registry and risk families (frozen)

The two Tool Security properties Cycle 014 must preserve **semantically unchanged**:

```text
AGENT.TOOL.AUTHORIZATION_BOUNDARY
  title       Tool authorization boundary
  risk_family TOOL_MISUSE_EXPLOITATION
  category    TOOL_SECURITY
  predicates  [agent_present, tools_present]
  modes       [static, passive]
  evidence    required_for_confirmed_verdict = true; classes [POLICY, TRACE, STATIC]
  standards   OWASP_AGENTIC_TOP10_2026 / ASI02 Tool Misuse and Exploitation / NORMATIVE
  maturity    EXPERIMENTAL

AGENT.TOOL.OUTPUT_TRUST_BOUNDARY
  title       Tool output trust boundary
  risk_family TOOL_MISUSE_EXPLOITATION
  category    TOOL_SECURITY
  predicates  [agent_present, tools_present]
  modes       [static, passive]
  evidence    required_for_confirmed_verdict = true; classes [TRACE, STATIC]
  standards   OWASP_AGENTIC_TOP10_2026 / ASI02 Tool Misuse and Exploitation / NORMATIVE
  maturity    EXPERIMENTAL
```

Ten closed risk families remain ten. No `MCP.*` or `AGENT.*` id is renamed or
re-scoped.

## 9. Cycle 013 — prompt-injection contracts (frozen)

```text
crates/dare-prompt-injection      engine, must keep passing unchanged
profiles/prompt-injection-baseline-2026.json   3 properties
corpus/prompt-injection/v1        16 entries
schemas/prompt-injection/v1       scenario, corpus-entry, corpus-registry, transcript
CI job prompt-injection-2026      22 run-steps
```

Cycle 013 patterns Cycle 014 reuses by design (not by copy-paste where a shared
helper is cleaner): closed schema + typed second gate, hostile-field sweep,
canonical identity binding, bounded trial ledger, replay/simulated/local-synthetic
adapters, evidence bridge, bounded report wording, corpus generator script.

## 10. Cycle 013 lessons promoted to Cycle 014 constraints

Recorded here because they were real defects found by Cycle 013's own tests, and
each maps to a Cycle 014 design rule:

1. **Independent facts must not mask each other.** A field that was both
   protected and outside the expected schema emitted only one fact, letting a
   real violation pass. → Cycle 014 must emit every independently true violation
   (`task-021`, TOOL-LAB-019).
2. **Absence of evidence is not evidence of absence.** Three invariants returned
   `PASS` from "some observation happened". → Cycle 014 requires an explicit
   per-invariant positive coverage channel (`task-009`).
3. **A clean observation needs a positive coverage signal.** Clean structured
   output produced no events, making a passing run indistinguishable from an
   unobserved one. → Cycle 014 defines coverage channels explicitly rather than
   inferring them.
4. **Secret detection must scan the whole bounded value.** A bearer token was
   missed mid-string. → Cycle 014 scans full bounded values (`task-021`).
5. **CI assertions must match exact structured fields.** A bare `grep -q 'SECURE'`
   matched `INSECURE_INTER_AGENT_COMMUNICATION` and failed a healthy run. →
   Cycle 014 uses exact field assertions and must execute the real workflow job
   via `scripts/run-ci-job-locally.py` before PR open (`task-027`).

## 11. CI policy (frozen)

```yaml
on:
  pull_request:
    branches: [main]
    types: [opened]
```

`push:` trigger count at baseline: **0**. Cycle 014 adds job `tool-security-2026`
and must not restore a push trigger.

`scripts/run-ci-job-locally.py` exists on `main` and extracts a job's `run:`
steps from the workflow YAML, executing them verbatim under `bash -e`. Its use
against `tool-security-2026` is a mandatory pre-PR gate.

## 12. Offline/confidential defaults (frozen)

```text
product offline mode   egress guard denies network class access
confidential mode      redaction applied before persistence
no runtime standards fetch is required for validation
```

All three Cycle 014 modes (`REPLAY`, `SIMULATED`, `LOCAL_SYNTHETIC`) must be
fully offline. The engine crate must declare no transport dependency.

## 13. Known drift at freeze

| Item | Observation | Cycle 014 handling |
|---|---|---|
| `crates/dare-coverage` tests pinning v2 registry at 22 properties | `property.rs` and `lib.rs` assert the count | update to 26 by addition; all 22 existing ids must remain present and all 10 families represented |
| Untracked local files | `.dare/state.cycle-011.json`, Cycle 012 `EXECUTION-2026-09-05.md` | out of Cycle 014 scope; not committed |

No other drift between the approved planning baseline and the working tree was found.
