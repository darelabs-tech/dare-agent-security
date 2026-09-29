# task-019 — Append the two `AGENT.TELEMETRY` properties and the `runtime_trace_present` predicate

**Status:** DONE  
**Complexity:** MED

## Registry (`schemas/coverage/v2/registry.json`)

Two entries are appended after the 65 existing ones. The first 63 498 bytes are
unchanged; the prefix digest is `5364f9dc…`, and the bytes after the prefix start with
`,\n`. The new file digest is `052c7792…`.

| Id | Risk family / category | Predicates | Modes / evidence | Standard |
|---|---|---|---|---|
| `AGENT.TELEMETRY.CONFIDENTIALITY` | IDENTITY_PRIVILEGE_ABUSE / CREDENTIAL_BOUNDARIES | `agent_present`, `runtime_trace_present` | passive / TRACE | ASI03 |
| `AGENT.TELEMETRY.COMPLETENESS` | ROGUE_AGENTS / EVIDENCE | `agent_present`, `runtime_trace_present` | passive / TRACE | ASI10 |

The risk-family enum is closed (the ten ASI families), so the new `AGENT.TELEMETRY` id
family uses existing risk families.

## Predicate, in the four `dare-coverage` places

1. `Predicate::RuntimeTracePresent` in `property.rs`, with `as_str` and
   `is_target_shape` (false → NOT_APPLICABLE, AD-12).
2. `AssessmentFacts::runtime_trace_present` in `facts.rs` (`#[serde(default)]`).
3. The `applicability.rs` match arm.
4. The `property.schema.json` predicate enum.

The workspace builds with no other change: every `AssessmentFacts` literal already
uses `..Default::default()`.

## Engine side

- `coverage::assessment_facts` sets `runtime_trace_present`.
- Evidence records now copy `standards` from the rule's registry entry, replacing a
  separate ASI table. This also fixed a wrong mapping: B-4R's entry cites LLM08, not
  ASI06.

## Tests

`dare-coverage/tests/runtime_telemetry_properties.rs` has 7 tests:
- exactly two properties are appended, and no other `AGENT.TELEMETRY.*` exists;
- every pre-025 entry is byte-identical (the prefix rule);
- the v1 registry is unchanged;
- the predicate is in the schema and is target-shape;
- it gates both properties (true → APPLICABLE, false → NOT_APPLICABLE);
- no pre-025 property uses it, and setting it changes no earlier property's
  applicability;
- both properties are passive TRACE evidence.

`multi_turn_properties.rs` is adapted per R-7.

## Ralph Loop

| Step | Result |
|---|---|
| Build | workspace `--all-targets`: ok |
| Test | `dare-coverage` and `dare-runtime-telemetry`: all suites ok. BQ-1 pins: `dare-remote-validation --test compatibility` 8/8, `dare-agent-security --test attack_path_compatibility` 4/4 |
| Lint | `cargo fmt --check`; `cargo clippy -p dare-coverage -p dare-runtime-telemetry --all-targets -D warnings`: clean |
| Audit | No dependency change |

No engine `src/` changes; no earlier profile changes.
