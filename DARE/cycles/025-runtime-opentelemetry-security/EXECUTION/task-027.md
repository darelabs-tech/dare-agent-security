# task-027 — Add the Cycle 023 projector for runtime telemetry (RF-15, SHOULD)

**Status:** DONE. No boundary was crossed, so there was no stop for Review.  
**Complexity:** HIGH

## Changes in `dare-attack-path`

`dare-attack-path` is the Cycle 023 crate, not an engine crate (013–022). The changes
are:

- **`ids.rs`:** `EngineSlug::RuntimeTelemetry` (`"runtime-telemetry"`); `ALL` now has 11
  entries.
- **`evidence_index.rs`:** the namespace `dare.runtime-telemetry.v1` with the key
  `property`. The engine writes `{records: [...]}`, as multi-turn does.
- **`bundle.rs`:**
  - the bundle entry `runtime-telemetry-result.json` / `runtime-telemetry-evidence.json`;
  - `RunData::RuntimeTelemetry { result: Value, policy: Option<Value> }`;
  - `bind_runtime_telemetry`:
    - the result must match `schemas/runtime-telemetry/v1/result.schema.json`;
    - `inputs/policy.json`, when present, must match `runtime-policy.schema.json`;
    - its canonical digest (sorted keys, compact, as the engine computes it) must equal
      `result.inputs.policy_digest`, or the bundle is refused with `DigestMismatch`. The
      policy is then pinned as the verified input `runtime policy`.
  - **Why JSON, not the engine types:** the result is read as schema-validated JSON,
    not decoded into the engine's types. The runtime telemetry crate stays a dependency
    of the CLI only, as its manifest test requires, and its result types do not
    implement `Deserialize`. The Cycle 022 remote result is bound the same way.
- **`guard_table.rs`:** seven roles; `ALL_ROLES` now has 35 entries.

  | Role | Guarding properties |
  |---|---|
  | `RuntimeToolCalls` | B-1, B-6 |
  | `RuntimeDestructiveCalls` | B-1, B-2, B-6 |
  | `RuntimeActsAs` | B-3 |
  | `RuntimeRetrieves` | B-4R |
  | `RuntimeMemory` | B-4M |
  | `RuntimeEgress` | B-5, B-6 |
  | `RuntimeTelemetryExport` | T-1, T-2 |

- **`project/runtime_telemetry.rs`:** the engine writes no attribute value (RS-02), so
  the traces cannot name entities. The projector takes the relationships from the bound
  policy, a pinned input, and marks them `STATICALLY_PROVEN`; the evidence records
  decide the guards.

  | Nodes | Edges and designations |
  |---|---|
  | user channel | ENTRY `UNTRUSTED_INPUT`; `TRANSFERS_TO` each agent (unguarded) |
  | each policy agent | `AUTHENTICATES_AS` its principal |
  | allowed tools | `CAN_INVOKE`; destructive tools flagged and designated `DESTRUCTIVE_CAPABILITY` |
  | egress hosts | `CAN_REACH`; designated `EXTERNAL_PUBLICATION` |
  | tenant retrieval and memory stores | `READS`, declared only when the traces observed that kind |
  | telemetry export (sensitive) | `TRANSFERS_TO`; designated `EXTERNAL_PUBLICATION` |

  Without a bound policy the run counts `RUNTIME_TELEMETRY_RESULT_ONLY` and projects
  nothing.

## Schemas

`"runtime-telemetry"` is appended to the engine enums of
`attack-graph/v2/attack-graph.schema.json`,
`attack-graph/v2/projection-report.schema.json` and
`attack-path/v1/system-model.schema.json`. Outputs embed no schema digest, so no
existing output changes.

## Fixture and tests

- **`tests/fixtures/bundles/rt/`** (68 KB) is the real CLI output over five recorded
  OTEL-LAB exports (OTL-001, 007, 014, 018, 023) and the lab policy, which is copied to
  `inputs/policy.json`. The command is recorded in `static-inputs/README.md`.
- **`projection_tables.rs::runtime_telemetry_rows`** checks:
  - every edge is `STATICALLY_PROVEN` from `input:runtime-telemetry:…`;
  - all five node types are present, with one entry and two destructive targets;
  - the approval guard is on destructive calls only;
  - B-1 FAIL guards every `CAN_INVOKE`, B-5 FAIL every `CAN_REACH`, B-3 PASS every
    `AUTHENTICATES_AS`, and B-4R FAIL the retrieval `READS`;
  - no memory store is declared, since memory was not observed;
  - T-1 and T-2 guard the export;
  - nothing is unprojected.
- **`binding.rs::a_runtime_telemetry_bundle_binds_its_policy_by_digest`** checks:
  - the policy is bound, and key order does not matter;
  - an edited policy gives `DigestMismatch`;
  - a policy outside its schema gives `InvalidDocument`;
  - without a policy the bundle projects nothing and counts result-only;
  - a result outside its schema gives `InvalidDocument`.

## Compatibility (the task's stop condition)

- `dare-attack-path`, `dare-attack-graph` and `dare-blast-radius` pass with
  `--no-fail-fast`.
- The CLI's `attack_path_goldens` (the **156 Cycle 023 goldens**), `attack_paths_cli`,
  `attack_path_compatibility`, `blast_radius_cli` and `blast_radius_lab` (BRL-001..020)
  all pass. That is 35 suites and 0 failures.
- The k23 and k24 scripts (credentials, proof citations) are clean.
- No engine `src/` changes.

## Ralph Loop

| Step | Result |
|---|---|
| Build | ok |
| Test | as above |
| Lint | fmt; clippy `-D warnings --all-targets` on `dare-attack-path` and `dare-agent-security`: clean |
| Audit | No dependency change |
