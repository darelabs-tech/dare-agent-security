# Cycle 025 — Blueprint: Runtime OpenTelemetry Security

**Version:** v0.1 | **Date:** 2026-09-29 | **Status:** ARCHITECTURE PROPOSED — awaiting Review  
**Design:** `DESIGN.md` v0.2 (approved: Q1–Q6 (a), Q7 (b))  
**Base:** `main @ 00e7aff`

---

## 1. Shape

```
OTLP/JSON trace files ─┐                          ┌─> runtime-telemetry-result.json
   (1–64, admitted)    ├─> dare-runtime-telemetry ├─> runtime-telemetry-evidence.json   (SecurityEvidence + coverage)
runtime policy ────────┘   admit → normalize →    ├─> runtime-telemetry-findings.json
   (optional, closed)      reconstruct → complete │   summary.md
                           → evaluate → aggregate └─> (SHOULD) Cycle 023 projector reads the result
```

The engine is a pure function of `(trace files, policy, bounds)`. It never opens a
socket, never reads the environment, and never writes outside the output directory the
CLI validated.

---

## 2. Architecture decisions

| # | Decision | Why |
|---|---|---|
| AD-01 | New crate `crates/dare-runtime-telemetry`. Dependencies: `dare-security-evidence`, `dare-coverage`, `serde`, `serde_json`, `jsonschema`, `sha2`, `thiserror` (all already in the workspace). No OpenTelemetry, protobuf, network or async crate | Q1; RS-04, RNF-04. The Cycle 021 `FORBIDDEN` dependency test and a manifest test enforce it |
| AD-02 | OTLP/JSON is parsed with serde into the engine's own types (`ExportTraceServiceRequest` JSON mapping). This follows the OTLP JSON rules: lowerCamelCase keys, trace and span ids as hex strings, `uint64` times as decimal strings or numbers, and `AnyValue` as a one-of | Q2; no generated code. The Collector's `file` exporter writes this form |
| AD-03 | **Evidence is `TRACE` and mode is `passive`.** Coverage rows use `SupportedMode::Passive` + `EvidenceClass::Trace`, which the registry already accepts for 49 properties | Design §1; first engine to produce TRACE |
| AD-04 | **Verdicts are the four `dare_security_evidence::Verdict` values.** Where the Design says NOT_APPLICABLE (no policy, or no span of the kind), the engine gives the property **no verdict** and emits a coverage row with `CoverageStatus::NotApplicable` or `NotTested`, with the reason | The verdict enum has no NOT_APPLICABLE; this matches Cycles 018–021 |
| AD-05 | **Aggregation** (per property, then the run) follows the Cycle 021 restatement of the Cycle 018 rule: any FAIL → FAIL; else an evaluator fault → ERROR; else PASS only if every required span kind is proven complete and at least one positive observation exists; else INCONCLUSIVE | RS-06, O-02 |
| AD-06 | **Completeness is a per-trace, per-property gate** (§6.3), computed before any evaluator runs. An evaluator may return FAIL on an incomplete trace (a violation seen is real), but never PASS | R-01 |
| AD-07 | **Values never leave the parser.** Normalized attributes keep `key`, a typed **fingerprint** (kind, length, SHA-256 of the canonical value) and the value in memory only. Evaluators read values; the evidence and findings builders receive only keys, span ids, rule ids and fingerprints. A test inspects every serialized artifact of the lab for any input value | RS-02, O-04 |
| AD-08 | **The semantic-convention mapping is data.** `standards/runtime-telemetry/2026/semconv-mapping.json` is closed and versioned. It maps span kinds (§4.2 of the Design) to attribute keys and values, and records the pinned OpenTelemetry semantic-conventions release and its provenance. It is embedded with `include_str!`, and unknown keys are counted, never guessed | R-03 |
| AD-09 | **Policy-named keys.** Principal and tenant have no stable GenAI convention, so the policy names the attribute keys to read, from a closed allow-list of up to 4 keys each (for example `enduser.id`, `user.id`, `tenant.id`). Approval events are named by the policy: event name plus the attribute carrying the approved tool | R-04; no guessing |
| AD-10 | **Deterministic ordering.** Files are sorted by content digest, traces by trace id, and spans by `(start_time_unix_nano, span_id)`. Output lists are sorted by ids. File order never matters | O-06 |
| AD-11 | **Result binding.** The result records the digest of each trace file, the policy digest, the mapping digest and the bounds. `RunTag`-compatible naming (`runtime-telemetry-result.json`) lets the Cycle 023 bundle detector recognise it | RF-14, RF-15 |
| AD-12 | **Registry additions (Q4)** are two properties, `AGENT.TELEMETRY.CONFIDENTIALITY` and `AGENT.TELEMETRY.COMPLETENESS`, and one predicate, `runtime_trace_present`. They are **appended** to `registry.json`, so every existing entry stays byte-identical. The predicate is added in the four places `dare-coverage` requires. It is a target-shape predicate: false → NOT_APPLICABLE | See BQ-1 for the pins this touches |

---

## 3. Crate layout (`crates/dare-runtime-telemetry/src/`)

| Module | Contents |
|---|---|
| `limits.rs` | Design §4.3 maxima; `Bounds` (lower-only, refuses 0 and above-max) |
| `error.rs` | `TelemetryError{Refused(Refusal), Internal(&'static str)}`; position-only messages |
| `admit.rs` | File admission (symlink, size, total size, JSON depth) before parse |
| `otlp.rs` | serde model of OTLP/JSON: `ResourceSpans`, `ScopeSpans`, `Span`, `Event`, `Link`, `Status`, `AnyValue`, `KeyValue`; strict hex-id and integer-time parsing |
| `normalize.rs` | `NSpan{trace_id, span_id, parent, name, kind, start, end, status, attrs:BTreeMap<Key, NValue>, events, resource_attrs, dropped:{attrs,events,links}, file}`; `NValue` holds value + fingerprint; resource attributes merged under a separate namespace |
| `semconv.rs` | mapping loader; `classify(&NSpan) -> SpanKind{AgentInvoke, ModelCall, ToolExec, McpCall, HttpClient, Approval, Delegation, Unrecognized}` |
| `policy.rs` | runtime-policy model + schema check + digest; per-agent `{allowed_tools, destructive_tools, principal, tenant, egress_hosts, max_retries}`, `principal_keys`, `tenant_keys`, `approval:{event_name, tool_key}`, `content_capture_allowed:bool` |
| `trace.rs` | `TraceForest`: groups by trace id, builds trees; detects orphans, duplicate ids (same file and across files, identical vs conflicting), parent cycles, time inversions, depth overflow |
| `complete.rs` | completeness per trace and property (§6.3) |
| `evaluate/` | one file per evaluator: `tool_auth.rs` (B-1), `approval.rs` (B-2), `principal.rs` (B-3), `tenant.rs` (B-4), `egress.rs` (B-5), `retry.rs` (B-6), `confidentiality.rs` (T-1), `completeness.rs` (T-2) |
| `aggregate.rs` | AD-05 |
| `result.rs` | `RuntimeTelemetryResult` (`deny_unknown_fields`), `run(files, policy, bounds) -> Result<Run>`, `render_artifacts` |
| `evidence_bridge.rs` | `SecurityEvidence` records (`observed.source = RuntimeEvent`, `extensions["dare.runtime-telemetry.v1"]`), `validate_secret_safety`, `dare_security_evidence::validate` |
| `coverage.rs` | `assessment_facts()` (`runtime_trace_present = true`, plus the existing facts implied by the policy), `coverage_rows()`, `coverage_report()` |
| `corpus.rs` | OTEL-LAB entries in code (`LabEntry{id, class, theme, evaluator, build}`) and the `SIMULATED` reference trace writer |
| `summary.rs` | `summary.md` with neutralized names (bidi/control stripped, markup escaped) |

Schemas go in `schemas/runtime-telemetry/v1/`: `runtime-policy.schema.json`,
`result.schema.json` and `otlp-trace-subset.schema.json`. The last one is a closed
subset of OTLP/JSON: unknown top-level fields are refused, and unknown span fields are
ignored but counted.

---

## 4. Contracts

### 4.1 Result (`runtime-telemetry-result.json`)

```text
schema_version "1", schema_id, mode: REPLAY|SIMULATED, synthetic,
semconv: {release, mapping_digest},
inputs: {trace_files:[{digest, spans, traces}], policy_digest?},
bounds, stop_reason?,
traces: {count, complete, incomplete:[{trace_id, reasons:[…]}]},
spans: {total, by_kind:{…}, unrecognized},
properties: [{property_id, verdict?, coverage_status, reason, evidence_ids:[…]}],
verdict, redaction_state: "REDACTED", bounded_claim, generated_at
```

### 4.2 Findings (`runtime-telemetry-findings.json`)

Each finding records:
- `rule` (B-1 … T-2 plus the sub-rule id);
- `property_id` and `verdict`;
- `trace_id` and `span_ids`;
- `keys` (attribute keys involved), with `fingerprints` in place of values;
- `reason_code`, from a closed enum.

### 4.3 Exit codes

| Code | Meaning |
|---|---|
| 0 | Every judged property is PASS; everything else is NOT_APPLICABLE or NOT_TESTED |
| 2 | Any FAIL or INCONCLUSIVE |
| 3 | Refusal (admission, schema, bounds, output dir, unsafe artifact); nothing is written |
| 1 | Internal error |

### 4.4 CLI

```
dare-agent-security validate runtime-telemetry \
  --traces <FILE> [--traces <FILE> …]   (1–64)
  [--policy <FILE>]
  --output-dir <DIR>
  [--max-spans N] [--json]
```

- `--mode` is not a flag: CLI runs are always `REPLAY`, and `SIMULATED` exists only in
  the lab.
- A test asserts the absence of `--endpoint`, `--listen`, `--port`, `--collector`,
  `--otlp-endpoint`, `--header`, `--token` and `--exec`.

---

## 5. Evaluators (fixed rules)

Every evaluator runs per trace over classified spans. "Acting agent" means the nearest
ancestor `AgentInvoke` span's `gen_ai.agent.name`, or its `gen_ai.agent.id` if the
policy says so.

| # | Property | FAIL rule | PASS rule (plus completeness) |
|---|---|---|---|
| B-1 | `AGENT.TOOL.AUTHORIZATION_BOUNDARY` | a `ToolExec` span whose `gen_ai.tool.name` is not in the acting agent's `allowed_tools`, or whose acting agent is not in the policy | ≥ 1 `ToolExec` span; each has an acting agent and an allowed tool |
| B-2 | `AGENT.HUMAN_APPROVAL.INTENT_BINDING` | a `ToolExec` of a destructive tool with no `Approval` event naming the same tool whose timestamp is ≤ the tool span's start, in the same trace | ≥ 1 destructive call; each is preceded by a matching approval |
| B-3 | `AGENT.IDENTITY.PRINCIPAL_BINDING` | an agent or tool span whose principal (from `principal_keys`) differs from the trace root's, with no `Delegation` span on the path between them | the principal is present on every agent and tool span, and changes only below a delegation |
| B-4 | `AGENT.MEMORY.TENANT_BOUNDARY` (memory spans) and `AGENT.RAG.TENANT_DOCUMENT_ISOLATION` (retrieval spans) | a retrieval or memory span whose tenant (from `tenant_keys`) differs from the run's tenant | every such span carries a tenant equal to the run's |
| B-5 | `AGENT.CODE_EXECUTION.EGRESS_BOUNDARY` | an `HttpClient` span under an agent whose `server.address` (or the host of `url.full`) is not in `egress_hosts`. Matching is exact host, with optional `*.` suffix entries | every client span carries a host, and all are allowed |
| B-6 | `AGENT.FAILURE.RETRY_AMPLIFICATION` | more than `max_retries` + 1 spans of the same kind, target and operation that share a parent and end in error before success | complete traces where every group is within the bound |
| T-1 | `AGENT.TELEMETRY.CONFIDENTIALITY` | any attribute or event value matching a credential marker or bearer-token rule (§6.4); or, when `content_capture_allowed` is false, any GenAI content key present (input/output messages, system instructions, tool call arguments/result) | all attributes scanned within the bounds, and no hit |
| T-2 | `AGENT.TELEMETRY.COMPLETENESS` | a span kind the policy requires is present, but its required attributes are missing on a span | every required kind appears with its required attributes, in traces with no completeness gap |

- **Scope of B-4.** B-4 applies only to spans the mapping classifies as retrieval or
  memory operations.
- **When there is no policy.** B-1..B-6 produce no verdict and a `NotApplicable` coverage
  row (reason `no_runtime_policy`). T-1 then uses `content_capture_allowed = false`, and
  T-2 checks only structural completeness.

---

## 6. Algorithms

### 6.1 Admission and parsing

1. Admit each file: no symlink, ≤ 16 MiB, ≤ 256 MiB in total, JSON depth ≤ 64.
2. Parse into the OTLP model. On a hex-id, time or type error → `Refusal::InvalidTrace{file_index}`.
3. Enforce the span, attribute and depth maxima before insertion.

### 6.2 Reconstruction

1. Group spans by trace id.
2. Duplicate `(trace_id, span_id)` entries are handled by content:
   - byte-identical across files → deduplicated and counted;
   - conflicting → the trace is marked `conflict` (INCONCLUSIVE for every property), never
     refused.
3. Link each span to its parent:
   - a missing parent makes an `orphan` subtree;
   - a parent cycle marks the trace `malformed`.
4. A span with `end < start` is counted as a time inversion.

### 6.3 Completeness (per trace)

A trace is **complete for property P** only when all of the following hold:
- no orphan, conflict or malformed marker;
- no `dropped_attributes_count`, `dropped_events_count` or `dropped_links_count` > 0 on any
  span of a kind P reads;
- the trace root is present;
- the W3C sampled flag, where it is recorded, is set on every span;
- every span of the kinds P reads has P's required keys.

Anything else makes P INCONCLUSIVE for that trace. The reasons come from a closed enum:
`orphan`, `conflict`, `malformed`, `dropped_attributes`, `dropped_events`,
`missing_root`, `not_sampled`, `missing_key:<key>`.

### 6.4 Confidentiality scan

- Values are scanned up to 64 KiB each. A longer value is fingerprinted and flagged
  `oversize_value_unscanned` (INCONCLUSIVE for T-1 if no hit elsewhere).
- The rules are the product's markers (`dare_attack_graph::v2::sweep::MARKERS` and
  `contains_bearer_credential`), reused as a dependency-free copy with a test that keeps
  it equal. The reuse is kept as a copy (BQ-3).

### 6.5 Determinism and bounds

- AD-10 ordering applies throughout.
- A span-bound stop records `stop_reason` and makes every property INCONCLUSIVE, never
  PASS.

---

## 7. Test plan

- **Unit and property tests** (`crates/dare-runtime-telemetry/tests/`):
  - `otlp.rs`: the OTLP JSON mapping edge cases (string or number times, id case, one-of
    values);
  - `trace.rs`: orphans, duplicates, cycles;
  - `complete.rs`: one test per reason;
  - `evaluators.rs`: each B/T rule has a FAIL case, a PASS case and an INCONCLUSIVE case;
  - `no_value_leaves.rs`: every lab artifact is scanned for every input attribute value
    longer than 3 characters (O-04);
  - `determinism.rs`: 10 shuffles of files and spans give byte-identical output (O-06);
  - `hostile.rs`: RF-12;
  - `scale.rs`: 100 000 spans in 64 files, release, < 10 s (O-08);
  - `manifest.rs` and the `FORBIDDEN` dependency test.
- **OTEL-LAB** (`tests/otel_lab.rs`): ≥ 40 entries, following the Cycle 021 pattern.
  - Class contracts: ATTACK → FAIL on its own property; CONTROL → PASS; GAP →
    INCONCLUSIVE; REFUSAL → refused.
  - `every_attack_theme_has_a_control` and `no_fixture_states_its_own_outcome`.
  - `SIMULATED` traces are written by the reference writer, and a recorded copy replays
    to the same verdict.
- **Coverage** (`dare-coverage/tests/runtime_telemetry_properties.rs`):
  - exactly two properties appended and one predicate;
  - `every_pre_existing_registry_entry_is_byte_for_byte_unchanged` (by prefix);
  - `no_earlier_profile_denominator_moved`, with a new
    `runtime-telemetry-baseline-2026` entry.
- **CLI** (`dare-agent-security-cli/tests/runtime_telemetry_cli.rs`):
  - flags, forbidden flags and exit codes 0/1/2/3;
  - the refusal corpus, echoing no value;
  - a double run gives byte-identical output.
- **Projector** (RF-15, SHOULD): `dare-attack-path/tests/projection_tables.rs`
  `runtime_telemetry_rows`, plus one APL-style scenario. The 156 Cycle 023 goldens and
  the BRL lab must stay unchanged.
- **Compatibility:** engine trees 013–022 unchanged except for the pin decided in BQ-1;
  Cycle 023/024 outputs byte-identical; `dare-adversarial` / `dare-continuous` suites green.

---

## 8. Phases

| Phase | Content |
|---|---|
| 0 | Baseline and pins: record the baseline, then apply the BQ-1 decision |
| 1 | Crate skeleton: limits, errors, admission, manifest |
| 2 | OTLP model, normalization, semconv mapping |
| 3 | Policy schema and loader |
| 4 | Reconstruction and completeness |
| 5 | Evaluators B-1..B-6, T-1, T-2; aggregation |
| 6 | Result, evidence bridge, coverage, summary |
| 7 | Registry, predicate and profile additions |
| 8 | CLI, refusal corpus |
| 9 | OTEL-LAB, determinism, no-value-leaves, scale |
| 10 | Projector (SHOULD) |
| 11 | CI job, k25 scripts, docs EN/PT, audit, container, PROOF |

---

## 9. Blueprint questions for Review

1. **BQ-1: the registry and profile pins (a frozen-boundary exception).** Adding the two
   Q4 properties and the Q5 profile changes files that earlier cycles pin byte for byte:
   - `crates/dare-remote-validation/tests/compatibility.rs` (Cycle 022, **an engine
     crate**) pins `registry.json` and all 11 profiles by whole-file digest and count;
   - `crates/dare-agent-security-cli/tests/attack_path_compatibility.rs` (Cycle 023)
     does the same, and also pins the Cycle 022 crate's **tree digest**, which includes
     its tests.

   Options:
   - **(a) Recommended:** change only those pin tests from "whole file unchanged" to
     "every pre-existing entry and every earlier profile byte-identical, and the new ones
     exactly as approved". This is the prefix rule Cycle 021 already uses. Then re-pin the
     Cycle 022 tree digest. No engine source, verdict or artifact changes. This is a
     test-only exception to the "no engine crate change" boundary, recorded in APPROVAL.
   - **(b)** Keep every earlier file untouched and drop Q4/Q5. Behaviour verdicts still
     use existing properties, but telemetry confidentiality and completeness become
     findings without a property verdict, and there is no profile.
   - **(c)** Put the new properties and profile in a separate registry extension that
     `dare-coverage` loads beside `registry.json`. Nothing pinned changes, but the
     registry is split in two.
2. **BQ-2: the semantic-conventions pin.**
   - **(a) Recommended:** pin the latest released OpenTelemetry semantic-conventions
     version at execution time. task-001 records its tag and the exact GenAI, HTTP and
     MCP keys the mapping uses in `standards/runtime-telemetry/2026/provenance.json`,
     checked against the upstream release.
   - **(b)** Pin v1.37.0 as a fixed, older reference.
3. **BQ-3: reuse of the secret markers.**
   - **(a) Recommended:** a local copy in the new crate plus a test that keeps it equal
     to `dare_attack_graph::v2::sweep`. This avoids a dependency from an engine on the
     graph crate.
   - **(b)** Depend on `dare-attack-graph`.
4. **BQ-4: retry rule scope (B-6).**
   - **(a) Recommended:** count only error-then-retry sibling groups under the same
     parent.
   - **(b)** Also count retries across traces within a time window. That needs a clock
     window, which is not deterministic across exports.
5. **BQ-5: exit code for INCONCLUSIVE.**
   - **(a) Recommended:** 2, as in the engines and BQ-5 of Cycle 024. A gate never
     passes on what was not decided.
   - **(b)** 0 with a warning.
