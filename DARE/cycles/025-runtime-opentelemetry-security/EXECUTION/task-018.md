# task-018 — Implement the evidence bridge and the coverage module

**Status:** DONE  
**Complexity:** MED

## `src/evidence_bridge.rs`

- **`build_evidence(run)`** gives one `SecurityEvidence` record per judged property, in
  `Rule::ALL` order. A property with no verdict (NOT_APPLICABLE or NOT_TESTED) gets no
  record (AD-04).
- Each record has:
  - `observed.source = RuntimeEvent`;
  - expected `Deny` / `property-holds`, and observed `Deny` (PASS), `Allow` (FAIL) or
    no decision (INCONCLUSIVE, `evidence-insufficient`), so it passes the Cycle 001
    comparator;
  - `extensions["dare.runtime-telemetry.v1"]` with the rule, property, reason, coverage,
    mode, per-trace counts, gaps, stop reason, semconv pins, and up to 64 deciding
    traces. Each deciding trace lists only its trace id, span ids, attribute keys,
    reason codes and gaps;
  - hashes of every trace file, the policy and the mapping;
  - OWASP Agentic ASI02/03/05/06/08/09 for the behaviour rules, and the pinned
    OpenTelemetry semantic conventions for T-1/T-2;
  - redaction `Remove` over attribute, event and resource values.
- Every record passes `validate_secret_safety` and `dare_security_evidence::validate`
  before it is returned. Otherwise the result is an internal error, never a partial
  record.
- **Ids:** `runtime-telemetry-<rule>-<16 hex>`, a digest of the file digests, policy
  digest, mapping digest, `max_spans` and rule. They never depend on the clock.
  `bind_evidence` writes them into `properties[].evidence_ids`, and the result schema
  now pins their shape (at most one per property).
- **Timestamps (R-6):** `started_at` and `observed_at` are the earliest start and the
  latest end of the traces that decided the verdict. If no trace decided it, they come
  from every trace, or from the Unix epoch when there are no spans. `recorded_at`
  equals `observed_at`.
- **`safe_key`:** an attribute key is written as-is only when it is a plain dotted name
  (`[A-Za-z0-9._-]`, at most 128 bytes, not starting with `eyJ`). Any other key becomes
  `key-<16 hex>`, so a key crafted to carry a credential cannot leave through a finding.

## `src/coverage.rs`

- **`assessment_facts(policy)`** sets `agent_present`, and `human_approval_present` only
  when the policy configures approval events. Nothing is inferred from span content.
  `runtime_trace_present` is added in task-019.
- **`coverage_rows(result, profile)`** gives one row per profile property:
  - the engine's state is restated as `CoverageStatus` with its verdict, evidence ids
    and a rationale (rule, reason, per-trace counts);
  - a property this engine does not decide is NOT_TESTED, never NOT_APPLICABLE;
  - there is no promotion.
- **`coverage_report`** builds the Cycle 006 report over a supplied profile. The profile
  itself arrives in task-020.
- **`executions_document(result)`** is `passive` + `TRACE` with one execution per
  property and passes `ExecutionsDocument::check()`. Before the ids are bound it is
  refused, because a verdict without an evidence id fails the check.

## Defect found and fixed in `analyze` (AD-10)

The new stability test showed that swapping the order of two trace files changed the
result. The cause was that `trace_files` kept the input order and an `index`. The fix:

- Files are still schema-checked and parsed in input order, so a refusal still names
  the first bad position.
- Files are then analysed in content-digest order, and the `file` tag used to break
  duplicate ties is that sorted position.
- `index` is dropped from `TraceFileRecord` and from the result schema. File order no
  longer changes a byte.

## Dependencies

`time = { workspace = true }` is added, as planned in R-6. It is already in the
lockfile: `Cargo.lock` gains only the dependency line under `dare-runtime-telemetry`
and no new package. `tests/manifest.rs` lists it.

## Tests: `tests/evidence.rs` (9)

- `every_verdict_gives_a_valid_runtime_event_record`: PASS, FAIL and INCONCLUSIVE
  records all validate.
- `ids_are_unique_bound_into_the_result_and_stable_across_runs`: the ids are bound
  into the result, the result schema still validates, and reordered files give
  byte-identical records.
- `timestamps_are_the_deciding_traces_span_times`
- `records_carry_no_attribute_value_and_neutralize_hostile_keys`: canary values, a
  JWT-shaped key, the tool name, the principal and the host never appear.
- `no_policy_run_records_only_the_telemetry_properties`
- `the_executions_document_is_passive_trace_evidence`
- `coverage_rows_restate_the_engine_states_without_promotion`
- `the_facts_name_only_what_the_policy_says`
- `build_and_bind_agree`

There are also 2 unit tests: `safe_key`, and the ASI mapping for every rule.

## Ralph Loop

| Step | Result |
|---|---|
| Build | `cargo build -p dare-runtime-telemetry`: ok |
| Test | `cargo test -p dare-runtime-telemetry`: 72 unit + 9 evidence + 3 manifest + 9 result, 0 failed |
| Lint | `cargo fmt --all`; `cargo clippy -p dare-runtime-telemetry --all-targets -- -D warnings`: clean |
| Audit | No new package (the workspace `time` is already locked); `cargo audit`: clean |

No engine `src/` and no registry or profile file is touched.
