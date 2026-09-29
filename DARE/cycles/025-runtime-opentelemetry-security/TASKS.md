# Cycle 025 — Tasks

**Status:** APPROVED FOR EXECUTION  
**Approval:** APPROVED 2026-09-29 — see `APPROVAL.md`  
**Baseline:** `main @ 00e7aff`  
**Branch:** `claude/loving-newton-113zme`

Source of truth: `BLUEPRINT.md` (section references below).

A task is DONE only when **both** of these hold:
- its criterion is met by an executed test or command, recorded in
  `EXECUTION/task-NNN.md`;
- the Ralph Loop is green: `cargo fmt --check`, `cargo clippy -D warnings`,
  `cargo test --workspace`, and `cargo audit` when dependencies change.

Throughout the cycle:
- `dare-runtime-telemetry` has no network, OpenTelemetry, protobuf or async dependency, emits no telemetry and opens no port;
- no engine crate `src/` (013–022) changes; the only engine-crate edit is the BQ-1 pin test in `dare-remote-validation/tests/`;
- every pre-existing registry entry and the 11 earlier profiles stay byte-identical;
- Cycle 023/024 outputs for existing inputs stay byte-identical;
- no attribute value from an input trace reaches any artifact.

## Checklist

- [x] task-001 — Record the post-024 baseline
- [x] task-002 — Convert the registry and profile pins to the prefix rule (BQ-1)
- [x] task-003 — Pin the semantic conventions and write the mapping (BQ-2)
- [x] task-004 — Create the `dare-runtime-telemetry` crate skeleton and the manifest guards
- [x] task-005 — Implement `limits.rs` and `error.rs`
- [x] task-006 — Implement `admit.rs`
- [x] task-007 — Implement the OTLP/JSON model and the trace-subset schema
- [x] task-008 — Implement `normalize.rs` and value fingerprints (AD-07)
- [x] task-009 — Implement the semconv classifier
- [x] task-010 — Add the runtime-policy schema and loader
- [x] task-011 — Implement trace reconstruction
- [x] task-012 — Implement completeness
- [x] task-013 — Implement evaluators B-1 (tool authorization) and B-2 (approval)
- [x] task-014 — Implement evaluators B-3 (principal) and B-4 (tenant)
- [x] task-015 — Implement evaluators B-5 (egress) and B-6 (retry bound, BQ-4)
- [x] task-016 — Implement T-1 (confidentiality, BQ-3) and T-2 (completeness)
- [x] task-017 — Implement aggregation, the result type and the result schema
- [x] task-018 — Implement the evidence bridge and the coverage module
- [x] task-019 — Append the two `AGENT.TELEMETRY` properties and the `runtime_trace_present` predicate
- [ ] task-020 — Add the `runtime-telemetry-baseline-2026` profile
- [ ] task-021 — Implement `summary.md`
- [ ] task-022 — Add the `validate runtime-telemetry` CLI subcommand
- [ ] task-023 — Add the CLI refusal corpus and the double-run test
- [ ] task-024 — Build OTEL-LAB (≥ 40 entries) with the SIMULATED reference writer
- [ ] task-025 — Add the no-value-leaves, determinism and hostile tests
- [ ] task-026 — Add the scale test (O-08)
- [ ] task-027 — Add the Cycle 023 projector for runtime telemetry (RF-15, SHOULD)
- [ ] task-028 — Add the `runtime-telemetry-2026` CI job and the k25 scripts
- [ ] task-029 — Security, dependency, container and compatibility audit
- [ ] task-030 — Write the EN/PT documentation
- [ ] task-031 — Write REGRESSION.md and PROOF.md, run the completion gate and create the archive branch

## Tasks

| ID | Title | Phase | Depends on | Complexity | Acceptance criterion |
|---|---|---|---|---|---|
| task-001 | Record the post-024 baseline | 0 — Baseline | — | LOW | `BASELINE.md` records: the base commit; workspace suites and test counts; the digests of `registry.json` and the 11 profiles; the 10 engine tree digests; and that the Cycle 023 goldens (156) and BRL-001..020 pass |
| task-002 | Convert the registry and profile pins to the prefix rule (BQ-1) | 0 — Baseline | task-001 | MED | Only the pin tests change: `dare-remote-validation/tests/compatibility.rs` and `attack_path_compatibility.rs` (`the_registries_and_every_profile_are_unchanged`). Each now asserts that every pre-existing registry entry is byte-identical (by position and by digest), that the 11 earlier profiles are byte-identical, and that additions are allowed only after the last pre-existing entry. The Cycle 022 tree digest in `ENGINE_TREES` is re-pinned. No engine `src/` file changes (diff check). Both tests pass on the unchanged tree |
| task-003 | Pin the semantic conventions and write the mapping (BQ-2) | 0 — Baseline | task-001 | MED | `standards/runtime-telemetry/2026/semconv-mapping.json` and `provenance.json` record the pinned OpenTelemetry semantic-conventions release tag and every key the mapping uses (GenAI agent/model/tool, HTTP client, MCP), with the upstream source and date. Each span kind of Design §4.2 has its recognition rule |
| task-004 | Create the `dare-runtime-telemetry` crate skeleton and the manifest guards | 1 — Skeleton | task-001 | LOW | The crate is a workspace member with only the dependencies of BLUEPRINT AD-01. `tests/manifest.rs` asserts: no network, async, OpenTelemetry or protobuf crate; only the CLI depends on it; no `std::net`, `std::process`, `std::thread` or `std::env` in `src/`. The `FORBIDDEN` dependency test is present |
| task-005 | Implement `limits.rs` and `error.rs` | 1 — Skeleton | task-004 | LOW | The constants equal Design §4.3. `Bounds` is lower-only and refuses 0 and every value above its maximum (one test per bound). `no_error_message_echoes_input` holds |
| task-006 | Implement `admit.rs` | 1 — Skeleton | task-005 | LOW | Refuses a symlink, a file over 16 MiB, a total over 256 MiB, JSON 65 levels deep, and invalid UTF-8/JSON, each with its refusal (tested at limit + 1); admits a valid file |
| task-007 | Implement the OTLP/JSON model and the trace-subset schema | 2 — OTLP model | task-006 | MED | `otlp.rs` parses the OTLP JSON mapping: hex ids of the right length (uppercase refused), times given as a string or as a number, and one-of `AnyValue`, including array and kvlist. `otlp-trace-subset.schema.json` refuses unknown top-level fields. The edge cases are tested one by one |
| task-008 | Implement `normalize.rs` and value fingerprints (AD-07) | 2 — OTLP model | task-007 | MED | `NSpan` and `NValue` exist. The fingerprint is (kind, length, SHA-256 of the canonical value). A test shows that no type reachable from the evidence, findings or result builders holds a raw value (the value type is private to `normalize` and `evaluate`) |
| task-009 | Implement the semconv classifier | 2 — OTLP model | task-003, task-008 | LOW | `classify` maps each span to one `SpanKind` using the mapping only. Unknown keys go to `Unrecognized`, and the count is reported. There is one test per kind and per unrecognized case |
| task-010 | Add the runtime-policy schema and loader | 3 — Policy | task-006 | MED | `runtime-policy.schema.json` is closed and matches BLUEPRINT §3 `policy.rs`. It covers `principal_keys` and `tenant_keys` (≤ 4 each, from the allow-list), the approval event, `content_capture_allowed`, and egress host patterns (exact or `*.` suffix). The policy digest is canonical. Each refusal is tested |
| task-011 | Implement trace reconstruction | 4 — Traces | task-009 | MED | The rules of BLUEPRINT §6.2: orphans, identical duplicates (deduplicated and counted), conflicting duplicates (the trace is marked `conflict`), parent cycles (`malformed`), time inversions and the depth bound. One test each; the order of files and spans does not matter |
| task-012 | Implement completeness | 4 — Traces | task-010, task-011 | MED | BLUEPRINT §6.3: each reason of the closed enum has a test that makes the property INCONCLUSIVE, and a complete trace is marked complete |
| task-013 | Implement evaluators B-1 (tool authorization) and B-2 (approval) | 5 — Evaluators | task-012 | MED | Each has FAIL, PASS and INCONCLUSIVE tests following BLUEPRINT §5. B-2 matches the approval by tool name and timestamp ordering |
| task-014 | Implement evaluators B-3 (principal) and B-4 (tenant) | 5 — Evaluators | task-012 | MED | FAIL, PASS and INCONCLUSIVE tests each. Without policy keys → INCONCLUSIVE (`missing_key`). A delegation span legitimizes a principal change below it only |
| task-015 | Implement evaluators B-5 (egress) and B-6 (retry bound, BQ-4) | 5 — Evaluators | task-012 | MED | FAIL, PASS and INCONCLUSIVE tests each. B-5 checks `server.address` or the `url.full` host, with exact and `*.` suffix matching. B-6 counts only error-then-retry sibling groups under one parent |
| task-016 | Implement T-1 (confidentiality, BQ-3) and T-2 (completeness) | 5 — Evaluators | task-012 | MED | T-1: each marker, the bearer rule, the GenAI content keys under `content_capture_allowed: false`, and oversize values have a test; the local marker copy equals `dare_attack_graph::v2::sweep::MARKERS` (test via dev-dependency). T-2 has FAIL, PASS and INCONCLUSIVE tests |
| task-017 | Implement aggregation, the result type and the result schema | 6 — Result | task-013, task-014, task-015, task-016 | MED | AD-05 aggregation: FAIL > ERROR > INCONCLUSIVE, and PASS only with positive evidence and completeness (every combination tested). `RuntimeTelemetryResult` uses `deny_unknown_fields` and validates against `result.schema.json`. Without a policy, B-1..B-6 carry no verdict and have reason `no_runtime_policy` |
| task-018 | Implement the evidence bridge and the coverage module | 6 — Result | task-017 | MED | The records are `SecurityEvidence` with `RuntimeEvent`, `extensions["dare.runtime-telemetry.v1"]`, and pass `validate_secret_safety` and `validate`. The `ExecutionsDocument` is `passive` + `TRACE` and passes `check()`. The coverage rows follow AD-04 |
| task-019 | Append the two `AGENT.TELEMETRY` properties and the `runtime_trace_present` predicate | 7 — Registry and profile | task-002, task-018 | MED | Exactly two properties are appended to `registry.json`, and the predicate is added in the four `dare-coverage` places. `dare-coverage/tests/runtime_telemetry_properties.rs` checks: exactly two added; every pre-existing entry byte-identical; the predicate gates both; the v1 registry unchanged. The BQ-1 pin tests pass |
| task-020 | Add the `runtime-telemetry-baseline-2026` profile | 7 — Registry and profile | task-019 | LOW | The profile is registered in `profile.rs`: the const, the function, the `resolve_profile` arm and the re-export. `no_earlier_profile_denominator_moved` covers all 11 earlier profiles and adds the new one. No earlier profile selects a Cycle 025 property |
| task-021 | Implement `summary.md` | 6 — Result | task-017 | LOW | Counts, per-property verdicts with reasons, and incomplete traces with reasons. Names are neutralized (bidi, control, markup). There is no attribute value and no time stamp. The summary ends with the not-claimed statements: self-reported evidence, no authenticity, and absence is not proof |
| task-022 | Add the `validate runtime-telemetry` CLI subcommand | 8 — CLI | task-018, task-021 | MED | The flags follow BLUEPRINT §4.4, and the forbidden-flag test covers `--endpoint`, `--listen`, `--port`, `--collector`, `--otlp-endpoint`, `--header`, `--token` and `--exec`. The four files are admitted and swept before any write. Exit codes 0, 1, 2 and 3 are each tested (BQ-5) |
| task-023 | Add the CLI refusal corpus and the double-run test | 8 — CLI | task-022 | MED | Every CLI-reachable refusal exits 3, writes nothing and echoes no planted value. Two runs give byte-identical files |
| task-024 | Build OTEL-LAB (≥ 40 entries) with the SIMULATED reference writer | 9 — Lab | task-017, task-022 | HIGH | `corpus.rs` has ≥ 40 entries covering Design §4.4. The harness asserts per-class contracts (ATTACK → FAIL on its own property with the deciding span; CONTROL → PASS; GAP → INCONCLUSIVE; REFUSAL → refused). It also checks `every_attack_theme_has_a_control`, `no_fixture_states_its_own_outcome`, and that the recorded SIMULATED traces replay to the same verdict |
| task-025 | Add the no-value-leaves, determinism and hostile tests | 9 — Lab | task-024 | MED | `no_value_leaves` scans every artifact of every lab entry for every input value longer than 3 characters and finds none (O-04). `determinism` runs 10 shuffles of files and spans to byte-identical output (O-06). `hostile` covers every RF-12 fixture |
| task-026 | Add the scale test (O-08) | 9 — Lab | task-024 | LOW | 100 000 spans in 64 files are analysed in release in < 10 s, with no bound overshoot. The test is release-only, like the Cycle 024 scale test |
| task-027 | Add the Cycle 023 projector for runtime telemetry (RF-15, SHOULD) | 10 — Projector | task-024 | HIGH | `dare-attack-path` gains an `EngineSlug::RuntimeTelemetry`, the bundle entry, binding for `inputs/policy.json`, `project/runtime_telemetry.rs` and guard roles. The engine enums in the attack-graph v2 and system-model schemas gain `runtime-telemetry`. `runtime_telemetry_rows` and one bundle fixture are added. The 156 Cycle 023 goldens, ATTACK-PATH-LAB and BRL-001..020 stay unchanged. If a boundary would be crossed, stop and record for Review |
| task-028 | Add the `runtime-telemetry-2026` CI job and the k25 scripts | 11 — Delivery | task-023, task-025, task-026 | LOW | The job runs the crate, the lab, the release scale test, the CLI, the coverage tests, the BQ-1 pins, the Cycle 023/024 goldens and labs, and the k25 scripts. `tests/ci_job.rs` asserts its shape. `scripts/k25/assert_no_real_credentials.py` is clean |
| task-029 | Security, dependency, container and compatibility audit | 11 — Delivery | task-027, task-028 | MED | `cargo audit` is clean and `Cargo.lock` adds only the new crate. The k25 credential sweep is clean. Engine `src/` trees 013–022 are unchanged. The builder-stage image builds, and the in-image binary exits 3 on a doctored trace with `--network none` |
| task-030 | Write the EN/PT documentation | 11 — Delivery | task-022 | LOW | The concept page in both books covers: inputs, policy, evaluators, completeness, the no-value rule, exit codes and what is not claimed. The `validate` and exit-code references are updated. Both mdBooks build |
| task-031 | Write REGRESSION.md and PROOF.md, run the completion gate and create the archive branch | 11 — Delivery | task-029, task-030 | MED | Every Design item and O-01..O-08 maps to an executed test, and `scripts/k25/verify_proof_citations.py` passes. The full gate is green. `agent/cycle-025-runtime-opentelemetry-security` is pushed |

## Notes on the Blueprint

- **task-002** runs before any registry change, so the converted pins are proven on the unchanged tree first (BQ-1).
- **task-027** is SHOULD (Q6 (a)). If it cannot keep every existing Cycle 023/024 output byte-identical, it stops for Review rather than widening the cycle.
