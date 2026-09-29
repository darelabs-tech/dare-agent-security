# Cycle 024 — Tasks

**Status:** APPROVED FOR EXECUTION  
**Approval:** APPROVED 2026-09-29 — see `APPROVAL.md`  
**Baseline:** `main @ d125081`  
**Branch:** `claude/loving-newton-113zme`

Source of truth: `BLUEPRINT.md` (section references below).

A task is DONE only when **both** of these hold:
- its criterion is met by an executed test or command, recorded in
  `EXECUTION/task-NNN.md`;
- the Ralph Loop is green: `cargo fmt --check`, `cargo clippy -D warnings`,
  `cargo test --workspace`, and `cargo audit` when dependencies change.

Throughout the cycle:
- `dare-blast-radius` has no network, engine or `dare-attack-path` dependency, and never
  executes anything;
- no engine crate (013–022) changes;
- Cycle 023 and Cycle 008 outputs stay byte-identical (task-002 goldens, v1 goldens).

## Checklist

- [x] task-001 — Record the post-023 baseline and the ATTACK-PATH-LAB output digests
- [x] task-002 — Extract the shared lab runner and pin the ATTACK-PATH-LAB output goldens
- [ ] task-003 — Move the continuity rule to `dare_attack_graph::v2::continuity`
- [ ] task-004 — Move the output sweep and publish the label escaper
- [ ] task-005 — Create the `dare-blast-radius` crate skeleton and the manifest guard
- [ ] task-006 — Implement `limits.rs` and `error.rs`
- [ ] task-007 — Implement `admit.rs`
- [ ] task-008 — Add `schemas/blast-radius/v1/compromise.schema.json`
- [ ] task-009 — Add `blast-radius.schema.json` and the `model.rs` types
- [ ] task-010 — Implement `scenario.rs`: seed resolution, the kind table and entry-point seeding
- [ ] task-011 — Implement the reach index and the structural search
- [ ] task-012 — Add the uncontained view, the excluded edge and the total budget
- [ ] task-013 — Implement `classify.rs`: targets, exposure, routes and frontier
- [ ] task-014 — Implement `impact.rs`, the top-level frontier and totals
- [ ] task-015 — Implement the remediation delta (RF-10, SHOULD)
- [ ] task-016 — Implement `validate_blast_radius` (invariants 1–9)
- [ ] task-017 — Implement `analyze` end to end, with the determinism test
- [ ] task-018 — Add the scale test (O-08)
- [ ] task-019 — Implement the reach views (`render.rs`)
- [ ] task-020 — Implement `summary.md`
- [ ] task-021 — Add the `validate blast-radius` CLI subcommand
- [ ] task-022 — Add the CLI refusal corpus, hostile labels and double-run test
- [ ] task-023 — Build the BLAST-RADIUS-LAB harness and BRL-001..BRL-010
- [ ] task-024 — Add BRL-011..BRL-020 and the class contract
- [ ] task-025 — Add the `blast-radius-2026` CI job
- [ ] task-026 — Security, dependency, container and compatibility audit
- [ ] task-027 — Write the EN/PT blast-radius pages
- [ ] task-028 — Write REGRESSION.md and PROOF.md, run the completion gate and create the cycle archive branch

## Task table

| ID | Title | Phase | Depends on | Complexity | DONE criterion |
|---|---|---|---|---|---|
| task-001 | Record the post-023 baseline and the ATTACK-PATH-LAB output digests | 0 — Baseline | — | LOW | `BASELINE.md` records the following: `d125081`; `cargo test --workspace` suites and pass/fail/ignore counts; 23 workspace members; the 11 profile denominators and registry digests (the values Cycle 023 pins); the green PR #48 `Action E2E` run as container evidence; and the SHA-256 of each of the six `validate attack-paths` output files for each of the 26 ATTACK-PATH-LAB scenarios (156 digests), taken with the current tree |
| task-002 | Extract the shared lab runner and pin the ATTACK-PATH-LAB output goldens | 0 — Baseline | task-001 | MED | The engine and `attack-paths` runner code of `attack_path_lab.rs` moves to `tests/common/lab_runner.rs` with no behaviour change, and `attack_path_lab` still passes. `tests/attack_path_goldens.rs` asserts the 156 task-001 digests. This is BLUEPRINT §7.3, O-07 |
| task-003 | Move the continuity rule to `dare_attack_graph::v2::continuity` | 1 — Shared rules | task-002 | HIGH | `Authority` (`for_entry`, `acting`, `unset`, `component`, `step`), `discontinuity` and `MUTATION_PROPERTIES` exist in `dare_attack_graph::v2` (BLUEPRINT §5.2). `dare-attack-path/src/continuity.rs` becomes a re-export. The six C1–C6 tests move unchanged, and one `step` test per rule is added. `attack_path_goldens`, `attack_path_lab`, `paths.rs` and the Cycle 023 compatibility tests pass unchanged |
| task-004 | Move the output sweep and publish the label escaper | 1 — Shared rules | task-003 | LOW | `dare_attack_graph::v2::sweep` holds the markers and the `bearer ` rule, and `dare-attack-path/src/sweep.rs` re-exports it. `render::safe_label` becomes `pub fn escape_label`, and the v1 and v2 renderers call it. The v1 goldens, `views_label_state_in_text_and_escape_hostile_labels` and `attack_path_goldens` pass unchanged |
| task-005 | Create the `dare-blast-radius` crate skeleton and the manifest guard | 2 — Skeleton | task-004 | LOW | The crate is a workspace member with the dependencies of BLUEPRINT §2 only. `tests/manifest.rs` asserts three things: no DARE dependency other than `dare-attack-graph`, and no network, engine or `dare-attack-path` dependency; no crate other than the CLI depends on it; and no `std::net`, `std::process`, `std::thread` or `std::env` appears in `src/` |
| task-006 | Implement `limits.rs` and `error.rs` | 2 — Skeleton | task-005 | LOW | The constants equal BLUEPRINT §4.2. `Bounds::validate` refuses 0 and every value above its maximum, with one test per bound. Every `Refusal` variant of §4.1 exists. `no_error_message_echoes_input` plants a value in each input and finds it in no message |
| task-007 | Implement `admit.rs` | 2 — Skeleton | task-006 | LOW | `read_admitted` refuses a symlink, a file over its size limit (tested at limit + 1 byte), JSON 65 levels deep, and invalid UTF-8/JSON, each with its `Refusal`, and admits a valid file |
| task-008 | Add `schemas/blast-radius/v1/compromise.schema.json` | 3 — Schemas and seeds | task-005 | LOW | The schema compiles under draft 2020-12 with `additionalProperties: false`, and matches BLUEPRINT §4.3 field for field: the id patterns, `oneOf` node_id/entity_id, 1–64 seeds, and bound ranges |
| task-009 | Add `blast-radius.schema.json` and the `model.rs` types | 3 — Schemas and seeds | task-005 | MED | Every type of BLUEPRINT §4.4 exists with `deny_unknown_fields`. A hand-built golden document round-trips and validates against the schema. A schema test lists the allowed top-level and nested keys and finds no score, probability or weight field (RS-07) |
| task-010 | Implement `scenario.rs`: seed resolution, the kind table and entry-point seeding | 3 — Schemas and seeds | task-007, task-008 | MED | Every rule of BLUEPRINT §6.1 has a test, each asserting its `Refusal`: `GraphMismatch`, `UnknownSeed`, `AmbiguousSeed`, `SeedKindMismatch`, `DuplicateSeed`, `NoSeeds`. The kind × node-type table is tested in full (4 × 14). Entry-point seeding maps every entry class, counts `seeds_skipped` and `seeds_omitted`, and sorts by `(node, kind)` |
| task-011 | Implement the reach index and the structural search | 4 — Reach engine | task-003, task-006, task-010 | HIGH | `reach::search` follows BLUEPRINT §6.3 in the structural view. Tests cover: initial states per kind; one C1–C6 case per rule inside a search; `refused_steps` counted; no revisit on cycles or self-loops; `depth_cut`; `MaxStates`; and the AD-07 witness tie-break |
| task-012 | Add the uncontained view, the excluded edge and the total budget | 4 — Reach engine | task-011 | MED | The uncontained view skips exactly the edges whose `edge_control` is `Decided(PASS)`, and counts `held_edges_skipped`. Structural, `INCONCLUSIVE`, `ERROR`, unassessed and `FAIL` edges stay traversable (one test each). `excluded` skips its edge. `MaxStatesTotal` stops the search and is reported |
| task-013 | Implement `classify.rs`: targets, exposure, routes and frontier | 5 — Analysis | task-009, task-012 | HIGH | The candidates follow BLUEPRINT §6.4, including cross-tenant ones and none for a seed without a tenant (BQ-4). All three exposure states are tested. Routes carry `path_control` fields. `frontier` is non-empty for every `Contained` target. A property test over 200 fixed-seed random graphs finds 0 `Contained` targets with an uncontained route, using an independent exhaustive enumeration within `max_depth` (O-03) |
| task-014 | Implement `impact.rs`, the top-level frontier and totals | 5 — Analysis | task-013 | MED | `ImpactCounts` per view follows BLUEPRINT §6.6. `tenants_reached`, `trust_boundaries_crossed` and `privileged_credentials_acquired` are each tested on a hand-built graph. `FrontierEdge.contained_targets` and `Totals` equal a manual count |
| task-015 | Implement the remediation delta (RF-10, SHOULD) | 5 — Analysis | task-013 | MED | The candidates, their order, the 64 cap and the recount follow BLUEPRINT §6.7. On two hand-built graphs, the delta equals a manual recount. Under an exhausted budget, the entries are `partial: true` |
| task-016 | Implement `validate_blast_radius` (invariants 1–9) | 5 — Analysis | task-014, task-015 | MED | One test per invariant of BLUEPRINT §4.5, each with a doctored document refused. A valid document produced by the engine passes |
| task-017 | Implement `analyze` end to end, with the determinism test | 5 — Analysis | task-016 | MED | `analyze` wires admission, validation, seeding, both views, classification, impact, delta and document validation (BLUEPRINT §5.2). Ten shuffles of the graph's node and edge arrays give identical documents (O-06). `analyze` writes no file |
| task-018 | Add the scale test (O-08) | 5 — Analysis | task-017 | LOW | `tests/scale.rs` analyses a fixed-seed graph of 2 000 nodes, 10 000 edges and 64 seeds, in both views and with the delta, in under 10 s with `--release`. No bound is exceeded |
| task-019 | Implement the reach views (`render.rs`) | 6 — CLI, views, summary | task-004, task-017 | LOW | The views follow BLUEPRINT §5.3: reached subgraph, text tags `[seed …]`, `[exposed]`, `[contained]` and `[unknown]`, `held` and `FAIL <property>` edge labels, and `escape_label`. A hostile-label test (`"]; click`, `-->`, `<script>`) renders escaped output |
| task-020 | Implement `summary.md` | 6 — CLI, views, summary | task-017 | LOW | The sections follow BLUEPRINT §5.4, and every summary ends with the four not-claimed statements (tested). There is no time stamp |
| task-021 | Add the `validate blast-radius` CLI subcommand | 6 — CLI, views, summary | task-019, task-020 | MED | The flags match BLUEPRINT §5.1, with `--compromise` and `--seed-entry-points` exclusive and one of them required. The four files are validated and swept before any write. Exit codes 0, 1, 2 and 3 are each tested (BQ-5). The stdout line and `after_help` are as specified |
| task-022 | Add the CLI refusal corpus, hostile labels and double-run test | 6 — CLI, views, summary | task-021 | MED | Every `Refusal` reachable from the CLI exits 3, writes nothing, and echoes no planted value. `--help` offers no flag beyond §5.1. Two runs give identical bytes |
| task-023 | Build the BLAST-RADIUS-LAB harness and BRL-001..BRL-010 | 7 — Lab | task-002, task-021 | HIGH | `blast_radius_lab.rs` uses `tests/common/lab_runner.rs` to build the named APL graph through the real binary. It substitutes `${graph_id}` and `${run:N}`, runs `validate blast-radius` twice (identical bytes), validates the document, and compares with `expected.json` (BLUEPRINT §7.1). BRL-001..010 pass |
| task-024 | Add BRL-011..BRL-020 and the class contract | 7 — Lab | task-023 | HIGH | BRL-011..020 pass. BRL-017..018 show `refused_steps` ≥ 1 with the target absent. BRL-019 uses `--seed-entry-points`. BRL-020 is truncated, with `CONTAINMENT_UNKNOWN` and exit 2. The class contract holds: every attack class has a control twin; every `EXPOSED` expectation with `CONTROL_FAILED` names its property; every `CONTAINED` expectation names its frontier properties |
| task-025 | Add the `blast-radius-2026` CI job | 8 — CI | task-018, task-022, task-024 | LOW | The job runs the `dare-blast-radius` suites, `scale.rs` in release, the CLI and lab tests, `attack_path_goldens` and `attack_path_lab`. `tests/ci_job.rs` asserts the unchanged PR-open trigger, the required steps, no `secrets.*`, no URL and no new action. The job passes through `scripts/run-ci-job-locally.py` |
| task-026 | Security, dependency, container and compatibility audit | 9 — Audit | task-025 | MED | The audit covers the following: `cargo audit` is clean and `Cargo.lock` adds only `dare-blast-radius`; `scripts/k24/assert_no_real_credentials.py` (from `scripts/k23/`) is clean; the Cycle 023 compatibility tests (engine trees, registries, v1/v2 eligibility, Docker `include_str!`) pass; the builder-stage image builds; and the in-image binary exits 3 on `validate blast-radius` with a doctored graph, with networking disabled |
| task-027 | Write the EN/PT blast-radius pages | 10 — Docs and proof | task-021 | LOW | The concept page in EN and PT is linked from both `SUMMARY.md` files. The EN `commands/validate.md` and `reference/exit-codes.md` gain `validate blast-radius`. The pages state that `CONTAINED` is not "safe" and that unreached is not unreachable. Both mdBook builds are green |
| task-028 | Write REGRESSION.md and PROOF.md, run the completion gate and create the cycle archive branch | 10 — Docs and proof | task-026, task-027 | MED | Every Design item and objective O-01..O-08 maps to an executed test in `PROOF.md`, and `scripts/k24/verify_proof_citations.py` passes. The full completion gate is green. `agent/cycle-024-blast-radius-analysis` is pushed at the final cycle commit |

## Notes on the Blueprint

- **task-002** extracts the shared lab runner in phase 0, not phase 7 (BLUEPRINT §3). The
  goldens need it before the continuity move, so that the move is measured against a
  runner that is already shared.
- **task-011 and task-012** split BLUEPRINT phase 4 into the structural search and the
  view-specific rules. Each is independently testable.
