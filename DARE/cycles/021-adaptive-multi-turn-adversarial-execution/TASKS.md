# Cycle 021 — Tasks

**Status:** APPROVED FOR EXECUTION  
**Approval:** APPROVED 2026-09-27 — see `APPROVAL.md`  
**Baseline:** `main @ 4ca06b2`  
**Branch:** `claude/loving-newton-113zme`

Source of truth: `BLUEPRINT.md` (section references below). Each task is DONE only when its criterion is met by an executed test or command recorded in `EXECUTION/task-NNN.md`, and the Ralph Loop (`cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`, `cargo audit` when dependencies change) is green. No task may add network, credential, generation or LLM capability.

## Checklist

- [x] task-001 — Freeze post-020 baseline, test count, pinned denominators and Action image build
- [x] task-002 — Record multi-turn standards provenance snapshot
- [x] task-003 — Create `dare-multi-turn-security` crate skeleton and no-network manifest test
- [x] task-004 — Implement `limits.rs` hard maxima and lower-only `Bounds`
- [x] task-005 — Implement `ids.rs` validated identifier newtypes
- [x] task-006 — Add JSON schemas (scenario, strategy graph, transcript, result)
- [x] task-007 — Implement `source.rs`/`schema.rs` byte, depth, schema and hostile admission
- [x] task-008 — Implement `StrategyGraph` types and validation rules 1–7 and 11
- [x] task-009 — Implement acyclicity, depth and DP path count (rules 8–10)
- [x] task-010 — Implement canonical JSON and graph digest
- [x] task-011 — Implement `MultiTurnScenario` model and validation
- [x] task-012 — Implement `RawTurnOutput` normalization, canary matching and redaction
- [x] task-013 — Implement `Turn`/`ConversationState` with chained digest
- [x] task-014 — Define `ConversationAdapter` trait, `HarnessMode` and `RawHarnessError`
- [x] task-015 — Implement `ReplayAdapter` with strategy-integrity (I08) and tamper checks
- [x] task-016 — Implement `SimulatedAdapter` and all `ReferenceAgent` variants
- [x] task-017 — Implement Cycle 009-gated `LocalSyntheticAdapter`
- [x] task-018 — Implement `OutputLedger` (`admit_bytes`, `admit_turn`, `admit_output`)
- [x] task-019 — Implement conversation runner and stop reasons
- [x] task-020 — Implement invariants I01 (refusal persistence) and I02 (cumulative intent)
- [x] task-021 — Implement invariants I03 (claimed authority) and I06 (objective stability)
- [x] task-022 — Implement invariants I04 (delayed instruction) and I07 (conversation isolation)
- [x] task-023 — Implement invariant I05 (approval continuity)
- [x] task-024 — Implement result aggregation, artifact and bounded claim
- [ ] task-025 — Build MULTITURN-LAB entries 001–018 (refusal, fragmentation, grooming)
- [ ] task-026 — Build MULTITURN-LAB entries 019–040 and strategy-fault entries
- [ ] task-027 — Implement MULTITURN-LAB harness contract test
- [ ] task-028 — Implement hostile/refusal corpus tests
- [x] task-029 — Add the seven registry entries and property tests
- [x] task-030 — Add `multi-turn-security-baseline-2026` profile and denominator row
- [x] task-031 — Implement coverage facts and Cycle 001 evidence bridge
- [ ] task-032 — Add `validate multi-turn` CLI subcommand
- [ ] task-033 — Add `multi-turn-security-2026` CI job
- [ ] task-034 — Add determinism and compatibility tests (including embedded-asset locations)
- [ ] task-035 — Security, dependency and container audit
- [ ] task-036 — Write EN/PT concept and extension docs
- [ ] task-037 — Write REGRESSION.md and PROOF.md and run the completion gate

## Task table

| ID | Title | Phase | Depends on | Complexity | DONE criterion |
|---|---|---|---|---|---|
| task-001 | Freeze post-020 baseline, test count, pinned denominators and Action image build | 0 — Container baseline | — | LOW | `BASELINE.md` records `4ca06b2`, `cargo test --workspace` pass count, the 9 pinned denominators and a successful `docker build .` (or the last green `action-e2e.yml` run on `main`) |
| task-002 | Record multi-turn standards provenance snapshot | 11 — Docs & proof | task-001 | LOW | `standards/multi-turn-security/2026/provenance.json` lists ASI01/03/06/09 references with version/date; JSON validates |
| task-003 | Create `dare-multi-turn-security` crate skeleton and no-network manifest test | 1 — Baseline & skeleton | task-001 | LOW | crate is a workspace member; `lib.rs` documents rules and boundaries; `this_crate_declares_no_network_dependency_of_its_own` passes and fails when an HTTP/RNG/LLM dependency is added |
| task-004 | Implement `limits.rs` hard maxima and lower-only `Bounds` | 1 — Baseline & skeleton | task-003 | LOW | every constant of Blueprint §4.1 exists; `Bounds` above a maximum returns `BoundRaised`; 1..=max accepted |
| task-005 | Implement `ids.rs` validated identifier newtypes | 1 — Baseline & skeleton | task-003 | LOW | regex `^[a-z0-9][a-z0-9._-]{0,63}$` enforced via `TryFrom<String>`; bidi/control/uppercase/empty/65-char ids rejected without echoing the value |
| task-006 | Add JSON schemas (scenario, strategy graph, transcript, result) | 2 — Schemas & admission | task-004, task-005 | MED | four schemas under `schemas/multi-turn-security/v1/` self-validate; embedded copies equal the files; unknown fields rejected |
| task-007 | Implement `source.rs`/`schema.rs` byte, depth, schema and hostile admission | 2 — Schemas & admission | task-004, task-005, task-006 | MED | files > 4 MiB, depth > 32, unknown fields, bidi/control ids and secret-like content are refused with their named `MultiTurnError` before domain parsing |
| task-008 | Implement `StrategyGraph` types and validation rules 1–7 and 11 | 3 — Strategy graph | task-005, task-007 | MED | one failing test per rule (version, limits, duplicate/unknown node, duplicate transition, `UNCLASSIFIABLE` edge, terminal/dead-end, unreachable, approval/role mismatch) |
| task-009 | Implement acyclicity, depth and DP path count (rules 8–10) | 3 — Strategy graph | task-008 | MED | cycle reports smallest remaining id; depth > 32 and paths > 64 refused; path count equals hand-computed value on 5 graphs; saturating arithmetic tested |
| task-010 | Implement canonical JSON and graph digest | 3 — Strategy graph | task-008 | LOW | `sha256:`-prefixed digest stable across 10 runs and across field-order permutations of the input file |
| task-011 | Implement `MultiTurnScenario` model and validation | 4 — Conversation & observation | task-008, task-010 | MED | field bounds, digest resolution, unknown canary, duplicate token and inapplicable primary invariant each fail with their error |
| task-012 | Implement `RawTurnOutput` normalization, canary matching and redaction | 4 — Conversation & observation | task-011 | HIGH | one test per row of Blueprint §4.7 precedence table; canary substring/case variant is not a hit; excerpt ≤ 256 chars with `[CANARY:<id>]`; oversize output becomes a harness error |
| task-013 | Implement `Turn`/`ConversationState` with chained digest | 4 — Conversation & observation | task-012 | MED | chain seed and recomputation tested; out-of-order push is `StrategyFault`; raw content never stored |
| task-014 | Define `ConversationAdapter` trait, `HarnessMode` and `RawHarnessError` | 5 — Adapters | task-013 | LOW | trait compiles with the Blueprint §4.9 signature; closed enums serialize in `SCREAMING_SNAKE_CASE` |
| task-015 | Implement `ReplayAdapter` with strategy-integrity (I08) and tamper checks | 5 — Adapters | task-014 | HIGH | reordered, inserted, dropped and unconsumed turns yield `StrategyFault`; chain mismatch refused as `TranscriptTampered` |
| task-016 | Implement `SimulatedAdapter` and all `ReferenceAgent` variants | 5 — Adapters | task-014 | HIGH | each variant in Blueprint §4.9 has a behaviour test over a fixed graph; state is per conversation id and persists across conversations |
| task-017 | Implement Cycle 009-gated `LocalSyntheticAdapter` | 5 — Adapters | task-016 | MED | every turn passes `inspect_step` and `BudgetState`; snapshot shows 0 state changes and 0 egress; a kill trigger yields ERROR; budget exhaustion yields `BUDGET_EXHAUSTED` |
| task-018 | Implement `OutputLedger` (`admit_bytes`, `admit_turn`, `admit_output`) | 6 — Runner & invariants | task-004 | MED | over-budget output refused before write; the result artifact's own bytes are charged |
| task-019 | Implement conversation runner and stop reasons | 6 — Runner & invariants | task-013, task-014, task-018 | HIGH | each `StopReason` reachable by a test; I08 holds for simulated runs; `unreached_nodes` recorded; `stop_on_first_fail` stops at the deciding turn |
| task-020 | Implement invariants I01 (refusal persistence) and I02 (cumulative intent) | 6 — Runner & invariants | task-019 | HIGH | every FAIL/PASS/INCONCLUSIVE cell of §4.8 for I01/I02 tested, including `NO_BASELINE_REFUSAL` delegated finding |
| task-021 | Implement invariants I03 (claimed authority) and I06 (objective stability) | 6 — Runner & invariants | task-019 | MED | every §4.8 cell for I03/I06 tested; authority compared only against `verified_authority` |
| task-022 | Implement invariants I04 (delayed instruction) and I07 (conversation isolation) | 6 — Runner & invariants | task-019 | HIGH | every §4.8 cell for I04/I07 tested; same-turn emission recorded as delegated finding; cross-principal leak is FAIL |
| task-023 | Implement invariant I05 (approval continuity) | 6 — Runner & invariants | task-019 | HIGH | digest/class/target mismatch, reuse, missing approval and cross-conversation approval each FAIL; exact binding PASS |
| task-024 | Implement result aggregation, artifact and bounded claim | 6 — Runner & invariants | task-020, task-021, task-022, task-023 | HIGH | FAIL on any invariant survives a PASS elsewhere; no PASS without `TERMINAL_REACHED` on every conversation; bounded claim never contains secure/immune/fully protected/guarantee; result validates against schema |
| task-025 | Build MULTITURN-LAB entries 001–018 (refusal, fragmentation, grooming) | 7 — Corpus | task-016, task-017, task-024 | MED | entries carry class and evidence, never expected verdicts; each attack theme has ≥ 1 control |
| task-026 | Build MULTITURN-LAB entries 019–040 and strategy-fault entries | 7 — Corpus | task-015, task-025 | MED | ≥ 40 entries total covering DESIGN §4.4 ranges; GAP and FAULT classes present |
| task-027 | Implement MULTITURN-LAB harness contract test | 7 — Corpus | task-026 | MED | `tests/multiturn_lab.rs`: ATTACK→FAIL on its invariant, CONTROL→PASS, GAP→INCONCLUSIVE, REFUSAL refused, FAULT→ERROR, in all applicable modes |
| task-028 | Implement hostile/refusal corpus tests | 7 — Corpus | task-007, task-015 | MED | `tests/hostile_refusal.rs` has one test per DESIGN §4.5 bullet, each refused before any turn runs |
| task-029 | Add the seven registry entries and property tests | 8 — Registry & coverage | task-003 | MED | `multi_turn_properties.rs` finds all 7 IDs with the §5.2 family/category/reference; no existing entry changed |
| task-030 | Add `multi-turn-security-baseline-2026` profile and denominator row | 8 — Registry & coverage | task-029 | LOW | `no_earlier_profile_denominator_moved` passes with the 9 existing literals unchanged plus a new row `= 7`; REQUIRED/CONDITIONAL split as §5.2 |
| task-031 | Implement coverage facts and Cycle 001 evidence bridge | 8 — Registry & coverage | task-024, task-030 | MED | `stateful_agent_present = true` drives applicability; evidence records pass `validate_secret_safety` and redaction validation |
| task-032 | Add `validate multi-turn` CLI subcommand | 9 — CLI & CI | task-015, task-017, task-024, task-031 | MED | both §5.1 examples reproduce; exit codes 0/1/2/3 each tested; forbidden-flag help test passes; nothing written on refusal |
| task-033 | Add `multi-turn-security-2026` CI job | 9 — CLI & CI | task-027, task-028, task-032 | LOW | job added to `ci.yml` without changing the PR-open trigger; runs locally via `scripts/run-ci-job-locally.py` |
| task-034 | Add determinism and compatibility tests (including embedded-asset locations) | 10 — Audit | task-027, task-032 | MED | 10× byte-identical artifacts per corpus entry and mode; Cycle 013/016/020 lab tests unchanged; every `include_str!` path lies under a Dockerfile-copied directory |
| task-035 | Security, dependency and container audit | 10 — Audit | task-033, task-034 | MED | `cargo audit` clean; credential scan passes; `docker build .` succeeds and `docker run … validate multi-turn --scenario multiturn-lab-001` exits 0 |
| task-036 | Write EN/PT concept and extension docs | 11 — Docs & proof | task-032 | LOW | four book pages added and linked in both `SUMMARY.md`; EN and PT mdBook builds green |
| task-037 | Write REGRESSION.md and PROOF.md and run the completion gate | 11 — Docs & proof | task-035, task-036 | MED | every DESIGN acceptance item maps to an executed test in `PROOF.md`; `verify_proof_citations.py` passes; full completion gate green |
