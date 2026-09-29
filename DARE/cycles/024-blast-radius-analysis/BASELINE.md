# Cycle 024 — Baseline

**Status:** DONE  
**Measured on:** 2026-09-29  
**Baseline commit:** `main @ d125081` (merge of PR #48). Its tree `862211aa…` is identical to
the Cycle 023 final commit `a0b5af1`, verified with
`git rev-parse d125081^{tree} a0b5af1^{tree}`.

Every later claim about what Cycle 024 added or changed is a difference against these
measured numbers.

## Workspace

| Measure | Value | How measured |
|---|---|---|
| `cargo test --workspace` result suites | 332 | the Cycle 023 completion gate on `a0b5af1` (same tree), `PROOF.md` §8 |
| Tests passed / failed / ignored | 4 351 / 0 / 5 | same |
| Workspace members | 23 | `Cargo.toml` `[workspace].members` |
| Registry v1 / v2 digests | `155ba470…fed71` / `e8c5004c…737e9` | pinned by `the_registries_and_every_profile_are_unchanged` |
| Profiles and denominators | 11, unchanged since Cycle 022 | pinned by the same test and `no_earlier_profile_denominator_moved` |
| CI jobs in `ci.yml` | 21 | top-level job keys |

## Container

PR #48 merged with all 27 checks green on `a0b5af1`, including the five `Action E2E` jobs
that build the Action image. That run is the image evidence for this baseline. A local
builder-stage build runs again in task-026, after the changes.

## ATTACK-PATH-LAB output digests (O-07)

**How the digests were taken.** The engines stamp their evidence with the wall clock
(`started_at`, `observed_at`, `recorded_at`). The prompt-injection, multi-turn and
static supply-chain results also differ between runs. Re-running an engine therefore
changes its artifact bytes, the run tags and the evidence digests. A fresh ATTACK-PATH-LAB
run is byte-identical to itself (the lab's double run), but not to an earlier run.

The goldens therefore pin `validate attack-paths` over a **frozen snapshot** of the engine
runs:
1. On this tree, before any Cycle 024 code change, the lab's 60 engine runs were executed
   once each.
2. The 35 unique `(engine, scenario)` runs were kept in
   `crates/dare-agent-security-cli/tests/fixtures/attack-path-lab-frozen/`, 2.3 MB. Only
   the files `attack-paths` reads were kept: result, evidence, transcript and `inputs/`.
3. The six output files of each of the 26 scenarios were hashed over that snapshot.

This is recorded as REGRESSION R-1.

The graph records `engine.commit` from `option_env!("DARE_BUILD_COMMIT")`. No workflow,
Dockerfile or script sets it, so every build writes `unrecorded`, and the digests are
stable across machines. The test asserts that value first.

The machine-readable copy is
`crates/dare-agent-security-cli/tests/fixtures/attack-path-lab-goldens.txt`. It was
written by `regenerate_frozen_runs_and_goldens` (ignored, baseline-only) and is asserted
by `every_attack_path_lab_output_keeps_its_baseline_digest`.

| Scenario | attack-graph.json | attack-paths.json | projection-report.json | graph.mmd | graph.dot | summary.md |
|---|---|---|---|---|---|---|
| APL-001 | `a976a7f4b1aa` | `e240da1e1d13` | `686a4ff87fd2` | `2197d26d9e22` | `d94b3db1fac2` | `70fee4797963` |
| APL-002 | `48b5a61e5b86` | `389f59521e1e` | `8c954f3e99c2` | `e2d4a70bc7b3` | `5c3a03aac1ad` | `3c9d17f67ef5` |
| APL-003 | `eb4a95b08ea2` | `4c4aebff53b3` | `3b3282f77b0a` | `4e4e43c29581` | `16506167d299` | `5165fdd3b1bd` |
| APL-004 | `86c946b414d5` | `bd399591c6be` | `b7b796267382` | `8a4b6d3f627b` | `5b1ef8007285` | `2003dcc48993` |
| APL-005 | `5a526ce738f3` | `b98251d7f313` | `0432022dd02c` | `7056f415d640` | `ebdaef67a526` | `c9b1a3dedbb6` |
| APL-006 | `13e51a49a7e9` | `3cffe6d434aa` | `d14fe9ab48ed` | `e13d096eff11` | `303a4c171f5f` | `94b244605f20` |
| APL-007 | `83dccca30e9c` | `5785b981b19b` | `e7b8035a2928` | `9bdf4de8e8c5` | `ac0214aaaf87` | `b0c965fca3ef` |
| APL-008 | `0801fa427035` | `67df3caa3123` | `b869c9f5f7ab` | `7b5e203a0688` | `e84949380657` | `27525ac2c2cf` |
| APL-009 | `ae904cfce3f6` | `5e42c444b47a` | `df683538176a` | `9a1500f726a8` | `5c795a322a8f` | `36e638862bb2` |
| APL-010 | `3f2e0cc97184` | `a8337bb0e535` | `7c2b76fdec4f` | `14019e8f71cc` | `aa511e624c7e` | `5bd858a79ab2` |
| APL-011 | `1c4e8ad7b339` | `b4351f0b269c` | `fbc00d8edad4` | `5da89d372336` | `0bb50c5d908e` | `526a5207f04c` |
| APL-012 | `34f68c87b479` | `4103d528f3b8` | `81f8edb5c533` | `03c271c5952e` | `61d0ac3e1cac` | `36e638862bb2` |
| APL-013 | `88c1f46cf9a0` | `dd4089c64202` | `73710e3dc72a` | `a8d6ca4ff79d` | `29c1bfd736e3` | `45be60f573f3` |
| APL-014 | `37d1e0d51dc6` | `5c0b49f33255` | `be5f4e8f9447` | `3387c4960809` | `b7fd0bb0175d` | `01a18ec8e062` |
| APL-015 | `369b8a55f0d0` | `683f6cdddebd` | `0e0f83d021dc` | `511412dbc33e` | `3c4c54b46906` | `555808d5001d` |
| APL-016 | `bf0a40a62f79` | `7283641fe78a` | `839fe81fd6b4` | `ffb4a7647451` | `72f011e1003b` | `804101896eb5` |
| APL-017 | `39e068b25bfe` | `920afc916ad0` | `9e6adbdb1bd2` | `106519d464f6` | `bb29868ff1de` | `28d087090ff7` |
| APL-018 | `7332bea87acc` | `67381df8f526` | `5d4cfa8484b3` | `a618fe4960ff` | `bab09f55a395` | `a3ab94a1c575` |
| APL-019 | `0a90fabd1b5c` | `86c11df9256b` | `b327a4fccdb8` | `c5095a45a501` | `983f063b3098` | `51978d001e0e` |
| APL-020 | `a3c3077a9fdc` | `1361a745386e` | `c0e83dd2bf95` | `f34e4d14d07c` | `3ecfab51bb20` | `47cbc7b1daa4` |
| APL-021 | `8314f8f4e981` | `05e17ee7e749` | `527d713a01dd` | `09956dd24974` | `28ecfcdd5e12` | `cc92b9745054` |
| APL-022 | `ff0e62e171d1` | `674532247004` | `71b7700d5beb` | `541a3c11aff5` | `dc1ce4d8107a` | `8626f96514b7` |
| APL-023 | `400f38d8314f` | `95312ae0c722` | `6bae29031d4d` | `907cc9da66f3` | `4ae11146d82a` | `ceab8fb6bbc1` |
| APL-024 | `248ee7190dff` | `dc7d25f45006` | `90149e7fa207` | `b9999cb68da8` | `f596a82d138b` | `417af9822dd2` |
| APL-025 | `c07a39f7b1e8` | `d4bd117f74bb` | `e96f8d5d77db` | `15986f1255ec` | `281affca533a` | `525b92b79c43` |
| APL-026 | `e14d804f94db` | `3583a331dc02` | `68eacba8a4fb` | `192a37dc9626` | `5856b100c1d7` | `fb6fe3a0b7a1` |

Digests are shown to 12 hex digits here. The fixture file holds all 64.

## v1 attack-graph golden digests

These are unchanged from Cycle 023 `BASELINE.md`, and asserted by
`crates/dare-attack-graph/tests/v1_unchanged.rs`.

## Observations carried forward

Cycle 023 REGRESSION "Notes for the next cycle" stay out of scope (DESIGN §10, Q4):
- A2A subjects are opaque to continuity.
- No engine emits `EXPOSES_TOOL` or a tool → resource edge.
- The 022 fixture is multi-turn.
