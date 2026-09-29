# Cycle 025 — Baseline

**Status:** DONE  
**Measured on:** 2026-09-29  
**Baseline commit:** `main @ 00e7aff` (merge of PR #49, Cycle 024). The Cycle 025 branch
adds only `DARE/` documents and `standards/runtime-telemetry/` on top of it.

Every later claim about what Cycle 025 added or changed is a difference against these
measured numbers.

## Workspace

| Measure | Value | How measured |
|---|---|---|
| `cargo test --workspace` result suites | 347 | full run on this tree (rustc 1.94.1) |
| Tests passed / failed / ignored | 4 433 / 0 / 9 | same |
| Workspace members | 24 | `Cargo.toml` `[workspace].members` |
| CI jobs in `ci.yml` | 22 | top-level job keys |
| Coverage registry v2 | 65 properties, `e8c5004c920c53606949ad537fb24d1e2f5d50ba23b26a75081afedf0f9737e9` | SHA-256 of the file |
| Coverage registry v1 | `155ba470453ab59654a48b5cf29b40278137d126427bde394188b4af4b7fed71` | SHA-256 of the file |
| Profiles | 11 files | `profiles/*.json` |

## Engine crate trees (pinned by `the_engine_crates_are_unchanged`)

| Crate | Tree digest | Files |
|---|---|---|
| dare-prompt-injection | `3600a290…6665f830` | 23 |
| dare-tool-security | `e7cb9942…83251652` | 22 |
| dare-identity-security | `27c601a7…bb45343` | 54 |
| dare-memory-security | `fa1daf59…bd14c19` | 53 |
| dare-rag-security | `5f2afab1…d70905` | 51 |
| dare-mcp-auth-security | `0ef431c4…07db55708` | 77 |
| dare-supply-chain-security | `ddade383…73d3ede4a` | 33 |
| dare-a2a-security | `e0d075d6…96212a2` | 36 |
| dare-multi-turn-security | `60ad42d8…1a3ba73add` | 27 |
| dare-remote-validation | `1b494a04…bdcf53dacd` | 52 |

The digests are computed exactly as the test computes them, and every one equals its pin.

## Cycle 023 / 024 outputs

`attack_path_goldens` (156 digests over the frozen runs), `attack_path_lab`,
`blast_radius_lab` (BRL-001..020) and `blast_radius_cli` all pass in the run above. They
are the byte-identical references for this cycle.
