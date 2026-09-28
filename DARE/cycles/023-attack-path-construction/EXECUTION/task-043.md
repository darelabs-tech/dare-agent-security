# task-043 — Add compatibility tests (§8.4)

**Status:** DONE  
**Complexity:** MED

## Tests (`crates/dare-agent-security-cli/tests/attack_path_compatibility.rs`)

| Test | Proves |
|---|---|
| `a_v2_path_is_eligible_exactly_when_the_v1_path_with_its_id_is` | Every path of the five v1 fixtures is viewed as v2 facts, with a v1 FAIL carried as a FAIL guard. v2's `path_id`, `path_status` and `impact_factors` give the same id, status and six factors. Cycle 009's `ensure_path_eligible` returns the identical result for the v1 path and the v2-built path, against every `fixtures/adversarial` plan, with `roe_valid` false and true. At least 50 comparisons are made, and some are eligible, so both outcomes are covered |
| `the_registries_and_every_profile_are_unchanged` | SHA-256 of registry v1 and v2 and of all 11 profiles equal the `32909ea` bytes; still 11 profiles |
| `the_engine_crates_are_unchanged` | A tree digest over every file of the ten engine crates, 013–022, equals the one computed from `git ls-tree 32909ea`, and the file counts are equal. Checked negatively: a one-byte change to `dare-tool-security/Cargo.toml` fails it |
| `every_include_str_lies_under_a_docker_copied_directory` | Every `include_str!` in `dare-attack-path`, `dare-attack-graph`, `dare-product` and the CLI `src/` resolves under a directory the Dockerfile's builder stage copies (`schemas`, `fixtures`) |

The v1 golden digests remain `dare-attack-graph/tests/v1_unchanged.rs` (task-002).

## CI

`attack-path-2026` gains two steps. The first runs this test. The second runs the
earlier consumers unchanged:
- `cargo test -p dare-adversarial`;
- `cargo test -p dare-continuous`;
- both `no_earlier_profile_denominator_moved` tests in `dare-coverage`.

## Ralph Loop

The following are green:
- the new test (4 tests);
- `dare-adversarial` and `dare-continuous` (27 tests);
- both denominator tests, `v1_unchanged` and `ci_job`;
- fmt, and clippy `-D warnings --tests`.

No dependency changed. The CLI already depends on `dare-adversarial`, `dare-attack-graph`
and `dare-attack-path`. Digests use `dare_attack_path::ids::sha256_prefixed`.
