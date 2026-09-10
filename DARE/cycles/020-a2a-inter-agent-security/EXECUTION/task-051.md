# task-051 — Implement reproducibility/determinism checks and generators

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Prove the engine gives the same answer twice, and that nothing it stages or writes carries a real credential or a reachable host.

## Files changed

- `crates/dare-a2a-security/tests/generators.rs` (new, 10 tests)
- `scripts/k20/assert_no_real_credentials.py` (new)

## Determinism

- `every_generated_card_is_byte_identical_between_runs` — over all 36 non-failing reference behaviours.
- `generated_cards_differ_between_behaviours_that_stage_different_things` — the control. Without it, byte-identity would hold trivially for a generator that returned one constant.
- `running_the_whole_corpus_twice_produces_identical_results` — digests every result from all 59 entries, twice. A corpus that produced different verdicts between runs would make every future comparison meaningless while the counts still looked right.
- `observation_digests_do_not_depend_on_the_order_evidence_arrived_in` — the canonical-form claim exercised rather than asserted. Every ordered collection in the evidence model is a `BTree` for this reason, and a `Vec` introduced later fails here.
- `evidence_record_ids_are_reproducible_and_distinct` — stable across builds and unique within a run.
- `a_run_records_zero_state_changes_and_zero_egress_for_every_entry` — the two numbers the cycle is defined by, checked on every vector rather than once on a convenient one.

## Fixture and artifact safety

`no_generated_card_...`, `no_corpus_bundle_...` and `no_artifact_a_run_writes_...` sweep 18 markers plus the shape-anchored bearer check over the generated cards, the staged bundles, every result artifact, every rendered summary and every evidence record.

The sweep runs over the **bytes**, not the source. What matters is what reaches disk.

## The distinction this task turns on

An Agent Card *is* a document full of locations. `https://peer.example/a2a` must stay readable, or the engine cannot describe an A2A interface at all — and a sweep that refused it would end with the fixtures deleted rather than the sweep.

So the ban list names issuer, key-set, registry and model-API hosts that **resolve**, and deliberately omits the reserved documentation domains. `an_example_interface_stays_and_a_real_host_does_not` asserts both halves in one test: the generated card carries `peer.example`, and carries none of the forbidden hosts.

## The script, and the Cycle 019 correction carried in

`scripts/k20/assert_no_real_credentials.py` applies three different rules:

- **shipping code** (`src/**`, outside `#[cfg(test)]`) — no credential shape and no live host. A `const` holding an endpoint is where a fetch would start.
- **tests and guard lists** — no credential shape, but hosts are permitted. A test that asserts a live issuer never reaches an artifact has to write the host down in order to look for it, and banning it there would delete the check.
- **JSON artifacts** — neither. They are the files that leave the repository.

`shipping_lines` is **brace-aware** from the start. Cycle 019 shipped the simpler rule — treat everything after the first `#[cfg(test)]` as test code — which fails *open* on any file that puts a test module in the middle. This crate has several: `lib.rs` carries tests inside its `limits` module above the crate-level ones, and `model.rs` exposes a `pub(crate) mod tests` other modules use.

The script also refuses to succeed having swept nothing. A sweep that found no files would print success having checked nothing, which is the same failure this cycle exists to prevent one layer down.

## Verification the check is not vacuous

A live host was appended to `tenant.rs` and the sweep was run:

```
credential sweep failed:
  crates\dare-a2a-security\src\tenant.rs:149: shipping code names `accounts.google.com`
exit=1
```

The line was reverted and the sweep passes again. A gate nobody has seen fail is a gate nobody knows works.

## Commands executed

```
cargo test -p dare-a2a-security --test generators
python scripts/k20/assert_no_real_credentials.py
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
cargo fmt --all
```

## Result

10 generator tests passing; the sweep clean over 32 shipping files, 5 test files and 2 artifacts, and demonstrated to fail on a planted host.

## Evidence

```
cargo test -p dare-a2a-security --test generators
test result: ok. 10 passed; 0 failed; 0 ignored

python scripts/k20/assert_no_real_credentials.py
no credential shape or live endpoint in Cycle 020 shipping code or artifacts
(32 shipping file(s), 5 test file(s), 2 artifact(s))
```

## Review result

**REVIEW PASS**
