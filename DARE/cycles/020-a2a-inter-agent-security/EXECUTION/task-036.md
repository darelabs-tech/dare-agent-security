# task-036 — Implement invariant-specific PASS/INCONCLUSIVE coverage contracts

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Make PASS mean a question was asked and answered, for each of the fourteen separately.

## Files changed

- `crates/dare-a2a-security/src/coverage.rs` (new — `CoverageContract`, `assess_coverage`, `comparison_reason`)

## Presence is the first step and not the last

Each contract names the observation channels its invariant needs. A missing channel is reported by name, because an operator handed INCONCLUSIVE learns nothing and one handed the missing channel knows what to collect.

The **second** step is the Cycle 019 correction carried forward. `comparison_reason` asks whether the channel that was present actually carried something to compare. Cycle 019 shipped a coverage gate that passed on a channel that was present and empty, and the run reported PASS having compared nothing. Here, for example, I01 requires that at least one of `digest_matches_policy`, `provider_matches_policy` or `signer_approved` be `Some` — an Agent Card observed against a policy that says nothing about it has been read, not checked.

Corpus entry `A2A-LAB-004B` exists to exercise exactly that path.

## Four invariants that need no approved side

I06, I07, I08 and I13 decide from what was observed alone, and `comparison_reason` returns `None` for them with the reason written down: a task carrying two contexts is a substitution whatever policy says, a chain that widened has widened, peer content that became instruction crossed, and an extension either was declared and approved or was not. Demanding a policy comparison for these would make them undecidable on evidence that fully decides them.

## Commands executed

```
cargo test -p dare-a2a-security --lib coverage::
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

8 tests passing, including `an_empty_run_satisfies_no_contract` and `every_invariant_has_a_contract_and_every_contract_requires_something` — an invariant with an empty contract would pass on an empty run, which is the exact failure the contracts exist to prevent.

## Evidence

```
cargo test -p dare-a2a-security --lib coverage::
test result: ok. 8 passed; 0 failed
```

## Review result

**REVIEW PASS**
