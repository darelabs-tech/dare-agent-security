# task-015 — Implement input binding for supply-chain and a2a through `StaticAdapter::collect`

**Status:** DONE  
**Complexity:** HIGH

## Change

**Scenario.** The binder uses `inputs/scenario.json` when it is present. Otherwise it
rebuilds the built-in corpus scenario (`corpus::entry_by_id` and `scenario_for`) for
`result.scenario_id`. In both cases the scenario must hash to `result.scenario_digest`.

**Evidence.** The evidence is rebuilt with **the same adapter the engine used**, chosen by
`result.mode`, and must then equal `result.evidence_digest`:

| Mode | Adapter and inputs |
|---|---|
| STATIC | Each `result.documents[]` entry is checked against the raw bytes of the file with the same name under `inputs/evidence/` (`digest_bytes`). Every file the scenario lists is pre-admitted (symlink, escape, size). Then `StaticAdapter::new(inputs/evidence).collect(...)` runs |
| REPLAY | `ReplayAdapter::new(capture, manifest)` for 019, over `inputs/capture.json` and `inputs/manifest.json`. `ReplayAdapter::new(capture, policy)` for 020, with `inputs/policy.json` |
| SIMULATED | `SimulatedAdapter::new()` when the scenario names a reference behaviour, otherwise `CorpusAdapter`, the same selection the CLI makes |
| LOCAL_SYNTHETIC | `LocalSyntheticAdapter::for_scenario` |

**Refinement of the Blueprint wording**, recorded here and in `REGRESSION.md`:
- AD-06 names `StaticAdapter::collect`. §4.4 rule 2 names a capture compared by its own
  digest.
- The engines also run 019 and 020 in simulated and local-synthetic modes, and a replay's
  evidence digest includes the local manifest or policy.
- So "the adapter the engine used" is the exact generalization. Each adapter is the
  engine's own public, deterministic code, and every mode ends in the same
  `evidence_digest` comparison.

## Fixtures

- `tests/generate_static_inputs.rs` produces the STATIC-mode documents. For A2A, they
  come from the engine's own corpus evidence (cards, peers, trace, delegation, policy).
  For supply chain, they are a CycloneDX document and a manifest.
- The committed files are checked against the generator. The real CLI's static-mode
  output over them is in `bundles/static-a2a` and `bundles/static-sc`.

## Tests

- `static_bundles_verify_each_document_and_the_rebuilt_evidence`: every document is
  verified, and the delegation chains and components are present.
- `a_one_byte_change_to_a_static_document_is_refused`: a delegation file, a trace or a
  BOM with one byte changed gives `DigestMismatch("evidence document")`.
- `a_changed_manifest_changes_the_rebuilt_evidence_and_is_refused`: gives
  `DigestMismatch("supply-chain evidence")`. This is observation O-3: the manifest's only
  pin holds.
- `simulated_supply_chain_and_a2a_runs_are_rebuilt_through_the_engine`: a false
  `evidence_digest` is refused.
- A static A2A scenario whose file is removed is rebuilt from its corpus id. It then no
  longer matches, and the refusal is `DigestMismatch("scenario")`.

## Ralph Loop

Green: fmt, clippy `-D warnings`, tests.
