# task-013 — Implement the `RemotePlan` model

**Status:** DONE  
**Complexity:** MED

## Result

- `RemotePlan`, `PlannedRun` and `EngineKind` follow BLUEPRINT §4.6, and `plan.schema.json` agrees field for field.
- `check_shape` enforces the rules the schema cannot express:
  - 1–32 runs;
  - at least one method;
  - well-formed digests;
  - graph digests exactly for multi-turn runs;
  - `a2a_policy_file` exactly for A2A runs, as a bare `*-policy.json` name with no path.
- Scenarios are resolved from built-in corpora by the engine conversions (tasks 027–031) through the `ScenarioDigests` trait.

## Tests

- `a_well_formed_plan_passes_its_shape_check`
- `unknown_fields_are_refused`
- `shape_rules_each_refuse`

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets -- -D warnings` green
- `cargo test -p dare-remote-validation`: 74 passed
- No dependency change
