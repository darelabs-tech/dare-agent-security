# Cycle 025 — Approval

**Cycle:** 025 — Runtime OpenTelemetry Security  
**Approval:** DESIGN AND BLUEPRINT APPROVED — task set pending  
**Approved at:** 2026-09-29  
**Approved by:** Product Owner  
**Base:** `main @ 00e7aff`  
**Branch:** `claude/loving-newton-113zme`

## Approval decision

`DESIGN.md` is approved as the scope contract for Cycle 025, with the recommended option
for every Review question in its §13:

1. **Q1 (a).** A new engine crate, `dare-runtime-telemetry`, with the same result and
   evidence shape as engines 013–022.
2. **Q2 (a).** OTLP/JSON trace files only. There is no receiver, no listener and no
   collector integration.
3. **Q3 (a).** A new runtime-policy schema. Without a policy, only the telemetry
   properties are judged, and the behaviour properties are NOT_APPLICABLE.
4. **Q4 (a).** Behaviour verdicts use existing properties. Two new properties go in a new
   `AGENT.TELEMETRY` family, gated by `runtime_trace_present`. These registry changes are
   additive only.
5. **Q5 (a).** A new optional profile, `runtime-telemetry-baseline-2026`.
6. **Q6 (a).** The Cycle 023 projector for this engine (RF-15) is SHOULD. Outputs for
   existing inputs stay byte-identical.
7. **Q7 (b).** Product integration (RF-17) is out of scope for v1.

## Frozen boundaries

Neither the Blueprint nor execution may, without a new Review:
- change an engine crate (013–022), its verdict semantics or its artifacts;
- change an existing property ID or any of the eleven existing profile denominators;
- change the output of `validate attack-paths` (Cycle 023), `validate blast-radius`
  (Cycle 024) or `validate attack-graph --facts` (Cycle 008) for any existing input;
- report PASS on a property whose required spans are not proven complete (RS-06);
- copy an attribute value, prompt, completion or tool argument from an input trace into
  any artifact (RS-02);
- emit telemetry, open a port, contact a collector, or call the system under test (RS-08);
- add a third-party dependency, including any OpenTelemetry SDK or protobuf crate.

## Blueprint approval (2026-09-29)

`BLUEPRINT.md` is approved, including AD-01 to AD-12, with the recommended option for
each Review item:

1. **BQ-1 (a) — a test-only exception to the frozen engine boundary.** Two pin tests may
   change from whole-file digests to the prefix rule of Cycle 021:
   - `crates/dare-remote-validation/tests/compatibility.rs`;
   - `the_registries_and_every_profile_are_unchanged` in
     `crates/dare-agent-security-cli/tests/attack_path_compatibility.rs`.

   Under the new rule, every pre-existing registry entry and the 11 earlier profiles must
   stay byte-identical. After that change, the Cycle 022 tree digest in `ENGINE_TREES` is
   re-pinned. No engine source, verdict or artifact may change.
2. **BQ-2 (a).** Pin the latest released OpenTelemetry semantic-conventions version at
   execution time, recorded with its provenance.
3. **BQ-3 (a).** A local copy of the secret markers, with a test that keeps it equal to
   `dare_attack_graph::v2::sweep`.
4. **BQ-4 (a).** Retries are counted only as error-then-retry sibling groups under one
   parent.
5. **BQ-5 (a).** INCONCLUSIVE exits 2.

## Next step

The task set (`TASKS.md`, `dare-dag.yaml`, `dare-dag.exec.yaml`) needs its own approval
before execution.
