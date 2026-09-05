# task-021 — Add validate prompt-injection CLI integration

**Status:** READY FOR EXECUTION

## Objective
Expose the real engine under the existing validate hierarchy.

## Acceptance
- command: `validate prompt-injection`;
- support scenario, replay/simulated/local-synthetic mode, bounded transcript/corpus/trials/output-dir/json inputs;
- no URL/API-key/token/provider/arbitrary-command flags;
- exit semantics remain compatible;
- output artifacts match Blueprint.
