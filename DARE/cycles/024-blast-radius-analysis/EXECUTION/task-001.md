# task-001 — Record the post-023 baseline and the ATTACK-PATH-LAB output digests

**Status:** DONE  
**Complexity:** LOW

`BASELINE.md` records the following:
- `main @ d125081`, whose tree equals `a0b5af1`;
- 332 suites, and 4 351 passed / 0 failed / 5 ignored (the Cycle 023 gate on the same
  tree);
- 23 members;
- the registry and profile pins;
- 21 CI jobs;
- the green PR #48 run (27 checks, including `Action E2E`) as the container evidence;
- the Cycle 023 notes carried forward.

## ATTACK-PATH-LAB digests

The first measurement ran the lab with `APL_KEEP` and hashed the 156 output files. A
second fresh run gave different digests for every scenario. The diff showed two causes:
- only the evidence timestamps changed;
- for APL-014 and APL-019..021, the result bytes changed too.

Both come from the engines' wall clock and run-specific values, not from
`validate attack-paths`. The digests in `BASELINE.md` are therefore taken over the
frozen snapshot of task-002 (REGRESSION R-1).

## Ralph Loop

The following were run: `cargo test -p dare-agent-security --test attack_path_lab`
(green) and the k23 credential sweep over the tree (clean). No code changed.
