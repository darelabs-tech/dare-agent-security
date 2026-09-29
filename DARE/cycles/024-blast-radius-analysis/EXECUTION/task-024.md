# task-024 — Add BRL-011..BRL-020 and the class contract

**Status:** DONE  
**Complexity:** HIGH

- **BRL-011:** tenant-B memory is injected. It reaches alice, the credential and tenant-A
  memory (`WRITE_TRUST_BOUNDARY`).
- **BRL-012/013:** supply chain. The attack is `BOM_COMPLETENESS`; the control stays
  undecided (R-7).
- **BRL-014/015:** goal hijack.
  - BRL-014's `USER_INPUT_INSTRUCTION_BOUNDARY` delta is 1.
  - BRL-015 is its APL-020 twin, which contains exactly that target. The frontier is
    `USER_INPUT_INSTRUCTION_BOUNDARY` and `CROSS_TURN_CONTINUITY`.
- **BRL-016:** the token's control twin of BRL-001. The two targets are `CONTAINED` with
  frontier `CREDENTIAL_SEPARATION`, matching the delta that BRL-001 counts for the token.
- **BRL-017/018:**
  - both have `refused_steps` ≥ 1 with the target absent;
  - BRL-017 is the tool-output injection whose access runs under mallory;
  - BRL-018 is the peer limited to `max_depth: 2`.
- **BRL-019:** `--seed-entry-points` over APL-001.
- **BRL-020:** `max_states: 3` over APL-006. The result is `truncated`, the credential is
  `CONTAINMENT_UNKNOWN`, and the exit code is 2.

`the_lab_keeps_its_class_contract` checks three rules:
- every class with an attack role has a control;
- every `EXPOSED`/`CONTROL_FAILED` expectation names its failed properties;
- every `CONTAINED` expectation names its frontier properties.

Ralph Loop green.
