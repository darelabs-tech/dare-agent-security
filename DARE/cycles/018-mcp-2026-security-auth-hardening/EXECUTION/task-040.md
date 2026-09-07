# task-040 — Benign controls and INCONCLUSIVE regressions

**Status:** DONE - REVIEW PASS

Add benign controls for every applicable surface and explicit missing-evidence regressions proving incomplete evidence produces INCONCLUSIVE rather than PASS/FAIL.

## Evidence

**Sixteen benign controls**, one per applicable surface plus one extra wherever the compliant path has a second legitimate shape: labs 001, 005, 007, 009, 011, 013, 016, 018, 020, 023, 024, 026, 028, 029, 031, 032. `lab_scenarios.rs` asserts the coverage mechanically rather than trusting the table.

**Two missing-evidence regressions.** These are the ones that matter, because silence is the failure mode a coverage-blind engine reports as PASS:

- Lab 014 strips every token observation. `TOKEN_VALIDITY_EVIDENCE_PRESENT` has nothing to judge and returns INCONCLUSIVE.
- Lab 035 strips the PKCE channels. `PKCE_BINDING_PRESERVED` returns INCONCLUSIVE.

Lab 035's invariant was chosen deliberately. A protocol-binding invariant would have passed vacuously: routing and operation come from the requests, which every scenario must declare, so those channels can never actually be absent and the lab would have proven nothing. The comment in `gen_mcp_auth_scenarios.py` records why.

The distinction both labs enforce is that INCONCLUSIVE is neither of the other verdicts — `lab_scenarios.rs` asserts both directions, not PASS and not FAIL. `result.rs::silence_is_inconclusive_and_never_pass` asserts it again at the aggregate level, where a single silent trial must not be averaged away by passing ones.
