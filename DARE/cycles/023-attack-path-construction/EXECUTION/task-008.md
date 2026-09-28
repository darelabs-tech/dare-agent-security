# task-008 — Implement `limits.rs` and `error.rs`

**Status:** DONE  
**Complexity:** LOW

## Change

- `limits.rs` sets every constant to its BLUEPRINT §4.2 value. It also adds
  `MAX_BOUNDARY_MEMBERS = 500`, the per-boundary bound written in §4.5.
- `ConstructOptions` defaults to (8, 10 000, 64). `validate` refuses 0 (`BoundZero`) and
  any value above its maximum (`BoundAboveMaximum`).
- `error.rs` contains every §4.1 variant, with these deliberate refinements:
  - **Positions instead of values.** Variants that the Blueprint sketched as carrying a
    value from the input now carry only a position, so no message can echo input content:
    - `InvalidEvidence { record }` and `UnknownEvidenceId { position }` replace the
      evidence id;
    - `InvalidDocument.reason` is a `&'static str`;
    - model refusals carry entity, alias, edge or designation positions instead of ids.
  - **Added variants:**
    - `NotADirectory`;
    - `BoundZero`, split out of `BoundAboveMaximum`;
    - `SensitiveOutput`, the AD-12 sweep refusal;
    - on the model side, `TooLarge`, `TooDeep`, `Symlink`, `UnsafeLabel`, `TenantClash`,
      `DesignationNeedsOneReference`, `DeclaredEdgeUnknownEntity`,
      `DeclaredEdgeWithoutReason` and `BoundaryUnknownEntity`. These are the refusals
      that §4.5 and §7.1 name without a variant.

## Tests

- `limits.rs`: `defaults_are_within_the_maxima` and
  `every_bound_refuses_zero_and_values_above_its_maximum` (all three bounds).
- `tests/error_messages.rs`: `no_error_message_echoes_input` plants
  `sk-live-CANARY-VALUE-1234` in three places: a broken JSON body, a JSON body that is too
  deep, and the file name itself. It asserts that neither `Display` nor `Debug` of the
  refusal contains it.

## Ralph Loop

Green: fmt, clippy `-D warnings`, tests.
