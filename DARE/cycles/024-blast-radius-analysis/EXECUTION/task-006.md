# task-006 — Implement `limits.rs` and `error.rs`

**Status:** DONE  
**Complexity:** LOW

- **`limits.rs`:** the constants equal BLUEPRINT §4.2, and `Bounds { max_depth, max_states }`
  has:
  - `validate`, which refuses 0 (`BoundZero`) and anything above the maximum
    (`BoundAboveMaximum`) and never clamps;
  - `lower`, where the smaller value wins.

  Tests: `defaults_are_within_the_maxima`,
  `every_bound_refuses_zero_and_values_above_its_maximum` (both bounds, at 0, at the
  maximum and at maximum + 1), and `lowering_takes_the_smaller_value`.
- **`error.rs`:** `BlastError::{Refused, Internal}` and every `Refusal` variant of §4.1.
  `Display` builds each message from positions and fixed names.
  `no_error_message_echoes_input` renders every variant and checks the text is
  `refused: ` plus plain words, with no quote, brace or path character. The CLI corpus
  (task-022) plants values in real inputs and checks stderr end to end.

Ralph Loop green.
