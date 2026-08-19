//! Stable CLI exit codes for `dare-agent-security`.

/// Complete success.
pub const SUCCESS: i32 = 0;
/// Scanner execution error.
pub const SCANNER_ERROR: i32 = 1;
/// Partial inventory or inconclusive evidence.
pub const PARTIAL: i32 = 2;
/// Unsupported, refused, or invalid target.
pub const UNSUPPORTED_TARGET: i32 = 3;

/// After-help text documenting exit codes.
pub const AFTER_HELP: &str = "\
Exit codes:
  0  complete success
  1  scanner execution error
  2  partial inventory or inconclusive evidence
  3  unsupported or refused target (policy, revision, invalid target)
";

/// After-help text for `validate coaz-integrity`.
pub const COAZ_INTEGRITY_AFTER_HELP: &str = "\
Exit codes (`validate coaz-integrity`):
  0  all executed vectors returned verdict PASS
  1  harness error (load, execution, serialization, I/O)
  2  at least one vector returned verdict FAIL or INCONCLUSIVE
  3  usage error or safety refusal (invalid flags, unknown fixture, vulnerable mode on non-synthetic fixture)

Built-in synthetic fixtures only; `--reference-mode vulnerable` never accepts arbitrary URL/stdio targets.
";
