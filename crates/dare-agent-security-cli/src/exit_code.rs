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
