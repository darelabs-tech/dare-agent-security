//! Errors (BLUEPRINT §4.3). A refusal exits 3 and writes nothing; its message
//! names input positions and bound names only, never input content.
use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("refused: {0}")]
    Refused(Refusal),
    #[error("internal error: {0}")]
    Internal(&'static str),
}

pub type Result<T> = std::result::Result<T, TelemetryError>;

/// Which supplied file a refusal is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    /// The trace file at this position of `--traces` (0-based).
    Trace(usize),
    Policy,
}

impl fmt::Display for Input {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Trace(index) => write!(f, "trace file {index}"),
            Self::Policy => write!(f, "the policy file"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    NoTraceFiles,
    TooManyTraceFiles,
    Unreadable {
        input: Input,
    },
    Symlink {
        input: Input,
    },
    TooLarge {
        input: Input,
    },
    TotalTooLarge,
    TooDeep {
        input: Input,
    },
    /// Not OTLP/JSON: `reason` is a fixed rule name, never input content.
    InvalidTrace {
        input: Input,
        reason: &'static str,
    },
    InvalidPolicy {
        reason: &'static str,
    },
    BoundAboveMaximum {
        bound: &'static str,
    },
    BoundZero {
        bound: &'static str,
    },
    UnsafeOutputDir,
    UnsafeArtifact {
        file: &'static str,
    },
}

impl From<Refusal> for TelemetryError {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal)
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTraceFiles => write!(f, "at least one trace file is required"),
            Self::TooManyTraceFiles => write!(f, "more trace files than the maximum"),
            Self::Unreadable { input } => write!(f, "{input} cannot be read"),
            Self::Symlink { input } => write!(f, "{input} is a symbolic link"),
            Self::TooLarge { input } => write!(f, "{input} exceeds its size limit"),
            Self::TotalTooLarge => write!(f, "the trace files exceed the total size limit"),
            Self::TooDeep { input } => write!(f, "{input} nests JSON deeper than 64 levels"),
            Self::InvalidTrace { input, reason } => {
                write!(f, "{input} is not valid OTLP/JSON ({reason})")
            }
            Self::InvalidPolicy { reason } => {
                write!(f, "the policy file does not match its schema ({reason})")
            }
            Self::BoundAboveMaximum { bound } => write!(f, "{bound} is above its maximum"),
            Self::BoundZero { bound } => write!(f, "{bound} must be at least 1"),
            Self::UnsafeOutputDir => write!(f, "the output directory is not a safe path"),
            Self::UnsafeArtifact { file } => write!(
                f,
                "{file} would carry a credential-shaped value; nothing was written"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every message is built from positions and fixed names only.
    #[test]
    fn no_error_message_echoes_input() {
        let all = [
            Refusal::NoTraceFiles,
            Refusal::TooManyTraceFiles,
            Refusal::Unreadable {
                input: Input::Trace(3),
            },
            Refusal::Symlink {
                input: Input::Policy,
            },
            Refusal::TooLarge {
                input: Input::Trace(0),
            },
            Refusal::TotalTooLarge,
            Refusal::TooDeep {
                input: Input::Trace(1),
            },
            Refusal::InvalidTrace {
                input: Input::Trace(2),
                reason: "span_id",
            },
            Refusal::InvalidPolicy {
                reason: "unknown_field",
            },
            Refusal::BoundAboveMaximum { bound: "max_spans" },
            Refusal::BoundZero { bound: "max_spans" },
            Refusal::UnsafeOutputDir,
            Refusal::UnsafeArtifact {
                file: "runtime-telemetry-result.json",
            },
        ];
        for refusal in all {
            let text = TelemetryError::from(refusal.clone()).to_string();
            assert!(text.starts_with("refused: "), "{text}");
            assert!(
                text.chars()
                    .all(|c| c.is_ascii_alphanumeric() || " :;'_.-()/".contains(c)),
                "{refusal:?}: {text}"
            );
        }
    }
}
