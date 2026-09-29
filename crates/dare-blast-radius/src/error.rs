//! Errors (BLUEPRINT §4.1). A refusal exits 3 and writes nothing; its message
//! names positions and bound names only, never input content.
use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum BlastError {
    #[error("refused: {0}")]
    Refused(Refusal),
    #[error("internal error: {0}")]
    Internal(&'static str),
}

pub type Result<T> = std::result::Result<T, BlastError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Unreadable { file: &'static str },
    Symlink { file: &'static str },
    TooLarge { file: &'static str },
    TooDeep { file: &'static str },
    InvalidDocument { file: &'static str },
    InvalidGraph,
    GraphMismatch,
    NoSeeds,
    UnknownSeed { seed: usize },
    AmbiguousSeed { seed: usize },
    SeedKindMismatch { seed: usize },
    DuplicateSeed { first: usize, second: usize },
    BoundAboveMaximum { bound: &'static str },
    BoundZero { bound: &'static str },
    UnsafeOutputDir,
    UnsafeArtifact { file: &'static str },
}

impl From<Refusal> for BlastError {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal)
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { file } => write!(f, "the {file} file cannot be read"),
            Self::Symlink { file } => write!(f, "the {file} file is a symbolic link"),
            Self::TooLarge { file } => write!(f, "the {file} file exceeds its size limit"),
            Self::TooDeep { file } => write!(f, "the {file} file nests JSON deeper than 64 levels"),
            Self::InvalidDocument { file } => {
                write!(f, "the {file} file does not match its schema")
            }
            Self::InvalidGraph => write!(f, "the graph fails v2 graph validation"),
            Self::GraphMismatch => {
                write!(f, "the scenario's graph_id does not name this graph")
            }
            Self::NoSeeds => write!(f, "the graph has no entry point to seed from"),
            Self::UnknownSeed { seed } => write!(f, "seed {seed} resolves to no node of the graph"),
            Self::AmbiguousSeed { seed } => {
                write!(f, "seed {seed} resolves to more than one node of the graph")
            }
            Self::SeedKindMismatch { seed } => {
                write!(
                    f,
                    "seed {seed} has a kind that does not fit its node's type"
                )
            }
            Self::DuplicateSeed { first, second } => {
                write!(f, "seeds {first} and {second} name the same node and kind")
            }
            Self::BoundAboveMaximum { bound } => write!(f, "{bound} is above its maximum"),
            Self::BoundZero { bound } => write!(f, "{bound} must be at least 1"),
            Self::UnsafeOutputDir => write!(f, "the output directory is not a safe path"),
            Self::UnsafeArtifact { file } => {
                write!(
                    f,
                    "{file} would carry a credential-shaped value; nothing was written"
                )
            }
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
            Refusal::Unreadable { file: "graph" },
            Refusal::Symlink { file: "graph" },
            Refusal::TooLarge { file: "scenario" },
            Refusal::TooDeep { file: "scenario" },
            Refusal::InvalidDocument { file: "scenario" },
            Refusal::InvalidGraph,
            Refusal::GraphMismatch,
            Refusal::NoSeeds,
            Refusal::UnknownSeed { seed: 3 },
            Refusal::AmbiguousSeed { seed: 3 },
            Refusal::SeedKindMismatch { seed: 3 },
            Refusal::DuplicateSeed {
                first: 1,
                second: 2,
            },
            Refusal::BoundAboveMaximum { bound: "max_depth" },
            Refusal::BoundZero {
                bound: "max_states",
            },
            Refusal::UnsafeOutputDir,
            Refusal::UnsafeArtifact {
                file: "blast-radius.json",
            },
        ];
        for refusal in all {
            let text = BlastError::from(refusal.clone()).to_string();
            assert!(text.starts_with("refused: "), "{text}");
            assert!(
                text.chars()
                    .all(|c| c.is_ascii_alphanumeric() || " :;'_.-".contains(c)),
                "{refusal:?}: {text}"
            );
        }
    }
}
