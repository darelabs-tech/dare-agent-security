//! Errors (BLUEPRINT §4.1).
//!
//! Every message names positions and field kinds only. No variant carries a
//! value read from an input file, so an error can never echo input content,
//! including a credential that slipped into an identifier.
use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum AttackPathError {
    /// Exit 3. Nothing is written.
    #[error("refused: {0}")]
    Refused(Refusal),
    /// Exit 1.
    #[error("internal error: {0}")]
    Internal(&'static str),
}

impl AttackPathError {
    pub fn is_refusal(&self) -> bool {
        matches!(self, Self::Refused(_))
    }
}

impl From<Refusal> for AttackPathError {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal)
    }
}

impl From<ModelRefusal> for AttackPathError {
    fn from(refusal: ModelRefusal) -> Self {
        Self::Refused(Refusal::Model(refusal))
    }
}

pub type Result<T> = std::result::Result<T, AttackPathError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    NoArtifacts,
    TooManyArtifacts {
        given: usize,
    },
    NotADirectory {
        index: usize,
    },
    UnknownBundle {
        index: usize,
    },
    FileTooLarge {
        index: usize,
        file: &'static str,
    },
    TooDeep {
        index: usize,
        file: &'static str,
    },
    Symlink {
        index: usize,
        file: &'static str,
    },
    PathEscape {
        index: usize,
        file: &'static str,
    },
    InvalidDocument {
        index: usize,
        file: &'static str,
        reason: &'static str,
    },
    MissingInput {
        index: usize,
        input: &'static str,
    },
    DigestMismatch {
        index: usize,
        input: &'static str,
    },
    InvalidEvidence {
        index: usize,
        record: usize,
    },
    UnknownEvidenceId {
        index: usize,
        position: usize,
    },
    DuplicateRun {
        first: usize,
        second: usize,
    },
    Model(ModelRefusal),
    BoundAboveMaximum {
        bound: &'static str,
        given: u64,
        max: u64,
    },
    BoundZero {
        bound: &'static str,
    },
    UnsafeOutputDir,
    SensitiveOutput {
        file: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelRefusal {
    Invalid(&'static str),
    TooLarge,
    TooDeep,
    Symlink,
    OverLimit(&'static str),
    UnusableEntityId { entity: usize },
    DuplicateEntity { entity: usize },
    UnsafeLabel { entity: usize },
    AliasUnknownEntity { alias: usize },
    ConflictingAlias { alias: usize },
    TypeClash { alias: usize },
    TenantClash { entity: usize },
    DesignationNeedsOneReference { designation: usize },
    UnknownDesignationTarget { designation: usize },
    DeclaredEdgeUnknownEntity { edge: usize },
    DeclaredEdgeWithoutRationale { edge: usize },
    DeclaredEdgeWithoutReason { edge: usize },
    BoundaryUnknownEntity { boundary: usize },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoArtifacts => write!(f, "no --artifacts directory was given"),
            Self::TooManyArtifacts { given } => {
                write!(f, "{given} artifact directories exceed the maximum of 64")
            }
            Self::NotADirectory { index } => write!(f, "artifact {index} is not a directory"),
            Self::UnknownBundle { index } => write!(
                f,
                "artifact {index} must contain exactly one known engine result file"
            ),
            Self::FileTooLarge { index, file } => {
                write!(f, "artifact {index}: {file} exceeds the size limit")
            }
            Self::TooDeep { index, file } => {
                write!(f, "artifact {index}: {file} exceeds the JSON depth limit")
            }
            Self::Symlink { index, file } => {
                write!(f, "artifact {index}: {file} is a symbolic link")
            }
            Self::PathEscape { index, file } => {
                write!(f, "artifact {index}: {file} resolves outside its directory")
            }
            Self::InvalidDocument {
                index,
                file,
                reason,
            } => {
                write!(f, "artifact {index}: {file} is invalid ({reason})")
            }
            Self::MissingInput { index, input } => {
                write!(f, "artifact {index}: required input {input} is missing")
            }
            Self::DigestMismatch { index, input } => write!(
                f,
                "artifact {index}: {input} does not match the digest its result pins"
            ),
            Self::InvalidEvidence { index, record } => write!(
                f,
                "artifact {index}: evidence record {record} fails Cycle 001 validation"
            ),
            Self::UnknownEvidenceId { index, position } => write!(
                f,
                "artifact {index}: evidence id {position} of the result is not in the evidence file"
            ),
            Self::DuplicateRun { first, second } => {
                write!(f, "artifacts {first} and {second} contain the same result")
            }
            Self::Model(refusal) => write!(f, "system model: {refusal}"),
            Self::BoundAboveMaximum { bound, given, max } => {
                write!(f, "{bound} = {given} exceeds the maximum of {max}")
            }
            Self::BoundZero { bound } => write!(f, "{bound} must be at least 1"),
            Self::UnsafeOutputDir => write!(f, "the output directory is not usable"),
            Self::SensitiveOutput { file } => write!(
                f,
                "refusing to write {file}: it would contain sensitive content"
            ),
        }
    }
}

impl fmt::Display for ModelRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid ({reason})"),
            Self::TooLarge => write!(f, "exceeds the size limit"),
            Self::TooDeep => write!(f, "exceeds the JSON depth limit"),
            Self::Symlink => write!(f, "is a symbolic link"),
            Self::OverLimit(what) => write!(f, "too many {what}"),
            Self::UnusableEntityId { entity } => write!(f, "entity {entity} has an unusable id"),
            Self::DuplicateEntity { entity } => write!(f, "entity {entity} repeats an id"),
            Self::UnsafeLabel { entity } => write!(f, "entity {entity} has an unsafe label"),
            Self::AliasUnknownEntity { alias } => {
                write!(f, "alias {alias} names an unknown entity")
            }
            Self::ConflictingAlias { alias } => {
                write!(f, "alias {alias} maps a local id that is already mapped")
            }
            Self::TypeClash { alias } => write!(
                f,
                "alias {alias} maps a node whose type differs from its entity's type"
            ),
            Self::TenantClash { entity } => write!(
                f,
                "entity {entity} would merge nodes that disagree on their tenant"
            ),
            Self::DesignationNeedsOneReference { designation } => write!(
                f,
                "designation {designation} must name exactly one of entity_id or node_id"
            ),
            Self::UnknownDesignationTarget { designation } => {
                write!(f, "designation {designation} names no node of the graph")
            }
            Self::DeclaredEdgeUnknownEntity { edge } => {
                write!(f, "declared edge {edge} names an unknown entity")
            }
            Self::DeclaredEdgeWithoutRationale { edge } => {
                write!(f, "declared INFERRED edge {edge} has no rationale")
            }
            Self::DeclaredEdgeWithoutReason { edge } => {
                write!(f, "declared NOT_TESTED edge {edge} has no reason")
            }
            Self::BoundaryUnknownEntity { boundary } => {
                write!(f, "trust boundary {boundary} names an unknown entity")
            }
        }
    }
}
