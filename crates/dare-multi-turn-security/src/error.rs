//! Errors, and the one thing they must never be mistaken for.
//!
//! A refusal is a statement about a *document*: a strategy graph that has a
//! cycle, a transcript whose turns were reordered, an identifier carrying a
//! bidi override. It is never a statement about the security of the agent the
//! document describes. `no_error_message_reads_as_a_verdict` holds that line.
//!
//! Rejected values are never echoed back. An identifier that was refused for
//! carrying a control character would carry it straight into a terminal.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, MultiTurnError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MultiTurnError {
    /// An input exceeded a hard byte bound before it was parsed.
    #[error("input too large: {label} is {len} bytes, the limit is {max}")]
    InputTooLarge {
        label: &'static str,
        len: usize,
        max: usize,
    },

    /// Nesting deeper than the hard maximum.
    #[error("input nested too deeply: {label} exceeds depth {max}")]
    DepthExceeded { label: &'static str, max: usize },

    /// The document failed a schema or version check.
    #[error("schema rejected the document: {0}")]
    Schema(String),

    /// An identifier failed the closed identifier grammar.
    #[error("invalid identifier in field `{field}`")]
    InvalidIdentifier { field: &'static str },

    /// A bidi override or control character in a field that must not carry one.
    #[error("forbidden character U+{codepoint:04X} in field `{field}`")]
    ForbiddenCharacter { field: &'static str, codepoint: u32 },

    /// A field name this engine will not read: executable, credential,
    /// remote, generation or self-declared outcome.
    #[error("refused field `{name}`: {category}")]
    ForbiddenField {
        name: &'static str,
        category: &'static str,
    },

    /// Content that looks like a credential was offered as fixture data.
    #[error("secret-like content refused in field `{field}`")]
    SecretLikeContent { field: &'static str },

    /// A scenario tried to raise a hard maximum instead of lowering it.
    #[error("bound `{name}` may only be lowered, never raised")]
    BoundRaised { name: &'static str },

    /// A scenario asked for a bound of zero, which would disable the run.
    #[error("bound `{name}` must be at least 1")]
    BoundZero { name: &'static str },

    /// A strategy graph exceeded a structural limit.
    #[error("strategy graph limit exceeded: {what} is {value}, the limit is {max}")]
    GraphLimit {
        what: &'static str,
        value: u64,
        max: u64,
    },

    #[error("strategy graph declares node `{node}` twice")]
    GraphDuplicateNode { node: String },

    #[error("strategy graph references unknown node `{node}`")]
    GraphUnknownNode { node: String },

    #[error("strategy graph declares two transitions from `{from}` on `{on}`")]
    GraphDuplicateTransition { from: String, on: &'static str },

    #[error("strategy graph edge from `{from}` is labelled UNCLASSIFIABLE")]
    GraphForbiddenEdge { from: String },

    #[error("terminal node `{node}` has outgoing edges")]
    GraphTerminalHasEdges { node: String },

    #[error("non-terminal node `{node}` has no outgoing edge")]
    GraphDeadEnd { node: String },

    #[error("node `{node}` is not reachable from the root")]
    GraphUnreachableNode { node: String },

    #[error("strategy graph contains a cycle through `{node}`")]
    GraphCycle { node: String },

    #[error("node `{node}` has an approval disclosure inconsistent with its role")]
    GraphInvalidApproval { node: String },

    #[error("conversation `{conversation}` pins a graph digest that was not supplied")]
    GraphDigestMismatch { conversation: String },

    #[error("node `{node}` plants undeclared canary `{canary}`")]
    UnknownCanary { node: String, canary: String },

    #[error("the primary invariant {invariant} is not applicable to this scenario")]
    InapplicableInvariant { invariant: &'static str },

    /// A replayed transcript's chained digest does not match its turns.
    #[error("transcript for conversation `{conversation}` was altered at turn {index}")]
    TranscriptTampered { conversation: String, index: u32 },

    /// The run departed from the approved strategy graph (I08). Always ERROR.
    #[error("strategy fault: {0}")]
    StrategyFault(String),

    /// A persisted artifact would cross the run-wide output budget.
    #[error("output budget exhausted: {0}")]
    OutputBudgetExceeded(String),

    #[error("io error: {0}")]
    Io(String),

    #[error("serialization failed for {kind}")]
    Serialization { kind: &'static str },

    /// A built evidence record failed Cycle 001 validation. This is an engine
    /// fault, never a verdict, and the record is not returned.
    #[error("evidence record failed Cycle 001 validation")]
    EvidenceInvalid,
}

impl MultiTurnError {
    /// True when the input was declined before anything was evaluated.
    ///
    /// A refusal produces no result artifact and exit code 3. It is never a
    /// security verdict about the target.
    pub fn is_refusal(&self) -> bool {
        !matches!(
            self,
            Self::OutputBudgetExceeded(_)
                | Self::StrategyFault(_)
                | Self::Io(_)
                | Self::Serialization { .. }
                | Self::EvidenceInvalid
        )
    }
}

impl From<std::io::Error> for MultiTurnError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_variant() -> Vec<MultiTurnError> {
        vec![
            MultiTurnError::EvidenceInvalid,
            MultiTurnError::InputTooLarge {
                label: "scenario",
                len: 9,
                max: 1,
            },
            MultiTurnError::DepthExceeded {
                label: "graph",
                max: 32,
            },
            MultiTurnError::Schema("unsupported version".into()),
            MultiTurnError::InvalidIdentifier { field: "node_id" },
            MultiTurnError::ForbiddenCharacter {
                field: "node_id",
                codepoint: 0x202e,
            },
            MultiTurnError::SecretLikeContent { field: "content" },
            MultiTurnError::ForbiddenField {
                name: "mutate",
                category: "turn generation",
            },
            MultiTurnError::BoundRaised {
                name: "max_turns_per_conversation",
            },
            MultiTurnError::GraphLimit {
                what: "paths",
                value: 65,
                max: 64,
            },
            MultiTurnError::GraphDuplicateNode { node: "n1".into() },
            MultiTurnError::GraphUnknownNode { node: "n1".into() },
            MultiTurnError::GraphDuplicateTransition {
                from: "n1".into(),
                on: "REFUSED",
            },
            MultiTurnError::GraphForbiddenEdge { from: "n1".into() },
            MultiTurnError::GraphTerminalHasEdges { node: "n1".into() },
            MultiTurnError::GraphDeadEnd { node: "n1".into() },
            MultiTurnError::GraphUnreachableNode { node: "n1".into() },
            MultiTurnError::GraphCycle { node: "n1".into() },
            MultiTurnError::GraphInvalidApproval { node: "n1".into() },
            MultiTurnError::GraphDigestMismatch {
                conversation: "c1".into(),
            },
            MultiTurnError::UnknownCanary {
                node: "n1".into(),
                canary: "k1".into(),
            },
            MultiTurnError::InapplicableInvariant {
                invariant: "I07_CONVERSATION_ISOLATION",
            },
            MultiTurnError::TranscriptTampered {
                conversation: "c1".into(),
                index: 2,
            },
            MultiTurnError::StrategyFault("turn out of order".into()),
            MultiTurnError::OutputBudgetExceeded("result".into()),
            MultiTurnError::Io("not found".into()),
            MultiTurnError::Serialization { kind: "result" },
        ]
    }

    #[test]
    fn no_error_message_reads_as_a_verdict() {
        for error in every_variant() {
            let message = error.to_string().to_ascii_lowercase();
            for verdict in ["pass", "fail", "secure", "vulnerable", "inconclusive"] {
                assert!(
                    !message
                        .split(|c: char| !c.is_ascii_alphanumeric())
                        .any(|w| w == verdict),
                    "`{message}` reads like a verdict (`{verdict}`)"
                );
            }
        }
    }

    #[test]
    fn document_problems_are_refusals_and_run_problems_are_not() {
        assert!(MultiTurnError::GraphCycle { node: "n1".into() }.is_refusal());
        assert!(MultiTurnError::TranscriptTampered {
            conversation: "c".into(),
            index: 0
        }
        .is_refusal());
        assert!(!MultiTurnError::OutputBudgetExceeded("x".into()).is_refusal());
        assert!(!MultiTurnError::Io("x".into()).is_refusal());
    }
}
