//! Deterministic, conservative tool classification.
//!
//! Name and description heuristics are recorded as non-authoritative indicators
//! only. They never independently produce `READ_ONLY`. Ambiguity and missing
//! metadata resolve to `UNKNOWN`.

use std::collections::BTreeSet;

use crate::inventory::{ClassificationSource, OperationClass, ToolAnnotations, ToolClassification};

/// Stable rationale: operator/scanner configuration supplied the class.
pub const RATIONALE_EXPLICIT_CONFIG: &str = "EXPLICIT_CONFIG";
/// Stable rationale: protocol `destructive_hint` (or equivalent) applied.
pub const RATIONALE_ANNOTATION_DESTRUCTIVE: &str = "ANNOTATION_DESTRUCTIVE";
/// Stable rationale: protocol `read_only_hint` (or equivalent) applied.
pub const RATIONALE_ANNOTATION_READ_ONLY: &str = "ANNOTATION_READ_ONLY";
/// Stable rationale: protocol state-changing annotation applied.
pub const RATIONALE_ANNOTATION_STATE_CHANGING: &str = "ANNOTATION_STATE_CHANGING";
/// Stable rationale: metadata was missing or too weak to classify.
pub const RATIONALE_INSUFFICIENT_METADATA: &str = "INSUFFICIENT_METADATA";
/// Stable rationale: annotations/heuristics contradicted each other.
pub const RATIONALE_CONFLICTING_ANNOTATIONS: &str = "CONFLICTING_ANNOTATIONS";

const INDICATOR_CONFLICTING_HINTS: &str = "conflicting_hints";
const INDICATOR_NAME_SUGGESTS_READ: &str = "name_suggests_read";
const INDICATOR_NAME_SUGGESTS_WRITE: &str = "name_suggests_write";
const INDICATOR_NAME_SUGGESTS_DELETE: &str = "name_suggests_delete";
const INDICATOR_DESCRIPTION_SUGGESTS_READ: &str = "description_suggests_read";
const INDICATOR_DESCRIPTION_SUGGESTS_WRITE: &str = "description_suggests_write";
const INDICATOR_DESCRIPTION_SUGGESTS_DELETE: &str = "description_suggests_delete";
const INDICATOR_OPEN_WORLD_HINT: &str = "open_world_hint";
const INDICATOR_IDEMPOTENT_HINT: &str = "idempotent_hint";
const INDICATOR_READ_ONLY_HINT: &str = "read_only_hint";
const INDICATOR_READ_ONLY_HINT_FALSE: &str = "read_only_hint_false";
const INDICATOR_DESTRUCTIVE_HINT: &str = "destructive_hint";
const INDICATOR_DESTRUCTIVE_HINT_FALSE: &str = "destructive_hint_false";

const READ_TOKENS: &[&str] = &[
    "get", "list", "read", "fetch", "lookup", "search", "find", "describe", "show", "query",
];
const WRITE_TOKENS: &[&str] = &[
    "create", "update", "write", "set", "put", "patch", "insert", "modify", "mutate", "add", "save",
];
const DELETE_TOKENS: &[&str] = &[
    "delete", "remove", "destroy", "drop", "purge", "wipe", "erase",
];

/// Inputs to [`classify_tool`]. Heuristics derived from these fields are never
/// an authoritative source of a safe (`READ_ONLY`) class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassificationInput<'a> {
    /// Tool name as advertised by the server or operator.
    pub name: &'a str,
    /// Optional untrusted description.
    pub description: Option<&'a str>,
    /// Optional protocol annotation hints.
    pub annotations: Option<&'a ToolAnnotations>,
    /// Operator-configured class. When present, this wins.
    pub explicit_class: Option<OperationClass>,
    /// Optional structured protocol class besides boolean hints.
    pub protocol_annotation_class: Option<OperationClass>,
}

impl<'a> ClassificationInput<'a> {
    /// Build an input that carries only a tool name.
    #[must_use]
    pub const fn new(name: &'a str) -> Self {
        Self {
            name,
            description: None,
            annotations: None,
            explicit_class: None,
            protocol_annotation_class: None,
        }
    }
}

/// Classify a tool conservatively from annotations, optional explicit config,
/// and non-authoritative name/description heuristics.
#[must_use]
pub fn classify_tool(input: &ClassificationInput<'_>) -> ToolClassification {
    let mut indicators = collect_heuristic_indicators(input);

    if let Some(annotations) = input.annotations {
        record_annotation_indicators(annotations, &mut indicators);
    }

    if let Some(class) = input.explicit_class {
        return finish(
            class,
            ClassificationSource::ExplicitConfiguration,
            RATIONALE_EXPLICIT_CONFIG,
            indicators,
        );
    }

    let destructive_hint = input
        .annotations
        .and_then(|annotations| annotations.destructive_hint);
    let read_only_hint = input
        .annotations
        .and_then(|annotations| annotations.read_only_hint);
    let protocol_class = input
        .protocol_annotation_class
        .filter(|class| !matches!(class, OperationClass::Unknown));

    let destructive_signal =
        destructive_hint == Some(true) || protocol_class == Some(OperationClass::Destructive);
    let read_only_signal =
        read_only_hint == Some(true) || protocol_class == Some(OperationClass::ReadOnly);
    let state_changing_signal =
        read_only_hint == Some(false) || protocol_class == Some(OperationClass::StateChanging);
    let write_or_delete = has_write_or_delete_signal(&indicators);

    if destructive_signal {
        if read_only_signal {
            indicators.insert(INDICATOR_CONFLICTING_HINTS.to_owned());
        }
        return finish(
            OperationClass::Destructive,
            ClassificationSource::ProtocolAnnotation,
            RATIONALE_ANNOTATION_DESTRUCTIVE,
            indicators,
        );
    }

    if read_only_signal && (write_or_delete || state_changing_signal) {
        indicators.insert(INDICATOR_CONFLICTING_HINTS.to_owned());
        return finish(
            OperationClass::Unknown,
            ClassificationSource::InsufficientMetadata,
            RATIONALE_CONFLICTING_ANNOTATIONS,
            indicators,
        );
    }

    if read_only_signal {
        return finish(
            OperationClass::ReadOnly,
            ClassificationSource::ProtocolAnnotation,
            RATIONALE_ANNOTATION_READ_ONLY,
            indicators,
        );
    }

    if state_changing_signal {
        return finish(
            OperationClass::StateChanging,
            ClassificationSource::ProtocolAnnotation,
            RATIONALE_ANNOTATION_STATE_CHANGING,
            indicators,
        );
    }

    finish(
        OperationClass::Unknown,
        ClassificationSource::InsufficientMetadata,
        RATIONALE_INSUFFICIENT_METADATA,
        indicators,
    )
}

fn finish(
    class: OperationClass,
    source: ClassificationSource,
    rationale_code: &str,
    indicators: BTreeSet<String>,
) -> ToolClassification {
    ToolClassification {
        class,
        source,
        rationale_code: rationale_code.to_owned(),
        heuristic_indicators: indicators.into_iter().collect(),
    }
}

fn record_annotation_indicators(annotations: &ToolAnnotations, indicators: &mut BTreeSet<String>) {
    match annotations.read_only_hint {
        Some(true) => {
            indicators.insert(INDICATOR_READ_ONLY_HINT.to_owned());
        }
        Some(false) => {
            indicators.insert(INDICATOR_READ_ONLY_HINT_FALSE.to_owned());
        }
        None => {}
    }
    match annotations.destructive_hint {
        Some(true) => {
            indicators.insert(INDICATOR_DESTRUCTIVE_HINT.to_owned());
        }
        Some(false) => {
            indicators.insert(INDICATOR_DESTRUCTIVE_HINT_FALSE.to_owned());
        }
        None => {}
    }
    if annotations.idempotent_hint == Some(true) {
        indicators.insert(INDICATOR_IDEMPOTENT_HINT.to_owned());
    }
    if annotations.open_world_hint == Some(true) {
        indicators.insert(INDICATOR_OPEN_WORLD_HINT.to_owned());
    }
}

fn collect_heuristic_indicators(input: &ClassificationInput<'_>) -> BTreeSet<String> {
    let mut indicators = BTreeSet::new();
    let name_tokens = tokenize(input.name);
    insert_token_indicators(
        &name_tokens,
        &mut indicators,
        INDICATOR_NAME_SUGGESTS_READ,
        INDICATOR_NAME_SUGGESTS_WRITE,
        INDICATOR_NAME_SUGGESTS_DELETE,
    );
    if let Some(description) = input.description {
        let description_tokens = tokenize(description);
        insert_token_indicators(
            &description_tokens,
            &mut indicators,
            INDICATOR_DESCRIPTION_SUGGESTS_READ,
            INDICATOR_DESCRIPTION_SUGGESTS_WRITE,
            INDICATOR_DESCRIPTION_SUGGESTS_DELETE,
        );
    }
    indicators
}

fn insert_token_indicators(
    tokens: &[String],
    indicators: &mut BTreeSet<String>,
    read_indicator: &str,
    write_indicator: &str,
    delete_indicator: &str,
) {
    if tokens.iter().any(|token| token_in(token, READ_TOKENS)) {
        indicators.insert(read_indicator.to_owned());
    }
    if tokens.iter().any(|token| token_in(token, WRITE_TOKENS)) {
        indicators.insert(write_indicator.to_owned());
    }
    if tokens.iter().any(|token| token_in(token, DELETE_TOKENS)) {
        indicators.insert(delete_indicator.to_owned());
    }
}

fn has_write_or_delete_signal(indicators: &BTreeSet<String>) -> bool {
    indicators.iter().any(|indicator| {
        matches!(
            indicator.as_str(),
            INDICATOR_NAME_SUGGESTS_WRITE
                | INDICATOR_NAME_SUGGESTS_DELETE
                | INDICATOR_DESCRIPTION_SUGGESTS_WRITE
                | INDICATOR_DESCRIPTION_SUGGESTS_DELETE
        )
    })
}

fn token_in(token: &str, vocabulary: &[&str]) -> bool {
    vocabulary.contains(&token)
}

fn tokenize(value: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut prev_was_lowercase = false;

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            if ch.is_ascii_uppercase() && prev_was_lowercase && !current.is_empty() {
                push_token(&mut tokens, &mut current);
            }
            current.push(ch.to_ascii_lowercase());
            prev_was_lowercase = ch.is_ascii_lowercase();
        } else {
            push_token(&mut tokens, &mut current);
            prev_was_lowercase = false;
        }
    }
    push_token(&mut tokens, &mut current);
    tokens
}

fn push_token(tokens: &mut Vec<String>, current: &mut String) {
    if !current.is_empty() {
        tokens.push(std::mem::take(current));
    }
}
