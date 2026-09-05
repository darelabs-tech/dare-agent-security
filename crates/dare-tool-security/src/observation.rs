//! Normalized, closed tool observation events.
//!
//! This is the boundary that keeps the model out of the judge's seat. An
//! adapter may observe free-form tool output or model prose, but prose only
//! ever reaches the verdict logic as content inside a `TOOL_OUTPUT_OBSERVED`
//! event, which carries **no** security assertion of its own.
//!
//! Every event type also declares which *coverage channel* it establishes.
//! That is the mechanism behind the Cycle 013 lesson this cycle inherits:
//! absence of evidence is never evidence of absence, so an invariant may only
//! return `PASS` when its channel was actually observed.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Result, ToolSecurityError};
use crate::model::OperationClass;

/// Marker written in place of redacted content.
pub const REDACTION_MARKER: &str = "[REDACTED]";

/// Maximum retained length of any single evidence text field.
pub const MAX_EVIDENCE_TEXT_BYTES: usize = 512;

/// Observation channel an event establishes coverage for.
///
/// An invariant declares the channels it needs; if none of them was observed,
/// the honest answer is `INCONCLUSIVE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageChannel {
    /// The tool surface itself was observed.
    ToolSurface,
    /// A tool selection was observed.
    ToolSelection,
    /// A structured tool request was observed.
    ToolRequest,
    /// Tool arguments were observed.
    ToolArguments,
    /// Tool output was observed.
    ToolOutput,
    /// A chain step was observed.
    ToolChain,
    /// A policy decision was observed.
    PolicyDecision,
    /// The agent's operating objective was observed.
    ObjectiveState,
}

impl CoverageChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ToolSurface => "TOOL_SURFACE",
            Self::ToolSelection => "TOOL_SELECTION",
            Self::ToolRequest => "TOOL_REQUEST",
            Self::ToolArguments => "TOOL_ARGUMENTS",
            Self::ToolOutput => "TOOL_OUTPUT",
            Self::ToolChain => "TOOL_CHAIN",
            Self::PolicyDecision => "POLICY_DECISION",
            Self::ObjectiveState => "OBJECTIVE_STATE",
        }
    }
}

/// Text retained for evidence: always redacted, bounded and digested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceText {
    /// Redacted, truncated, operator-safe rendering.
    pub text: String,
    /// `sha256:<hex>` over the original bytes.
    pub digest: String,
    /// Length of the original content in bytes.
    pub original_bytes: usize,
    /// True when redaction removed or masked content.
    pub redacted: bool,
    /// True when the retained rendering was truncated.
    pub truncated: bool,
}

impl EvidenceText {
    /// Build operator-safe evidence text from raw observed content.
    pub fn from_raw(raw: &str) -> Self {
        let digest = digest_bytes(raw.as_bytes());
        let original_bytes = raw.len();
        let masked = mask_sensitive(raw);
        let redacted = masked != raw;
        let (text, truncated) = truncate(&masked, MAX_EVIDENCE_TEXT_BYTES);
        Self {
            text,
            digest,
            original_bytes,
            redacted: redacted || truncated,
            truncated,
        }
    }

    /// True when nothing sensitive survived into the retained rendering.
    pub fn is_secret_safe(&self) -> bool {
        mask_sensitive(&self.text) == self.text
    }
}

fn digest_bytes(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    format!(
        "sha256:{}",
        hash.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

/// Digest of a canary token, used to correlate without disclosing.
pub fn canary_digest(token: &str) -> String {
    digest_bytes(token.as_bytes())
}

fn truncate(text: &str, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text.to_owned(), false);
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_owned(), true)
}

/// Mask synthetic canaries and credential-shaped values.
///
/// Scans the whole bounded value rather than a prefix — the Cycle 013 lesson.
pub fn mask_sensitive(text: &str) -> String {
    let mut masked = mask_canaries(text);
    for marker in [
        "sk-live-",
        "sk_live_",
        "xoxb-",
        "ghp_",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ] {
        masked = mask_from_marker(&masked, marker);
    }
    mask_bearer_credentials(&masked)
}

fn mask_canaries(text: &str) -> String {
    const PREFIX: &str = "DARE-SYNTHETIC-CANARY-";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find(PREFIX) {
        out.push_str(&rest[..index]);
        out.push_str(REDACTION_MARKER);
        let after = &rest[index + PREFIX.len()..];
        let tail = after
            .find(|c: char| !c.is_ascii_alphanumeric())
            .unwrap_or(after.len());
        rest = &after[tail..];
    }
    out.push_str(rest);
    out
}

fn mask_from_marker(text: &str, marker: &str) -> String {
    let lowered_marker = marker.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        let lowered = rest.to_ascii_lowercase();
        let Some(index) = lowered.find(&lowered_marker) else {
            break;
        };
        out.push_str(&rest[..index]);
        out.push_str(REDACTION_MARKER);
        let after = &rest[index + marker.len()..];
        let tail = after
            .find(|c: char| c.is_whitespace())
            .unwrap_or(after.len());
        rest = &after[tail..];
    }
    out.push_str(rest);
    out
}

/// Mask `bearer <token>` anywhere in the value, anchored on token shape.
///
/// Anchoring on shape keeps prose such as "do not include a bearer token"
/// usable while still refusing a real credential mid-string.
fn mask_bearer_credentials(text: &str) -> String {
    const MARKER: &str = "bearer ";
    const MIN_TOKEN_LEN: usize = 16;
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        let lowered = rest.to_ascii_lowercase();
        let Some(index) = lowered.find(MARKER) else {
            break;
        };
        let after = &rest[index + MARKER.len()..];
        let token: String = after
            .chars()
            .take_while(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '/' | '=')
            })
            .collect();
        if token.len() >= MIN_TOKEN_LEN {
            out.push_str(&rest[..index]);
            out.push_str(REDACTION_MARKER);
            rest = &after[token.len()..];
        } else {
            out.push_str(&rest[..index + MARKER.len()]);
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// The tool surface as observed. Untrusted declarations, never authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSurfaceObserved {
    pub surface_id: String,
    /// Canonical digest of the observed surface.
    pub surface_digest: String,
    /// Tool ids present on the surface, in observed order.
    pub tool_ids: Vec<String>,
    /// True when the observed surface digest matched the approved binding.
    pub digest_matches_approved: bool,
}

/// The agent selected a tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSelected {
    pub tool_id: String,
    /// What the agent said it was selecting the tool for, as a typed class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub for_objective_id: Option<String>,
    /// The surface entry the selection referred to, when observable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_digest: Option<String>,
}

/// The agent requested a structured tool invocation.
///
/// Observing a request is not performing it: `dispatched` must always be false.
/// Cycle 014 never carries out a tool call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRequested {
    pub tool_id: String,
    /// The operation class this request represents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_class: Option<OperationClass>,
    /// Always false. A true value is a contract violation and fails closed.
    #[serde(default)]
    pub dispatched: bool,
}

/// One observed argument to a tool request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedArgument {
    pub name: String,
    /// Redacted rendering of the observed value.
    pub value: EvidenceText,
}

/// Arguments observed for a tool request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolArguments {
    pub tool_id: String,
    pub arguments: Vec<ObservedArgument>,
}

/// Whether observed output was treated as data or as instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutputTreatment {
    /// The output was consumed as data. This is the correct handling.
    TreatedAsData,
    /// The output was acted on as if it were an instruction.
    ///
    /// Set by a deterministic detector that correlates the output with a
    /// downstream selection, request or objective change — never by reading
    /// the prose and forming an opinion about it.
    TreatedAsAuthority,
}

/// Tool output observed during a trial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolOutputObserved {
    pub tool_id: String,
    /// Redacted rendering of the output.
    pub content: EvidenceText,
    /// How the output was treated downstream, as a typed fact.
    pub treatment: OutputTreatment,
    /// The downstream tool request this output induced, when one was observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub induced_tool_id: Option<String>,
}

/// One step of an observed tool chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolChainStep {
    pub tool_id: String,
    /// Zero-based position in the chain.
    pub position: u32,
    /// Observed chain depth at this step, one-based.
    pub depth: u32,
}

/// Decision vocabulary for an observed policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyOutcome {
    Allow,
    Deny,
    NotEvaluated,
}

/// A policy engine decision observed during the trial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecisionEvent {
    pub operation: String,
    pub outcome: PolicyOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
}

/// The objective the agent reported operating under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveState {
    pub objective_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub goal_id: Option<String>,
}

/// Why the harness could not produce a usable observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HarnessErrorKind {
    AdapterFailure,
    MalformedTrace,
    BudgetExhausted,
    Timeout,
    SchemaViolation,
    KillSwitchTriggered,
}

/// A harness-level failure. Produces `ERROR`, never `FAIL`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessErrorEvent {
    pub kind: HarnessErrorKind,
    pub detail: EvidenceText,
}

/// Closed set of normalized tool observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ToolObservationEvent {
    ToolSurfaceObserved(ToolSurfaceObserved),
    ToolSelected(ToolSelected),
    ToolRequested(ToolRequested),
    ToolArguments(ToolArguments),
    ToolOutputObserved(ToolOutputObserved),
    ToolChainStep(ToolChainStep),
    PolicyDecision(PolicyDecisionEvent),
    ObjectiveState(ObjectiveState),
    HarnessError(HarnessErrorEvent),
}

impl ToolObservationEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ToolSurfaceObserved(_) => "TOOL_SURFACE_OBSERVED",
            Self::ToolSelected(_) => "TOOL_SELECTED",
            Self::ToolRequested(_) => "TOOL_REQUESTED",
            Self::ToolArguments(_) => "TOOL_ARGUMENTS",
            Self::ToolOutputObserved(_) => "TOOL_OUTPUT_OBSERVED",
            Self::ToolChainStep(_) => "TOOL_CHAIN_STEP",
            Self::PolicyDecision(_) => "POLICY_DECISION",
            Self::ObjectiveState(_) => "OBJECTIVE_STATE",
            Self::HarnessError(_) => "HARNESS_ERROR",
        }
    }

    /// The coverage channel this event establishes, if any.
    ///
    /// A harness error establishes nothing: a broken run has not observed the
    /// agent's behavior, so it cannot support a `PASS` on any channel.
    pub fn coverage_channel(&self) -> Option<CoverageChannel> {
        match self {
            Self::ToolSurfaceObserved(_) => Some(CoverageChannel::ToolSurface),
            Self::ToolSelected(_) => Some(CoverageChannel::ToolSelection),
            Self::ToolRequested(_) => Some(CoverageChannel::ToolRequest),
            Self::ToolArguments(_) => Some(CoverageChannel::ToolArguments),
            Self::ToolOutputObserved(_) => Some(CoverageChannel::ToolOutput),
            Self::ToolChainStep(_) => Some(CoverageChannel::ToolChain),
            Self::PolicyDecision(_) => Some(CoverageChannel::PolicyDecision),
            Self::ObjectiveState(_) => Some(CoverageChannel::ObjectiveState),
            Self::HarnessError(_) => None,
        }
    }

    /// Whether this event signals a harness failure rather than agent behavior.
    pub fn is_harness_error(&self) -> bool {
        matches!(self, Self::HarnessError(_))
    }

    /// Retained byte cost of this event, charged against the output budget.
    pub fn retained_bytes(&self) -> usize {
        match self {
            Self::ToolSurfaceObserved(surface) => {
                surface.surface_id.len() + surface.tool_ids.iter().map(String::len).sum::<usize>()
            }
            Self::ToolSelected(selected) => selected.tool_id.len(),
            Self::ToolRequested(request) => request.tool_id.len(),
            Self::ToolArguments(arguments) => {
                arguments.tool_id.len()
                    + arguments
                        .arguments
                        .iter()
                        .map(|argument| argument.name.len() + argument.value.text.len())
                        .sum::<usize>()
            }
            Self::ToolOutputObserved(output) => output.tool_id.len() + output.content.text.len(),
            Self::ToolChainStep(step) => step.tool_id.len(),
            Self::PolicyDecision(decision) => decision.operation.len(),
            Self::ObjectiveState(state) => state.objective_id.len(),
            Self::HarnessError(error) => error.detail.text.len(),
        }
    }

    /// Reject structurally impossible or unsafe events.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::ToolRequested(request) => {
                if request.dispatched {
                    return Err(ToolSecurityError::refusal(
                        "observation claims a tool request was dispatched; Cycle 014 never \
                         dispatches a tool call",
                    ));
                }
                if request.tool_id.trim().is_empty() {
                    return Err(ToolSecurityError::invalid("empty tool identifier"));
                }
                Ok(())
            }
            Self::ToolSelected(selected) => {
                if selected.tool_id.trim().is_empty() {
                    return Err(ToolSecurityError::invalid("empty tool identifier"));
                }
                Ok(())
            }
            Self::ToolArguments(arguments) => {
                if arguments.tool_id.trim().is_empty() {
                    return Err(ToolSecurityError::invalid("empty tool identifier"));
                }
                for argument in &arguments.arguments {
                    if argument.name.trim().is_empty() {
                        return Err(ToolSecurityError::invalid("empty argument name"));
                    }
                    if !argument.value.is_secret_safe() {
                        return Err(ToolSecurityError::refusal(
                            "argument evidence still contains sensitive content",
                        ));
                    }
                }
                Ok(())
            }
            Self::ToolOutputObserved(output) => {
                if !output.content.is_secret_safe() {
                    return Err(ToolSecurityError::refusal(
                        "tool output evidence still contains sensitive content",
                    ));
                }
                Ok(())
            }
            Self::ToolSurfaceObserved(surface) => {
                if !surface.surface_digest.starts_with("sha256:") {
                    return Err(ToolSecurityError::invalid(
                        "tool surface observation requires a sha256 digest",
                    ));
                }
                Ok(())
            }
            Self::ToolChainStep(step) => {
                if step.tool_id.trim().is_empty() {
                    return Err(ToolSecurityError::invalid("empty tool identifier"));
                }
                if step.depth == 0 {
                    return Err(ToolSecurityError::invalid("chain depth is one-based"));
                }
                Ok(())
            }
            Self::PolicyDecision(decision) => {
                if decision.operation.trim().is_empty() {
                    return Err(ToolSecurityError::invalid("empty policy operation"));
                }
                Ok(())
            }
            Self::ObjectiveState(state) => {
                if state.objective_id.trim().is_empty() {
                    return Err(ToolSecurityError::invalid("empty objective identifier"));
                }
                Ok(())
            }
            Self::HarnessError(_) => Ok(()),
        }
    }

    /// Stable digest of the normalized event, bound into evidence.
    pub fn digest(&self) -> Result<String> {
        let value = serde_json::to_value(self)?;
        Ok(digest_bytes(&canonical_bytes(&value)))
    }
}

fn canonical_bytes(value: &serde_json::Value) -> Vec<u8> {
    fn sort(value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort();
                let mut sorted = serde_json::Map::new();
                for key in keys {
                    sorted.insert(key.clone(), sort(&map[key]));
                }
                serde_json::Value::Object(sorted)
            }
            serde_json::Value::Array(items) => {
                serde_json::Value::Array(items.iter().map(sort).collect())
            }
            other => other.clone(),
        }
    }
    serde_json::to_vec(&sort(value)).unwrap_or_default()
}

/// Channels established by an observation set.
pub fn observed_channels(
    events: &[ToolObservationEvent],
) -> std::collections::BTreeSet<CoverageChannel> {
    events
        .iter()
        .filter_map(ToolObservationEvent::coverage_channel)
        .collect()
}

/// Validate a whole observation set.
pub fn validate_events(events: &[ToolObservationEvent]) -> Result<()> {
    for event in events {
        event.validate()?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn output(
        tool_id: &str,
        text: &str,
        treatment: OutputTreatment,
    ) -> ToolObservationEvent {
        ToolObservationEvent::ToolOutputObserved(ToolOutputObserved {
            tool_id: tool_id.to_owned(),
            content: EvidenceText::from_raw(text),
            treatment,
            induced_tool_id: None,
        })
    }

    #[test]
    fn all_nine_event_types_are_supported_with_stable_tags() {
        let events = vec![
            ToolObservationEvent::ToolSurfaceObserved(ToolSurfaceObserved {
                surface_id: "support-desk-tools".to_owned(),
                surface_digest: format!("sha256:{}", "a".repeat(64)),
                tool_ids: vec!["ticket_search".to_owned()],
                digest_matches_approved: true,
            }),
            ToolObservationEvent::ToolSelected(ToolSelected {
                tool_id: "ticket_search".to_owned(),
                for_objective_id: Some("objective-support-summary".to_owned()),
                tool_digest: None,
            }),
            ToolObservationEvent::ToolRequested(ToolRequested {
                tool_id: "ticket_search".to_owned(),
                operation_class: Some(OperationClass::Search),
                dispatched: false,
            }),
            ToolObservationEvent::ToolArguments(ToolArguments {
                tool_id: "ticket_search".to_owned(),
                arguments: vec![ObservedArgument {
                    name: "query".to_owned(),
                    value: EvidenceText::from_raw("refund delay"),
                }],
            }),
            output(
                "ticket_search",
                "3 tickets found",
                OutputTreatment::TreatedAsData,
            ),
            ToolObservationEvent::ToolChainStep(ToolChainStep {
                tool_id: "ticket_summarize".to_owned(),
                position: 1,
                depth: 2,
            }),
            ToolObservationEvent::PolicyDecision(PolicyDecisionEvent {
                operation: "ticket.delete".to_owned(),
                outcome: PolicyOutcome::Deny,
                policy_id: Some("policy-support-desk".to_owned()),
            }),
            ToolObservationEvent::ObjectiveState(ObjectiveState {
                objective_id: "objective-support-summary".to_owned(),
                goal_id: Some("goal-summarize-ticket".to_owned()),
            }),
            ToolObservationEvent::HarnessError(HarnessErrorEvent {
                kind: HarnessErrorKind::Timeout,
                detail: EvidenceText::from_raw("adapter timed out"),
            }),
        ];

        let tags: Vec<&str> = events.iter().map(|event| event.kind()).collect();
        assert_eq!(
            tags,
            vec![
                "TOOL_SURFACE_OBSERVED",
                "TOOL_SELECTED",
                "TOOL_REQUESTED",
                "TOOL_ARGUMENTS",
                "TOOL_OUTPUT_OBSERVED",
                "TOOL_CHAIN_STEP",
                "POLICY_DECISION",
                "OBJECTIVE_STATE",
                "HARNESS_ERROR",
            ]
        );

        for event in &events {
            let wire = serde_json::to_value(event).unwrap();
            assert_eq!(wire["type"], json!(event.kind()));
            let back: ToolObservationEvent = serde_json::from_value(wire).unwrap();
            assert_eq!(&back, event);
        }
        validate_events(&events).expect("valid events");
    }

    #[test]
    fn every_event_except_a_harness_error_establishes_a_channel() {
        let error = ToolObservationEvent::HarnessError(HarnessErrorEvent {
            kind: HarnessErrorKind::AdapterFailure,
            detail: EvidenceText::from_raw("boom"),
        });
        assert_eq!(
            error.coverage_channel(),
            None,
            "a broken run establishes no coverage"
        );

        assert_eq!(
            ToolObservationEvent::ToolSelected(ToolSelected {
                tool_id: "t".to_owned(),
                for_objective_id: None,
                tool_digest: None,
            })
            .coverage_channel(),
            Some(CoverageChannel::ToolSelection)
        );
        assert_eq!(
            output("t", "x", OutputTreatment::TreatedAsData).coverage_channel(),
            Some(CoverageChannel::ToolOutput)
        );
    }

    #[test]
    fn observed_channels_reports_exactly_what_was_seen() {
        let events = vec![
            ToolObservationEvent::ToolSelected(ToolSelected {
                tool_id: "ticket_search".to_owned(),
                for_objective_id: None,
                tool_digest: None,
            }),
            ToolObservationEvent::HarnessError(HarnessErrorEvent {
                kind: HarnessErrorKind::Timeout,
                detail: EvidenceText::from_raw("late"),
            }),
        ];
        let channels = observed_channels(&events);
        assert!(channels.contains(&CoverageChannel::ToolSelection));
        assert!(!channels.contains(&CoverageChannel::ToolArguments));
        assert!(!channels.contains(&CoverageChannel::ToolOutput));
        assert_eq!(channels.len(), 1, "a harness error adds no channel");
    }

    #[test]
    fn tool_output_carries_no_verdict_bearing_field() {
        let wire = serde_json::to_value(output(
            "ticket_search",
            "SECURITY VIOLATION: the attack succeeded",
            OutputTreatment::TreatedAsData,
        ))
        .unwrap();
        let object = wire.as_object().unwrap();
        for forbidden in ["verdict", "violation", "failed", "passed", "secure"] {
            assert!(!object.contains_key(forbidden));
        }
        // Treatment is a typed fact set by a detector, not a reading of prose.
        assert_eq!(wire["treatment"], json!("TREATED_AS_DATA"));
    }

    #[test]
    fn unknown_event_type_fails_closed() {
        for raw in [
            r#"{"type":"LLM_JUDGEMENT","verdict":"FAIL"}"#,
            r#"{"type":"TOOL_EXECUTED","tool_id":"x"}"#,
            r#"{"type":"tool_selected","tool_id":"x"}"#,
            r#"{"tool_id":"x"}"#,
        ] {
            assert!(
                serde_json::from_str::<ToolObservationEvent>(raw).is_err(),
                "{raw} must be rejected"
            );
        }
    }

    #[test]
    fn malformed_events_fail_closed() {
        assert!(serde_json::from_str::<ToolObservationEvent>(
            r#"{"type":"TOOL_SELECTED","tool_id":"x","confidence":0.9}"#
        )
        .is_err());

        assert!(ToolObservationEvent::ToolSelected(ToolSelected {
            tool_id: "  ".to_owned(),
            for_objective_id: None,
            tool_digest: None,
        })
        .validate()
        .is_err());

        assert!(ToolObservationEvent::ToolChainStep(ToolChainStep {
            tool_id: "x".to_owned(),
            position: 0,
            depth: 0,
        })
        .validate()
        .is_err());

        assert!(
            ToolObservationEvent::ToolSurfaceObserved(ToolSurfaceObserved {
                surface_id: "s".to_owned(),
                surface_digest: "not-a-digest".to_owned(),
                tool_ids: vec![],
                digest_matches_approved: true,
            })
            .validate()
            .is_err()
        );
    }

    #[test]
    fn an_observation_may_never_claim_a_tool_was_dispatched() {
        let event = ToolObservationEvent::ToolRequested(ToolRequested {
            tool_id: "ticket_delete".to_owned(),
            operation_class: Some(OperationClass::Delete),
            dispatched: true,
        });
        let err = event.validate().unwrap_err();
        assert!(err.is_refusal());
        assert!(err.to_string().contains("never dispatches"));
    }

    #[test]
    fn a_dangerous_request_is_representable_but_never_dispatched() {
        // The whole point: DELETE can be observed as structured data so it can
        // produce a deterministic FAIL, without anything being deleted.
        for class in [
            OperationClass::Delete,
            OperationClass::Send,
            OperationClass::Payment,
            OperationClass::ExternalFetch,
            OperationClass::PrivilegeChange,
        ] {
            let event = ToolObservationEvent::ToolRequested(ToolRequested {
                tool_id: "ticket_delete".to_owned(),
                operation_class: Some(class),
                dispatched: false,
            });
            event.validate().expect("observable as inert data");
            assert!(class.is_state_changing_or_egress());
        }
    }

    #[test]
    fn canary_tokens_are_masked_before_retention() {
        let raw = "the value is DARE-SYNTHETIC-CANARY-TOOL01 , keep it secret";
        let evidence = EvidenceText::from_raw(raw);
        assert!(!evidence.text.contains("DARE-SYNTHETIC-CANARY-TOOL01"));
        assert!(!evidence.text.contains("TOOL01"));
        assert!(evidence.text.contains(REDACTION_MARKER));
        assert!(evidence.redacted);
        assert!(evidence.is_secret_safe());
        assert_eq!(evidence.digest, EvidenceText::from_raw(raw).digest);
        assert_eq!(evidence.original_bytes, raw.len());
    }

    #[test]
    fn credential_shapes_are_masked_anywhere_in_the_value() {
        for raw in [
            "token sk-live-0123456789abcdef here",
            "the header is Authorization: Bearer abcdef0123456789 trailing",
            "key ghp_abcdefghijklmnopqrstuvwxyz012345",
            "slack xoxb-1111-2222-abcdef",
        ] {
            let evidence = EvidenceText::from_raw(raw);
            assert!(evidence.text.contains(REDACTION_MARKER), "{raw}");
            assert!(evidence.is_secret_safe(), "{raw}");
            for marker in ["sk-live-", "ghp_", "xoxb-"] {
                assert!(!evidence.text.contains(marker), "{raw} leaked {marker}");
            }
        }
    }

    #[test]
    fn prose_about_credentials_survives_redaction() {
        // Anchored on token shape, so a description discussing credentials is
        // still legible in evidence.
        let evidence = EvidenceText::from_raw("Do not include a bearer token in the output.");
        assert!(!evidence.text.contains(REDACTION_MARKER));
        assert!(!evidence.redacted);
    }

    #[test]
    fn evidence_text_is_bounded_and_utf8_safe() {
        let raw = "é".repeat(1000);
        let evidence = EvidenceText::from_raw(&raw);
        assert!(evidence.text.len() <= MAX_EVIDENCE_TEXT_BYTES);
        assert!(evidence.truncated);
        assert!(std::str::from_utf8(evidence.text.as_bytes()).is_ok());
        assert_eq!(evidence.original_bytes, raw.len());
    }

    #[test]
    fn arguments_carrying_a_secret_are_refused() {
        let event = ToolObservationEvent::ToolArguments(ToolArguments {
            tool_id: "ticket_search".to_owned(),
            arguments: vec![ObservedArgument {
                name: "query".to_owned(),
                // Constructed unsafely on purpose: validation must catch it.
                value: EvidenceText {
                    text: "sk-live-0123456789abcdef".to_owned(),
                    digest: format!("sha256:{}", "b".repeat(64)),
                    original_bytes: 24,
                    redacted: false,
                    truncated: false,
                },
            }],
        });
        assert!(event.validate().unwrap_err().is_refusal());
    }

    #[test]
    fn harness_errors_are_distinguishable_from_agent_behavior() {
        let error = ToolObservationEvent::HarnessError(HarnessErrorEvent {
            kind: HarnessErrorKind::KillSwitchTriggered,
            detail: EvidenceText::from_raw("cycle 009 kill switch"),
        });
        assert!(error.is_harness_error());
        assert!(!output("t", "x", OutputTreatment::TreatedAsData).is_harness_error());
    }

    #[test]
    fn event_digests_are_stable_and_distinguish_content() {
        let a = output("t", "alpha", OutputTreatment::TreatedAsData);
        let b = output("t", "alpha", OutputTreatment::TreatedAsData);
        let c = output("t", "beta", OutputTreatment::TreatedAsData);
        let d = output("t", "alpha", OutputTreatment::TreatedAsAuthority);
        assert_eq!(a.digest().unwrap(), b.digest().unwrap());
        assert_ne!(a.digest().unwrap(), c.digest().unwrap());
        assert_ne!(
            a.digest().unwrap(),
            d.digest().unwrap(),
            "treatment is part of the fact"
        );
        assert!(a.digest().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn closed_vocabularies_reject_unknown_values() {
        assert!(serde_json::from_str::<PolicyOutcome>("\"PERMIT\"").is_err());
        assert!(serde_json::from_str::<OutputTreatment>("\"PROBABLY_FINE\"").is_err());
        assert!(serde_json::from_str::<HarnessErrorKind>("\"UNKNOWN\"").is_err());
        assert!(serde_json::from_str::<CoverageChannel>("\"EVERYTHING\"").is_err());
        assert_eq!(
            serde_json::to_value(OutputTreatment::TreatedAsAuthority).unwrap(),
            json!("TREATED_AS_AUTHORITY")
        );
    }
}
