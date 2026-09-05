//! Harness contract and the deterministic normalizer.
//!
//! Adapters are deliberately dumb transports: they surface what was observed
//! and decide nothing. Every security-relevant classification happens in the
//! evaluator, over the typed events [`normalize`] produces.
//!
//! Cycle 014 has three approved modes, all local and offline. There is no
//! remote provider, no live MCP client and no arbitrary command path, and
//! [`ToolHarnessMode`] has no variant that could represent one.
//!
//! Two properties here are structural rather than documented:
//!
//! - a normalized [`ToolRequested`] always carries `dispatched: false`, because
//!   nothing in this crate can dispatch a tool call;
//! - argument and output content becomes [`EvidenceText`], so credential-shaped
//!   or canary content is masked before it can reach a report.

use serde::{Deserialize, Serialize};

use crate::canonical::ToolIdentityBinding;
use crate::error::{Result, ToolSecurityError};
use crate::model::{OperationClass, ToolCorpusEntry, ToolSecurityScenario};
use crate::observation::{
    validate_events, EvidenceText, HarnessErrorEvent, HarnessErrorKind, ObjectiveState,
    ObservedArgument, OutputTreatment, PolicyDecisionEvent, PolicyOutcome, ToolArguments,
    ToolChainStep, ToolObservationEvent, ToolOutputObserved, ToolRequested, ToolSelected,
    ToolSurfaceObserved,
};

/// Approved execution modes. All are local and offline.
///
/// There is deliberately no `RemoteProvider`, `LiveMcp` or `AuthorizedDynamic`
/// variant: remote and live tool execution is out of scope for Cycle 014 and
/// cannot be selected, not merely discouraged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ToolHarnessMode {
    /// Evaluate a sanitized local trace. Invokes no tool, server or model.
    Replay,
    /// Deterministic corpus-derived observations for regression.
    Simulated,
    /// Controlled local synthetic execution through the Cycle 009 substrate.
    LocalSynthetic,
}

impl ToolHarnessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Replay => "REPLAY",
            Self::Simulated => "SIMULATED",
            Self::LocalSynthetic => "LOCAL_SYNTHETIC",
        }
    }

    /// Every approved mode. All of them are offline.
    pub fn all() -> [Self; 3] {
        [Self::Replay, Self::Simulated, Self::LocalSynthetic]
    }

    /// True when observations are synthetic rather than recorded from a real
    /// agent. Reports must not present these as production evidence.
    pub fn is_synthetic(self) -> bool {
        matches!(self, Self::Simulated | Self::LocalSynthetic)
    }

    /// Parse an operator-supplied mode, failing closed on anything else.
    pub fn parse(token: &str) -> Result<Self> {
        Self::all()
            .into_iter()
            .find(|mode| mode.as_str() == token)
            .ok_or_else(|| {
                ToolSecurityError::refusal(format!(
                    "unknown or unapproved harness mode '{token}'; Cycle 014 supports only \
                     REPLAY, SIMULATED and LOCAL_SYNTHETIC"
                ))
            })
    }
}

/// A tool surface as reported by an adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawToolSurface {
    pub surface_id: String,
    /// Digest of the surface actually observed, when the recorder captured it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_digest: Option<String>,
    /// Recorded fact: did the observed surface match the approved binding?
    pub digest_matches_approved: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_ids: Vec<String>,
}

/// A tool the agent selected, as reported by an adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSelection {
    pub tool_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub for_objective_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_digest: Option<String>,
}

/// A structured tool request. Requested, never dispatched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRequest {
    pub tool_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_class: Option<OperationClass>,
}

/// One observed argument name/value pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawArgumentValue {
    pub name: String,
    pub value: String,
}

/// Arguments observed for one tool request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawArguments {
    pub tool_id: String,
    pub values: Vec<RawArgumentValue>,
}

/// Tool output, plus the recorded fact about how it was handled downstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawOutput {
    pub tool_id: String,
    pub content: String,
    /// How the output was treated. A recorded behavioral fact, never a reading
    /// of what the text appears to say.
    pub treatment: OutputTreatment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub induced_tool_id: Option<String>,
}

/// One step of an observed tool chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawChainStep {
    pub tool_id: String,
    pub position: u32,
    pub depth: u32,
}

/// A policy decision observed during a trial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPolicyDecision {
    pub operation: String,
    pub outcome: PolicyOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
}

/// The objective state the agent reported operating under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawObjectiveState {
    pub objective_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub goal_id: Option<String>,
}

/// An adapter-level failure. Produces `ERROR`, never `FAIL`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawHarnessError {
    pub kind: HarnessErrorKind,
    pub detail: String,
}

/// What an adapter observed in one trial, before normalization.
///
/// This is raw transport data. Nothing here is a security conclusion.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawToolTrialOutput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_observed: Option<RawToolSurface>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objective_state: Option<RawObjectiveState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selections: Vec<RawSelection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requests: Vec<RawRequest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<RawArguments>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outputs: Vec<RawOutput>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain_steps: Vec<RawChainStep>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_decisions: Vec<RawPolicyDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_error: Option<RawHarnessError>,
}

/// One trial's inputs.
#[derive(Debug, Clone, Copy)]
pub struct ToolTrialRequest<'a> {
    pub trial_index: u32,
    pub scenario: &'a ToolSecurityScenario,
    pub binding: &'a ToolIdentityBinding,
    /// The corpus vector under test, when the scenario references one.
    pub entry: Option<&'a ToolCorpusEntry>,
}

/// A bounded, local source of tool observations.
pub trait ToolHarnessAdapter {
    /// Mode this adapter implements.
    fn mode(&self) -> ToolHarnessMode;

    /// Observe one trial.
    ///
    /// Implementations must not perform network I/O, spawn a process, contact
    /// an MCP server, or execute any tool the agent requested.
    fn observe(&self, request: &ToolTrialRequest<'_>) -> Result<RawToolTrialOutput>;
}

/// Convert raw adapter output into normalized, typed observation events.
///
/// Content is inspected only to make it operator-safe. Nothing here reads
/// meaning out of text: `treatment` and `digest_matches_approved` are facts the
/// recorder captured, not judgements this function forms. Nothing absent is
/// filled in either — a channel the adapter did not report stays unreported, so
/// the coverage contract can say INCONCLUSIVE rather than PASS.
pub fn normalize(
    raw: &RawToolTrialOutput,
    binding: &ToolIdentityBinding,
) -> Vec<ToolObservationEvent> {
    let mut events = Vec::new();

    if let Some(error) = &raw.harness_error {
        events.push(ToolObservationEvent::HarnessError(HarnessErrorEvent {
            kind: error.kind,
            detail: EvidenceText::from_raw(&error.detail),
        }));
        // A failed trial supports no behavioral claim whatsoever.
        return events;
    }

    if let Some(surface) = &raw.surface_observed {
        events.push(ToolObservationEvent::ToolSurfaceObserved(
            ToolSurfaceObserved {
                surface_id: surface.surface_id.clone(),
                surface_digest: observed_surface_digest(surface, binding),
                tool_ids: surface.tool_ids.clone(),
                digest_matches_approved: surface.digest_matches_approved,
            },
        ));
    }

    if let Some(state) = &raw.objective_state {
        events.push(ToolObservationEvent::ObjectiveState(ObjectiveState {
            objective_id: state.objective_id.clone(),
            goal_id: state.goal_id.clone(),
        }));
    }

    for selection in &raw.selections {
        events.push(ToolObservationEvent::ToolSelected(ToolSelected {
            tool_id: selection.tool_id.clone(),
            for_objective_id: selection.for_objective_id.clone(),
            tool_digest: selection.tool_digest.clone(),
        }));
    }

    for request in &raw.requests {
        events.push(ToolObservationEvent::ToolRequested(ToolRequested {
            tool_id: request.tool_id.clone(),
            operation_class: request.operation_class,
            // Structurally false: Cycle 014 observes requests and never
            // dispatches one, so no adapter can claim otherwise.
            dispatched: false,
        }));
    }

    for arguments in &raw.arguments {
        events.push(ToolObservationEvent::ToolArguments(ToolArguments {
            tool_id: arguments.tool_id.clone(),
            arguments: arguments
                .values
                .iter()
                .map(|value| ObservedArgument {
                    name: value.name.clone(),
                    value: EvidenceText::from_raw(&value.value),
                })
                .collect(),
        }));
    }

    for output in &raw.outputs {
        events.push(ToolObservationEvent::ToolOutputObserved(
            ToolOutputObserved {
                tool_id: output.tool_id.clone(),
                content: EvidenceText::from_raw(&output.content),
                treatment: output.treatment,
                induced_tool_id: output.induced_tool_id.clone(),
            },
        ));
    }

    for step in &raw.chain_steps {
        events.push(ToolObservationEvent::ToolChainStep(ToolChainStep {
            tool_id: step.tool_id.clone(),
            position: step.position,
            depth: step.depth,
        }));
    }

    for decision in &raw.policy_decisions {
        events.push(ToolObservationEvent::PolicyDecision(PolicyDecisionEvent {
            operation: decision.operation.clone(),
            outcome: decision.outcome,
            policy_id: decision.policy_id.clone(),
        }));
    }

    events
}

/// Normalize and reject any event that is structurally unsafe.
pub fn normalize_checked(
    raw: &RawToolTrialOutput,
    binding: &ToolIdentityBinding,
) -> Result<Vec<ToolObservationEvent>> {
    let events = normalize(raw, binding);
    validate_events(&events)?;
    Ok(events)
}

/// Total retained bytes for a normalized trial, charged against the budget.
pub fn retained_bytes(events: &[ToolObservationEvent]) -> usize {
    events
        .iter()
        .map(ToolObservationEvent::retained_bytes)
        .sum()
}

/// Deepest chain depth present in a normalized trial, if any.
pub fn observed_chain_depth(events: &[ToolObservationEvent]) -> Option<u32> {
    events
        .iter()
        .filter_map(|event| match event {
            ToolObservationEvent::ToolChainStep(step) => Some(step.depth),
            _ => None,
        })
        .max()
}

/// Digest of the surface that was actually observed.
///
/// A recorder that captured the observed digest is believed about the digest,
/// though never about what it implies. When it captured none, a matching
/// surface takes the approved digest and a mismatching one is digested from
/// what was recorded, so the event always carries a verifiable identity rather
/// than an empty field.
fn observed_surface_digest(surface: &RawToolSurface, binding: &ToolIdentityBinding) -> String {
    if let Some(digest) = &surface.surface_digest {
        return digest.clone();
    }
    if surface.digest_matches_approved {
        return binding.surface_digest.clone();
    }
    crate::canonical::observed_surface_digest(&surface.surface_id, &surface.tool_ids)
}

/// Refuse a surface observation that contradicts itself.
///
/// A recorded digest equal to the approved one while claiming a mismatch — or
/// the reverse — is a corrupt or tampered record, not a finding.
pub fn assert_surface_claim_consistent(
    surface: &RawToolSurface,
    binding: &ToolIdentityBinding,
) -> Result<()> {
    let Some(digest) = &surface.surface_digest else {
        return Ok(());
    };
    let equal = digest == &binding.surface_digest;
    if equal != surface.digest_matches_approved {
        return Err(ToolSecurityError::DigestMismatch(format!(
            "surface observation claims digest_matches_approved={} while its recorded digest {} \
             the approved binding",
            surface.digest_matches_approved,
            if equal { "equals" } else { "differs from" }
        )));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::canonical::bind;
    use crate::observation::CoverageChannel;

    pub(crate) fn scenario() -> ToolSecurityScenario {
        serde_json::from_value(crate::schema::tests::valid_scenario()).unwrap()
    }

    pub(crate) fn binding() -> ToolIdentityBinding {
        bind(&scenario()).unwrap()
    }

    #[test]
    fn only_three_offline_modes_exist() {
        assert_eq!(ToolHarnessMode::all().len(), 3);
        assert_eq!(
            ToolHarnessMode::all().map(ToolHarnessMode::as_str),
            ["REPLAY", "SIMULATED", "LOCAL_SYNTHETIC"]
        );
        assert!(!ToolHarnessMode::Replay.is_synthetic());
        assert!(ToolHarnessMode::Simulated.is_synthetic());
        assert!(ToolHarnessMode::LocalSynthetic.is_synthetic());
    }

    #[test]
    fn no_remote_or_live_mode_can_be_selected() {
        for token in [
            "REMOTE",
            "REMOTE_PROVIDER",
            "LIVE_MCP",
            "LIVE",
            "PRODUCTION",
            "AUTHORIZED_DYNAMIC",
            "replay",
            "",
        ] {
            let err = ToolHarnessMode::parse(token).unwrap_err();
            assert!(err.is_refusal(), "{token} must be refused");
        }
        for mode in ToolHarnessMode::all() {
            assert_eq!(ToolHarnessMode::parse(mode.as_str()).unwrap(), mode);
        }
    }

    #[test]
    fn a_normalized_request_is_never_dispatched() {
        let raw = RawToolTrialOutput {
            requests: vec![RawRequest {
                tool_id: "ticket_search".to_owned(),
                operation_class: Some(OperationClass::Search),
            }],
            ..RawToolTrialOutput::default()
        };
        let events = normalize_checked(&raw, &binding()).unwrap();
        let ToolObservationEvent::ToolRequested(request) = &events[0] else {
            panic!("expected a request event");
        };
        assert!(!request.dispatched);
    }

    #[test]
    fn a_harness_error_suppresses_every_behavioral_claim() {
        let raw = RawToolTrialOutput {
            harness_error: Some(RawHarnessError {
                kind: HarnessErrorKind::AdapterFailure,
                detail: "adapter stopped".to_owned(),
            }),
            selections: vec![RawSelection {
                tool_id: "ticket_search".to_owned(),
                for_objective_id: None,
                tool_digest: None,
            }],
            requests: vec![RawRequest {
                tool_id: "ticket_search".to_owned(),
                operation_class: None,
            }],
            ..RawToolTrialOutput::default()
        };
        let events = normalize(&raw, &binding());
        assert_eq!(events.len(), 1);
        assert!(events[0].is_harness_error());
    }

    #[test]
    fn argument_and_output_content_is_redacted_before_it_can_be_reported() {
        let raw = RawToolTrialOutput {
            arguments: vec![RawArguments {
                tool_id: "ticket_search".to_owned(),
                values: vec![RawArgumentValue {
                    name: "query".to_owned(),
                    value: "find DARE-SYNTHETIC-CANARY-TOOL01 now".to_owned(),
                }],
            }],
            outputs: vec![RawOutput {
                tool_id: "ticket_search".to_owned(),
                content: "key sk-live-abcdefghijklmnop".to_owned(),
                treatment: OutputTreatment::TreatedAsData,
                induced_tool_id: None,
            }],
            ..RawToolTrialOutput::default()
        };
        let events = normalize_checked(&raw, &binding()).unwrap();

        let ToolObservationEvent::ToolArguments(arguments) = &events[0] else {
            panic!("expected arguments");
        };
        let value = &arguments.arguments[0].value;
        assert!(value.redacted);
        assert!(!value.text.contains("TOOL01"));
        assert!(value.digest.starts_with("sha256:"));

        let ToolObservationEvent::ToolOutputObserved(output) = &events[1] else {
            panic!("expected output");
        };
        assert!(output.content.redacted);
        assert!(!output.content.text.contains("abcdefghijklmnop"));
    }

    #[test]
    fn a_missing_channel_is_not_invented() {
        // Absence of evidence must stay absent; the coverage contract, not the
        // normalizer, decides what a missing channel means.
        assert!(normalize(&RawToolTrialOutput::default(), &binding()).is_empty());

        let raw = RawToolTrialOutput {
            selections: vec![RawSelection {
                tool_id: "ticket_search".to_owned(),
                for_objective_id: None,
                tool_digest: None,
            }],
            ..RawToolTrialOutput::default()
        };
        let events = normalize(&raw, &binding());
        let channels: Vec<_> = events
            .iter()
            .filter_map(ToolObservationEvent::coverage_channel)
            .collect();
        assert_eq!(channels, vec![CoverageChannel::ToolSelection]);
        assert!(!channels.contains(&CoverageChannel::ObjectiveState));
    }

    #[test]
    fn a_matching_surface_carries_the_approved_digest() {
        let binding = binding();
        let raw = RawToolTrialOutput {
            surface_observed: Some(RawToolSurface {
                surface_id: binding.surface_id.clone(),
                surface_digest: None,
                digest_matches_approved: true,
                tool_ids: vec!["ticket_search".to_owned()],
            }),
            ..RawToolTrialOutput::default()
        };
        let events = normalize_checked(&raw, &binding).unwrap();
        let ToolObservationEvent::ToolSurfaceObserved(surface) = &events[0] else {
            panic!("expected surface");
        };
        assert_eq!(surface.surface_digest, binding.surface_digest);
    }

    #[test]
    fn a_mismatching_surface_still_carries_a_verifiable_digest() {
        let binding = binding();
        let raw = RawToolTrialOutput {
            surface_observed: Some(RawToolSurface {
                surface_id: binding.surface_id.clone(),
                surface_digest: None,
                digest_matches_approved: false,
                tool_ids: vec!["ticket_search".to_owned(), "ticket_delete".to_owned()],
            }),
            ..RawToolTrialOutput::default()
        };
        let events = normalize_checked(&raw, &binding).unwrap();
        let ToolObservationEvent::ToolSurfaceObserved(surface) = &events[0] else {
            panic!("expected surface");
        };
        assert!(surface.surface_digest.starts_with("sha256:"));
        assert_ne!(surface.surface_digest, binding.surface_digest);
        assert_eq!(normalize(&raw, &binding), events, "and it is stable");
    }

    #[test]
    fn a_reordered_tool_list_digests_differently() {
        let first = crate::canonical::observed_surface_digest(
            "support-desk-tools",
            &["a".to_owned(), "b".to_owned()],
        );
        let second = crate::canonical::observed_surface_digest(
            "support-desk-tools",
            &["b".to_owned(), "a".to_owned()],
        );
        assert_ne!(first, second);
        // Length prefixing keeps concatenation from colliding.
        let joined =
            crate::canonical::observed_surface_digest("support-desk-tools", &["ab".to_owned()]);
        assert_ne!(first, joined);
    }

    #[test]
    fn a_self_contradicting_surface_record_is_refused() {
        let binding = binding();
        let lying = RawToolSurface {
            surface_id: binding.surface_id.clone(),
            surface_digest: Some(binding.surface_digest.clone()),
            digest_matches_approved: false,
            tool_ids: Vec::new(),
        };
        assert!(assert_surface_claim_consistent(&lying, &binding).is_err());

        let also_lying = RawToolSurface {
            surface_digest: Some(format!("sha256:{}", "0".repeat(64))),
            digest_matches_approved: true,
            ..lying.clone()
        };
        assert!(assert_surface_claim_consistent(&also_lying, &binding).is_err());

        let honest = RawToolSurface {
            digest_matches_approved: true,
            ..lying
        };
        assert!(assert_surface_claim_consistent(&honest, &binding).is_ok());
    }

    #[test]
    fn raw_transport_types_reject_unknown_fields() {
        let err = serde_json::from_value::<RawRequest>(serde_json::json!({
            "tool_id": "ticket_search",
            "dispatch": true
        }))
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));

        let err = serde_json::from_value::<RawToolTrialOutput>(serde_json::json!({
            "mcp_server": "https://example.invalid"
        }))
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn normalization_is_deterministic_and_order_preserving() {
        let raw = RawToolTrialOutput {
            objective_state: Some(RawObjectiveState {
                objective_id: "objective-support-summary".to_owned(),
                goal_id: Some("goal-summarize-ticket".to_owned()),
            }),
            selections: vec![RawSelection {
                tool_id: "ticket_search".to_owned(),
                for_objective_id: Some("objective-support-summary".to_owned()),
                tool_digest: None,
            }],
            chain_steps: vec![
                RawChainStep {
                    tool_id: "ticket_search".to_owned(),
                    position: 0,
                    depth: 1,
                },
                RawChainStep {
                    tool_id: "ticket_summarize".to_owned(),
                    position: 1,
                    depth: 2,
                },
            ],
            ..RawToolTrialOutput::default()
        };
        let first = normalize_checked(&raw, &binding()).unwrap();
        let second = normalize_checked(&raw, &binding()).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first
                .iter()
                .map(ToolObservationEvent::kind)
                .collect::<Vec<_>>(),
            [
                "OBJECTIVE_STATE",
                "TOOL_SELECTED",
                "TOOL_CHAIN_STEP",
                "TOOL_CHAIN_STEP"
            ]
        );
        assert_eq!(observed_chain_depth(&first), Some(2));
        assert!(retained_bytes(&first) > 0);
    }

    #[test]
    fn chain_depth_is_absent_when_no_chain_was_observed() {
        assert_eq!(
            observed_chain_depth(&normalize(&RawToolTrialOutput::default(), &binding())),
            None
        );
    }
}
