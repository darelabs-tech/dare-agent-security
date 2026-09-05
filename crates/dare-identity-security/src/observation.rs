//! Normalized identity observation events.
//!
//! A closed set of typed facts. Every verdict in this cycle is computed from
//! these and nothing else — no prose, no similarity score, no classifier.
//!
//! Two properties are structural rather than documented:
//!
//! - **independent facts stay independent.** Principal substitution, tenant
//!   crossing and privilege amplification are separate events, so a trace where
//!   all three are true produces all three, and no evaluator can collapse them;
//! - **credential material cannot be represented.** A `CREDENTIAL_CONTEXT`
//!   carries an identifier, an owner and capability labels. There is no field a
//!   token could occupy, and text that reaches evidence is masked first.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::authority::{Authority, LogicalTime};
use crate::authorization::DecisionEffect;
use crate::error::{IdentitySecurityError, Result};
use crate::operation::Operation;
use crate::resource::ResourceContext;
use crate::source::{DelegationKind, PrincipalKind, PrincipalRole};

/// Marker substituted for redacted content.
pub const REDACTION_MARKER: &str = "[REDACTED]";

/// Ceiling on retained evidence text.
pub const MAX_EVIDENCE_TEXT_BYTES: usize = 512;

/// The positive evidence channels an invariant can require.
///
/// This enum is the mechanism behind "absence of evidence is not evidence of
/// absence". An invariant names the channels it needs, and a missing channel
/// yields `INCONCLUSIVE` rather than `PASS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageChannel {
    PrincipalContext,
    EffectiveAuthority,
    DelegationEdge,
    DelegationAssertion,
    ResourceContext,
    CredentialContext,
    AuthorizationDecision,
    OperationRequest,
    FinalOperation,
    PolicyDecision,
}

impl CoverageChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrincipalContext => "PRINCIPAL_CONTEXT",
            Self::EffectiveAuthority => "EFFECTIVE_AUTHORITY",
            Self::DelegationEdge => "DELEGATION_EDGE",
            Self::DelegationAssertion => "DELEGATION_ASSERTION",
            Self::ResourceContext => "RESOURCE_CONTEXT",
            Self::CredentialContext => "CREDENTIAL_CONTEXT",
            Self::AuthorizationDecision => "AUTHORIZATION_DECISION",
            Self::OperationRequest => "OPERATION_REQUEST",
            Self::FinalOperation => "FINAL_OPERATION",
            Self::PolicyDecision => "POLICY_DECISION",
        }
    }

    pub fn all() -> [Self; 10] {
        [
            Self::PrincipalContext,
            Self::EffectiveAuthority,
            Self::DelegationEdge,
            Self::DelegationAssertion,
            Self::ResourceContext,
            Self::CredentialContext,
            Self::AuthorizationDecision,
            Self::OperationRequest,
            Self::FinalOperation,
            Self::PolicyDecision,
        ]
    }
}

/// Operator-safe evidence text.
///
/// Carries a digest of the original so occurrences can be correlated without
/// the original ever being retained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceText {
    pub text: String,
    pub digest: String,
    pub original_bytes: usize,
    pub redacted: bool,
    pub truncated: bool,
}

impl EvidenceText {
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
/// Scans the whole bounded value rather than a prefix. A secret pasted at the
/// end of a long string is still a secret.
pub fn mask_sensitive(text: &str) -> String {
    let mut masked = mask_canaries(text);
    for marker in [
        "sk-live-",
        "sk_live_",
        "xoxb-",
        "ghp_",
        "eyJ",
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
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find(marker) {
        out.push_str(&rest[..index]);
        out.push_str(REDACTION_MARKER);
        let after = &rest[index + marker.len()..];
        let tail = after
            .find(|c: char| {
                !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '/' | '='))
            })
            .unwrap_or(after.len());
        rest = &after[tail..];
    }
    out.push_str(rest);
    out
}

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

/// A principal observed filling a role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalContext {
    pub role: PrincipalRole,
    pub principal_id: String,
    pub kind: PrincipalKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

/// The authority actually exercised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveAuthorityObserved {
    pub principal_id: String,
    pub authority: Authority,
    /// The ceiling this authority is claimed to derive from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ceiling_id: Option<String>,
}

/// A delegation edge observed in use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationEdgeObserved {
    pub edge_id: String,
    pub kind: DelegationKind,
    pub delegator_principal_id: String,
    pub delegatee_principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_subject_id: Option<String>,
    pub authority_ceiling_id: String,
}

/// A delegation asserted without a full edge being observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationAssertion {
    pub asserted_by_principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_subject_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose_id: Option<String>,
    /// Whether the scenario's declared chain actually contains this delegation.
    ///
    /// A recorded fact, not a reading: an assertion that nothing backs is how a
    /// delegation gets claimed rather than granted.
    pub backed_by_declared_chain: bool,
}

/// Synthetic credential metadata.
///
/// Describes what a runtime identity *could* do. That is capability
/// availability, which is not authority: nothing here grants anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialContextObserved {
    pub credential_context_id: String,
    pub owner_principal_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tenant_labels: Vec<String>,
    /// The authority this credential would confer if it had been delegated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_authority: Option<Authority>,
}

/// An authorization decision observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationDecisionObserved {
    pub decision_id: String,
    pub effect: DecisionEffect,
    pub subject_id: String,
    pub policy_digest: String,
    pub bound_operation_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<LogicalTime>,
}

/// An operation requested or finally performed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationObserved {
    pub operation: Operation,
    pub projection_digest: String,
    /// Structurally false. Cycle 015 observes operations and never performs one.
    pub dispatched: bool,
}

/// A policy-level decision about a named operation key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecisionObserved {
    pub operation_key: String,
    pub effect: DecisionEffect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
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

/// Closed set of normalized identity observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityObservationEvent {
    PrincipalContext(PrincipalContext),
    EffectiveAuthority(EffectiveAuthorityObserved),
    DelegationEdge(DelegationEdgeObserved),
    DelegationAssertion(DelegationAssertion),
    ResourceContext(ResourceContext),
    CredentialContext(CredentialContextObserved),
    AuthorizationDecision(AuthorizationDecisionObserved),
    OperationRequest(OperationObserved),
    FinalOperation(OperationObserved),
    PolicyDecision(PolicyDecisionObserved),
    HarnessError(HarnessErrorEvent),
}

impl IdentityObservationEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::PrincipalContext(_) => "PRINCIPAL_CONTEXT",
            Self::EffectiveAuthority(_) => "EFFECTIVE_AUTHORITY",
            Self::DelegationEdge(_) => "DELEGATION_EDGE",
            Self::DelegationAssertion(_) => "DELEGATION_ASSERTION",
            Self::ResourceContext(_) => "RESOURCE_CONTEXT",
            Self::CredentialContext(_) => "CREDENTIAL_CONTEXT",
            Self::AuthorizationDecision(_) => "AUTHORIZATION_DECISION",
            Self::OperationRequest(_) => "OPERATION_REQUEST",
            Self::FinalOperation(_) => "FINAL_OPERATION",
            Self::PolicyDecision(_) => "POLICY_DECISION",
            Self::HarnessError(_) => "HARNESS_ERROR",
        }
    }

    /// The positive coverage channel this event supplies, if any.
    ///
    /// A harness error supplies none: a failed trial is not evidence about the
    /// boundary in either direction.
    pub fn coverage_channel(&self) -> Option<CoverageChannel> {
        Some(match self {
            Self::PrincipalContext(_) => CoverageChannel::PrincipalContext,
            Self::EffectiveAuthority(_) => CoverageChannel::EffectiveAuthority,
            Self::DelegationEdge(_) => CoverageChannel::DelegationEdge,
            Self::DelegationAssertion(_) => CoverageChannel::DelegationAssertion,
            Self::ResourceContext(_) => CoverageChannel::ResourceContext,
            Self::CredentialContext(_) => CoverageChannel::CredentialContext,
            Self::AuthorizationDecision(_) => CoverageChannel::AuthorizationDecision,
            Self::OperationRequest(_) => CoverageChannel::OperationRequest,
            Self::FinalOperation(_) => CoverageChannel::FinalOperation,
            Self::PolicyDecision(_) => CoverageChannel::PolicyDecision,
            Self::HarnessError(_) => return None,
        })
    }

    pub fn is_harness_error(&self) -> bool {
        matches!(self, Self::HarnessError(_))
    }

    /// Retained byte cost, charged against the output budget.
    pub fn retained_bytes(&self) -> usize {
        match self {
            Self::PrincipalContext(context) => context.principal_id.len(),
            Self::EffectiveAuthority(observed) => observed.principal_id.len(),
            Self::DelegationEdge(edge) => edge.edge_id.len(),
            Self::DelegationAssertion(assertion) => assertion.asserted_by_principal_id.len(),
            Self::ResourceContext(resource) => {
                resource.resource_id.len() + resource.tenant_id.len()
            }
            Self::CredentialContext(credential) => {
                credential.credential_context_id.len()
                    + credential
                        .capability_labels
                        .iter()
                        .map(String::len)
                        .sum::<usize>()
            }
            Self::AuthorizationDecision(decision) => decision.decision_id.len(),
            Self::OperationRequest(operation) | Self::FinalOperation(operation) => {
                operation.operation.operation_id.len() + operation.projection_digest.len()
            }
            Self::PolicyDecision(decision) => decision.operation_key.len(),
            Self::HarnessError(error) => error.detail.text.len(),
        }
    }

    /// Reject structurally impossible or unsafe events.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::OperationRequest(observed) | Self::FinalOperation(observed) => {
                if observed.dispatched {
                    return Err(IdentitySecurityError::refusal(
                        "observation claims an operation was dispatched; Cycle 015 observes \
                         operations and never performs one",
                    ));
                }
                if !observed.projection_digest.starts_with("sha256:") {
                    return Err(IdentitySecurityError::invalid(
                        "operation observation requires a sha256 projection digest",
                    ));
                }
                observed.operation.validate()
            }
            Self::PrincipalContext(context) => {
                if context.principal_id.trim().is_empty() {
                    return Err(IdentitySecurityError::invalid("empty principal identifier"));
                }
                Ok(())
            }
            Self::AuthorizationDecision(decision) => {
                if !decision.bound_operation_digest.starts_with("sha256:") {
                    return Err(IdentitySecurityError::invalid(
                        "authorization decision requires a sha256 bound-operation digest",
                    ));
                }
                Ok(())
            }
            Self::CredentialContext(credential) => {
                // A credential context is metadata. If a label ever carried
                // secret material, evidence would persist it.
                for label in credential
                    .capability_labels
                    .iter()
                    .chain(credential.tenant_labels.iter())
                {
                    crate::schema::assert_no_credential_value(label, "credential context")?;
                }
                Ok(())
            }
            Self::HarnessError(error) => {
                if !error.detail.is_secret_safe() {
                    return Err(IdentitySecurityError::refusal(
                        "harness error detail still contains sensitive content",
                    ));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Stable digest of the normalized event, bound into evidence.
    pub fn digest(&self) -> Result<String> {
        crate::canonical::digest(self)
    }
}

/// Every coverage channel present in a normalized event stream.
pub fn observed_channels(
    events: &[IdentityObservationEvent],
) -> std::collections::BTreeSet<CoverageChannel> {
    events
        .iter()
        .filter_map(IdentityObservationEvent::coverage_channel)
        .collect()
}

/// Validate a whole event stream.
pub fn validate_events(events: &[IdentityObservationEvent]) -> Result<()> {
    for event in events {
        event.validate()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operation::tests::authorized_operation;
    use serde_json::json;

    fn observed(operation: Operation) -> OperationObserved {
        let projection_digest = operation.projection_digest().expect("digest");
        OperationObserved {
            operation,
            projection_digest,
            dispatched: false,
        }
    }

    #[test]
    fn every_event_kind_round_trips_with_a_stable_tag() {
        let events = vec![
            IdentityObservationEvent::PrincipalContext(PrincipalContext {
                role: PrincipalRole::Initiating,
                principal_id: "user-7".to_owned(),
                kind: PrincipalKind::Human,
                tenant_id: Some("tenant-a".to_owned()),
            }),
            IdentityObservationEvent::OperationRequest(observed(authorized_operation())),
        ];
        for event in events {
            let encoded = serde_json::to_value(&event).expect("serializes");
            assert_eq!(encoded["type"], json!(event.kind()));
            let decoded: IdentityObservationEvent =
                serde_json::from_value(encoded).expect("round trips");
            assert_eq!(decoded, event);
        }
    }

    #[test]
    fn the_ten_coverage_channels_are_all_reachable() {
        // Every channel an invariant can require must be suppliable by some
        // event, or the requirement would be unsatisfiable by construction.
        assert_eq!(CoverageChannel::all().len(), 10);
        let events = vec![
            IdentityObservationEvent::PrincipalContext(PrincipalContext {
                role: PrincipalRole::Effective,
                principal_id: "user-7".to_owned(),
                kind: PrincipalKind::Human,
                tenant_id: None,
            }),
            IdentityObservationEvent::EffectiveAuthority(EffectiveAuthorityObserved {
                principal_id: "user-7".to_owned(),
                authority: Authority::empty("authority-x"),
                source_ceiling_id: None,
            }),
            IdentityObservationEvent::DelegationEdge(DelegationEdgeObserved {
                edge_id: "edge-1".to_owned(),
                kind: DelegationKind::OnBehalfOf,
                delegator_principal_id: "user-7".to_owned(),
                delegatee_principal_id: "agent-1".to_owned(),
                delegated_subject_id: Some("user-7".to_owned()),
                authority_ceiling_id: "authority-x".to_owned(),
            }),
            IdentityObservationEvent::DelegationAssertion(DelegationAssertion {
                asserted_by_principal_id: "agent-1".to_owned(),
                delegated_subject_id: Some("user-7".to_owned()),
                purpose_id: None,
                backed_by_declared_chain: true,
            }),
            IdentityObservationEvent::ResourceContext(
                crate::resource::tests::same_tenant_resource(),
            ),
            IdentityObservationEvent::CredentialContext(CredentialContextObserved {
                credential_context_id: "cred-1".to_owned(),
                owner_principal_id: "svc-index".to_owned(),
                capability_labels: vec!["index.admin".to_owned()],
                tenant_labels: vec!["tenant-a".to_owned()],
                capability_authority: None,
            }),
            IdentityObservationEvent::AuthorizationDecision(AuthorizationDecisionObserved {
                decision_id: "decision-1".to_owned(),
                effect: DecisionEffect::Permit,
                subject_id: "user-7".to_owned(),
                policy_digest: format!("sha256:{}", "a".repeat(64)),
                bound_operation_digest: format!("sha256:{}", "b".repeat(64)),
                issued_at: Some(100),
            }),
            IdentityObservationEvent::OperationRequest(observed(authorized_operation())),
            IdentityObservationEvent::FinalOperation(observed(authorized_operation())),
            IdentityObservationEvent::PolicyDecision(PolicyDecisionObserved {
                operation_key: "document.delete".to_owned(),
                effect: DecisionEffect::Deny,
                policy_id: Some("policy-support-desk".to_owned()),
            }),
        ];

        let channels = observed_channels(&events);
        assert_eq!(channels.len(), 10, "every channel must be reachable");
        for channel in CoverageChannel::all() {
            assert!(channels.contains(&channel), "{}", channel.as_str());
        }
    }

    #[test]
    fn a_harness_error_supplies_no_coverage_channel() {
        // A failed trial is not evidence about the boundary in either
        // direction, so it must not satisfy any invariant's requirement.
        let error = IdentityObservationEvent::HarnessError(HarnessErrorEvent {
            kind: HarnessErrorKind::AdapterFailure,
            detail: EvidenceText::from_raw("adapter stopped"),
        });
        assert_eq!(error.coverage_channel(), None);
        assert!(error.is_harness_error());
        assert!(observed_channels(std::slice::from_ref(&error)).is_empty());
    }

    #[test]
    fn an_operation_can_never_be_recorded_as_dispatched() {
        let mut event = observed(authorized_operation());
        event.dispatched = true;
        let err = IdentityObservationEvent::FinalOperation(event)
            .validate()
            .expect_err("must be refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("never performs one"));
    }

    #[test]
    fn independent_facts_remain_independently_observable() {
        // Principal substitution, tenant crossing and privilege amplification
        // are three events, not one summary. An evaluator cannot collapse what
        // the stream keeps separate.
        let events = [
            IdentityObservationEvent::PrincipalContext(PrincipalContext {
                role: PrincipalRole::Effective,
                principal_id: "svc-index".to_owned(),
                kind: PrincipalKind::Service,
                tenant_id: Some("tenant-a".to_owned()),
            }),
            IdentityObservationEvent::ResourceContext(ResourceContext {
                resource_id: "document-999".to_owned(),
                resource_type: "document".to_owned(),
                tenant_id: "tenant-b".to_owned(),
                owner_principal_id: "user-7".to_owned(),
                classification: None,
            }),
            IdentityObservationEvent::EffectiveAuthority(EffectiveAuthorityObserved {
                principal_id: "svc-index".to_owned(),
                authority: Authority::empty("authority-admin"),
                source_ceiling_id: Some("authority-user-read".to_owned()),
            }),
        ];
        assert_eq!(events.len(), 3);
        let kinds: Vec<&str> = events.iter().map(IdentityObservationEvent::kind).collect();
        assert_eq!(
            kinds,
            [
                "PRINCIPAL_CONTEXT",
                "RESOURCE_CONTEXT",
                "EFFECTIVE_AUTHORITY"
            ]
        );
    }

    #[test]
    fn credential_material_is_masked_across_the_whole_value() {
        for secret in [
            "sk-live-4f9c2ab117de",
            "xoxb-1234-5678-abcdef",
            "ghp_abcdefghijklmnopqrstuvwxyz",
            "Bearer ya29.a0ARrdaM9tokenlikevalue",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "-----BEGIN PRIVATE KEY-----MIIEvQ",
            "DARE-SYNTHETIC-CANARY-IDENT01",
        ] {
            let evidence = EvidenceText::from_raw(&format!("context {secret} recorded"));
            assert!(evidence.redacted, "{secret} was not redacted");
            assert!(evidence.is_secret_safe(), "{secret} survived masking");
            assert!(evidence.text.contains(REDACTION_MARKER));
            assert!(evidence.digest.starts_with("sha256:"));
        }

        // The scan covers the whole bounded value, not a prefix.
        let long = format!("{}sk-live-tail", "a".repeat(400));
        assert!(!mask_sensitive(&long).contains("sk-live-tail"));
    }

    #[test]
    fn ordinary_prose_about_credentials_is_not_masked() {
        // Otherwise every honest description of the boundary becomes
        // unreadable in evidence.
        let evidence = EvidenceText::from_raw("the delegation issues no bearer token at all");
        assert!(!evidence.redacted);
        assert_eq!(
            evidence.text,
            "the delegation issues no bearer token at all"
        );
    }

    #[test]
    fn a_credential_context_label_cannot_carry_a_secret() {
        let event = IdentityObservationEvent::CredentialContext(CredentialContextObserved {
            credential_context_id: "cred-1".to_owned(),
            owner_principal_id: "svc-index".to_owned(),
            capability_labels: vec!["sk-live-4f9c2ab117de".to_owned()],
            tenant_labels: Vec::new(),
            capability_authority: None,
        });
        assert!(event.validate().is_err());
    }

    #[test]
    fn evidence_text_is_truncated_at_the_bound() {
        let evidence = EvidenceText::from_raw(&"x".repeat(MAX_EVIDENCE_TEXT_BYTES + 100));
        assert!(evidence.truncated);
        assert!(evidence.redacted);
        assert_eq!(evidence.text.len(), MAX_EVIDENCE_TEXT_BYTES);
        assert_eq!(evidence.original_bytes, MAX_EVIDENCE_TEXT_BYTES + 100);
    }

    #[test]
    fn event_digests_are_stable_and_distinguish_events() {
        let one = IdentityObservationEvent::PrincipalContext(PrincipalContext {
            role: PrincipalRole::Effective,
            principal_id: "user-7".to_owned(),
            kind: PrincipalKind::Human,
            tenant_id: None,
        });
        let other = IdentityObservationEvent::PrincipalContext(PrincipalContext {
            role: PrincipalRole::Effective,
            principal_id: "agent-1".to_owned(),
            kind: PrincipalKind::Agent,
            tenant_id: None,
        });
        assert_eq!(one.digest().expect("digest"), one.digest().expect("digest"));
        assert_ne!(
            one.digest().expect("digest"),
            other.digest().expect("digest")
        );
    }

    #[test]
    fn an_unknown_event_type_fails_closed() {
        let hostile = json!({"type": "TOKEN_ISSUED", "token": "abc"});
        assert!(serde_json::from_value::<IdentityObservationEvent>(hostile).is_err());
    }

    #[test]
    fn a_decision_event_requires_a_bound_operation_digest() {
        let event =
            IdentityObservationEvent::AuthorizationDecision(AuthorizationDecisionObserved {
                decision_id: "decision-1".to_owned(),
                effect: DecisionEffect::Permit,
                subject_id: "user-7".to_owned(),
                policy_digest: format!("sha256:{}", "a".repeat(64)),
                bound_operation_digest: "none".to_owned(),
                issued_at: None,
            });
        assert!(event.validate().is_err());
    }

    #[test]
    fn a_stream_validates_as_a_whole() {
        let events = vec![
            IdentityObservationEvent::PrincipalContext(PrincipalContext {
                role: PrincipalRole::Initiating,
                principal_id: "user-7".to_owned(),
                kind: PrincipalKind::Human,
                tenant_id: None,
            }),
            IdentityObservationEvent::FinalOperation(observed(authorized_operation())),
        ];
        validate_events(&events).expect("valid stream");
        assert!(
            events
                .iter()
                .map(IdentityObservationEvent::retained_bytes)
                .sum::<usize>()
                > 0
        );
    }
}
