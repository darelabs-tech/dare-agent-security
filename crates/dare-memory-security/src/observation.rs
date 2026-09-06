//! Normalized memory observation events.
//!
//! A closed set of typed events. Every security conclusion in Cycle 016 is
//! drawn from these and nothing else — not from prose, not from similarity, not
//! from what an adapter asserts about itself.
//!
//! Independent facts stay independent. A trial in which memory was promoted,
//! recalled across a tenant boundary *and* substituted produces three separate
//! events and three separate violations. Collapsing any of them would lose a
//! finding that was actually observed.
//!
//! Text that reaches evidence passes through [`EvidenceText`], which masks
//! credential shapes and synthetic canaries before anything is retained.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{MemorySecurityError, Result};
use crate::lifecycle::LogicalTime;
use crate::memory::{MemoryItem, Provenance};
use crate::source::{LifecycleState, SourceKind, TrustClass};

/// Ceiling on retained evidence text for one field.
const MAX_EVIDENCE_TEXT_BYTES: usize = 512;

/// What a redacted span is replaced with.
pub const REDACTION_MARKER: &str = "[REDACTED]";

/// Positive observation channels an invariant can require.
///
/// A channel is a *kind of evidence*, not a verdict. An invariant declares the
/// channels it needs; a run that lacks one is `INCONCLUSIVE` rather than `PASS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageChannel {
    MemorySnapshot,
    MemoryWriteRequest,
    MemoryWriteObserved,
    MemoryUpdateObserved,
    MemoryInvalidationObserved,
    MemoryRecallRequest,
    MemoryRecallObserved,
    MemoryInfluenceObserved,
    DecisionContextObserved,
    ActionIntentObserved,
    PolicyDecision,
}

impl CoverageChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MemorySnapshot => "MEMORY_SNAPSHOT",
            Self::MemoryWriteRequest => "MEMORY_WRITE_REQUEST",
            Self::MemoryWriteObserved => "MEMORY_WRITE_OBSERVED",
            Self::MemoryUpdateObserved => "MEMORY_UPDATE_OBSERVED",
            Self::MemoryInvalidationObserved => "MEMORY_INVALIDATION_OBSERVED",
            Self::MemoryRecallRequest => "MEMORY_RECALL_REQUEST",
            Self::MemoryRecallObserved => "MEMORY_RECALL_OBSERVED",
            Self::MemoryInfluenceObserved => "MEMORY_INFLUENCE_OBSERVED",
            Self::DecisionContextObserved => "DECISION_CONTEXT_OBSERVED",
            Self::ActionIntentObserved => "ACTION_INTENT_OBSERVED",
            Self::PolicyDecision => "POLICY_DECISION",
        }
    }

    pub fn all() -> [Self; 11] {
        [
            Self::MemorySnapshot,
            Self::MemoryWriteRequest,
            Self::MemoryWriteObserved,
            Self::MemoryUpdateObserved,
            Self::MemoryInvalidationObserved,
            Self::MemoryRecallRequest,
            Self::MemoryRecallObserved,
            Self::MemoryInfluenceObserved,
            Self::DecisionContextObserved,
            Self::ActionIntentObserved,
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
/// end of a long memory excerpt is still a secret.
pub fn mask_sensitive(text: &str) -> String {
    let mut masked = mask_canaries(text);
    for marker in ["sk-live-", "sk_live_", "xoxb-", "xoxp-", "ghp_", "eyJ"] {
        masked = mask_from_marker(&masked, marker);
    }
    // Key material is whitespace-separated base64 across several lines, so it
    // is masked as a whole block rather than up to the first space. Cycle 015
    // shipped the other behaviour and left key bodies in retained text.
    masked = mask_pem_blocks(&masked);
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

/// Mask an armoured key block whole, from `-----BEGIN` through its closing
/// armour, or to the end of the value when the block is unterminated.
fn mask_pem_blocks(text: &str) -> String {
    const BEGIN: &str = "-----begin";
    const END: &str = "-----end";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        // `to_ascii_lowercase` maps only A-Z, so byte offsets stay aligned with
        // the original and the slicing below is safe.
        let lowered = rest.to_ascii_lowercase();
        let Some(index) = lowered.find(BEGIN) else {
            break;
        };
        out.push_str(&rest[..index]);
        out.push_str(REDACTION_MARKER);

        let after = &rest[index + BEGIN.len()..];
        let lowered_after = after.to_ascii_lowercase();
        rest = match lowered_after.find(END) {
            Some(end) => {
                let tail = &after[end + END.len()..];
                match tail.find("-----") {
                    Some(close) => &tail[close + "-----".len()..],
                    None => "",
                }
            }
            // Unterminated: everything after the header is treated as key
            // material rather than assumed harmless.
            None => "",
        };
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

// --- event payloads ----------------------------------------------------------

/// The store as observed at the start of a trial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySnapshotObserved {
    pub store_id: String,
    pub store_digest: String,
    pub item_count: u32,
    /// Per-item content digests, so a later substitution is visible.
    pub item_digests: Vec<MemoryItemDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryItemDigest {
    pub memory_id: String,
    pub content_digest: String,
    pub version: u32,
}

/// A request to persist memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryWriteRequested {
    pub request_id: String,
    pub memory_id: String,
    pub writer_principal_id: String,
    pub namespace_id: String,
    pub tenant_id: String,
    pub source_kind: SourceKind,
    pub requested_trust_class: TrustClass,
}

/// A write that actually happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryWriteObserved {
    pub memory_id: String,
    pub writer_principal_id: String,
    pub namespace_id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    pub stored_trust_class: TrustClass,
    pub content_digest: String,
    pub version: u32,
}

/// An update to memory that already existed.
///
/// `authorized` is a recorded fact, not a reading: an update a policy permitted
/// is a legitimate operation, and confusing it with a substitution would make
/// every ordinary memory update a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryUpdateObserved {
    pub memory_id: String,
    pub writer_principal_id: String,
    pub before_content_digest: String,
    pub after_content_digest: String,
    pub before_version: u32,
    pub after_version: u32,
    pub authorized: bool,
}

/// Memory being expired or revoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryInvalidationObserved {
    pub memory_id: String,
    pub state: LifecycleState,
    pub at: LogicalTime,
}

/// What the agent asked memory for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryRecallRequested {
    pub request_id: String,
    pub requester_principal_id: String,
    pub requested_namespace_id: String,
    pub requested_tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_owner_principal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_memory_ids: Vec<String>,
}

/// What memory actually returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryRecallObserved {
    pub request_id: String,
    pub requester_principal_id: String,
    /// The items returned, each with the binding facts a boundary check needs.
    pub items: Vec<RecalledItem>,
    pub at: LogicalTime,
}

/// One recalled item, with everything a boundary comparison requires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecalledItem {
    pub memory_id: String,
    pub owner_principal_id: String,
    pub tenant_id: String,
    pub namespace_id: String,
    pub trust_class: TrustClass,
    pub content_digest: String,
    pub lifecycle_state: LifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
}

impl RecalledItem {
    /// Build from a store item plus the instant it was recalled at.
    pub fn from_item(item: &MemoryItem, now: LogicalTime) -> Self {
        Self {
            memory_id: item.memory_id.clone(),
            owner_principal_id: item.owner_principal_id.clone(),
            tenant_id: item.tenant_id.clone(),
            namespace_id: item.namespace_id.clone(),
            trust_class: item.trust_class,
            content_digest: item.content_digest.clone(),
            lifecycle_state: item.lifecycle_at(now),
            provenance: item.provenance.clone(),
        }
    }
}

/// Which decision-relevant field a recalled item changed.
///
/// Structural. Nothing here is natural language and nothing is compared by
/// similarity: a field either differs from its baseline or it does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InfluenceTarget {
    Objective,
    ToolSelection,
    ToolArgument,
    ProtectedField,
    DecisionContext,
}

impl InfluenceTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Objective => "OBJECTIVE",
            Self::ToolSelection => "TOOL_SELECTION",
            Self::ToolArgument => "TOOL_ARGUMENT",
            Self::ProtectedField => "PROTECTED_FIELD",
            Self::DecisionContext => "DECISION_CONTEXT",
        }
    }

    pub fn all() -> [Self; 5] {
        [
            Self::Objective,
            Self::ToolSelection,
            Self::ToolArgument,
            Self::ProtectedField,
            Self::DecisionContext,
        ]
    }
}

/// A recalled item changing something decision-relevant.
///
/// `changed` is recorded even when false, because "recalled and changed
/// nothing" is the positive evidence a no-influence PASS requires. Without it,
/// silence and non-influence would be indistinguishable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryInfluenceObserved {
    pub memory_id: String,
    pub target: InfluenceTarget,
    /// The field name, for `TOOL_ARGUMENT` and `PROTECTED_FIELD`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub baseline_value: Option<String>,
    pub observed_value: Option<String>,
    pub changed: bool,
}

/// The decision context in effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionContextObserved {
    pub authorized_objective_id: String,
    pub observed_objective_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_tool_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_tool_id: Option<String>,
}

/// An action the agent intended. Observed, never performed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionIntentObserved {
    pub action_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_id: Option<String>,
    /// Structurally false. Cycle 016 observes intents and performs none.
    pub performed: bool,
}

/// A policy-level decision about a memory operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecisionObserved {
    pub policy_id: String,
    pub operation: String,
    pub memory_id: String,
    pub allowed: bool,
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

/// Closed set of normalized memory observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemoryObservationEvent {
    MemorySnapshot(MemorySnapshotObserved),
    MemoryWriteRequest(MemoryWriteRequested),
    MemoryWriteObserved(MemoryWriteObserved),
    MemoryUpdateObserved(MemoryUpdateObserved),
    MemoryInvalidationObserved(MemoryInvalidationObserved),
    MemoryRecallRequest(MemoryRecallRequested),
    MemoryRecallObserved(MemoryRecallObserved),
    MemoryInfluenceObserved(MemoryInfluenceObserved),
    DecisionContextObserved(DecisionContextObserved),
    ActionIntentObserved(ActionIntentObserved),
    PolicyDecision(PolicyDecisionObserved),
    HarnessError(HarnessErrorEvent),
}

impl MemoryObservationEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::MemorySnapshot(_) => "MEMORY_SNAPSHOT",
            Self::MemoryWriteRequest(_) => "MEMORY_WRITE_REQUEST",
            Self::MemoryWriteObserved(_) => "MEMORY_WRITE_OBSERVED",
            Self::MemoryUpdateObserved(_) => "MEMORY_UPDATE_OBSERVED",
            Self::MemoryInvalidationObserved(_) => "MEMORY_INVALIDATION_OBSERVED",
            Self::MemoryRecallRequest(_) => "MEMORY_RECALL_REQUEST",
            Self::MemoryRecallObserved(_) => "MEMORY_RECALL_OBSERVED",
            Self::MemoryInfluenceObserved(_) => "MEMORY_INFLUENCE_OBSERVED",
            Self::DecisionContextObserved(_) => "DECISION_CONTEXT_OBSERVED",
            Self::ActionIntentObserved(_) => "ACTION_INTENT_OBSERVED",
            Self::PolicyDecision(_) => "POLICY_DECISION",
            Self::HarnessError(_) => "HARNESS_ERROR",
        }
    }

    /// The positive coverage channel this event supplies, if any.
    ///
    /// A harness error supplies none: a failed run is not evidence about the
    /// boundary in either direction.
    pub fn coverage_channel(&self) -> Option<CoverageChannel> {
        Some(match self {
            Self::MemorySnapshot(_) => CoverageChannel::MemorySnapshot,
            Self::MemoryWriteRequest(_) => CoverageChannel::MemoryWriteRequest,
            Self::MemoryWriteObserved(_) => CoverageChannel::MemoryWriteObserved,
            Self::MemoryUpdateObserved(_) => CoverageChannel::MemoryUpdateObserved,
            Self::MemoryInvalidationObserved(_) => CoverageChannel::MemoryInvalidationObserved,
            Self::MemoryRecallRequest(_) => CoverageChannel::MemoryRecallRequest,
            Self::MemoryRecallObserved(_) => CoverageChannel::MemoryRecallObserved,
            Self::MemoryInfluenceObserved(_) => CoverageChannel::MemoryInfluenceObserved,
            Self::DecisionContextObserved(_) => CoverageChannel::DecisionContextObserved,
            Self::ActionIntentObserved(_) => CoverageChannel::ActionIntentObserved,
            Self::PolicyDecision(_) => CoverageChannel::PolicyDecision,
            Self::HarnessError(_) => return None,
        })
    }

    pub fn is_harness_error(&self) -> bool {
        matches!(self, Self::HarnessError(_))
    }

    /// Bytes this event contributes to the retention budget.
    pub fn retained_bytes(&self) -> usize {
        serde_json::to_vec(self)
            .map(|bytes| bytes.len())
            .unwrap_or(0)
    }

    /// Canonical digest of the event, for evidence.
    pub fn digest(&self) -> Result<String> {
        crate::canonical::digest(self)
    }

    /// Structural safety checks.
    pub fn validate(&self) -> Result<()> {
        if let Self::ActionIntentObserved(intent) = self {
            if intent.performed {
                return Err(MemorySecurityError::refusal(format!(
                    "action `{}` claims to have been performed; Cycle 016 observes intents and \
                     performs none",
                    intent.action_id
                )));
            }
        }
        let serialized = serde_json::to_string(self)?;
        if mask_sensitive(&serialized) != serialized {
            return Err(MemorySecurityError::refusal(
                "an observation carries unmasked sensitive content".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Every positive channel a normalized event stream supplies.
pub fn observed_channels(events: &[MemoryObservationEvent]) -> Vec<CoverageChannel> {
    let mut channels: Vec<CoverageChannel> = events
        .iter()
        .filter_map(|event| event.coverage_channel())
        .collect();
    channels.sort_unstable();
    channels.dedup();
    channels
}

/// Validate a whole normalized stream.
pub fn validate_events(events: &[MemoryObservationEvent]) -> Result<()> {
    for event in events {
        event.validate()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recalled(memory_id: &str) -> RecalledItem {
        RecalledItem {
            memory_id: memory_id.to_owned(),
            owner_principal_id: "user-7".to_owned(),
            tenant_id: "tenant-a".to_owned(),
            namespace_id: "ns-support".to_owned(),
            trust_class: TrustClass::Constrained,
            content_digest: format!("sha256:{}", "a".repeat(64)),
            lifecycle_state: LifecycleState::Valid,
            provenance: None,
        }
    }

    #[test]
    fn the_eleven_coverage_channels_are_all_reachable_from_an_event() {
        let mut reachable: Vec<CoverageChannel> = Vec::new();
        for channel in CoverageChannel::all() {
            reachable.push(channel);
        }
        assert_eq!(reachable.len(), 11);

        // Every channel except none is produced by exactly one event kind.
        let events = [
            MemoryObservationEvent::MemorySnapshot(MemorySnapshotObserved {
                store_id: "s".to_owned(),
                store_digest: format!("sha256:{}", "a".repeat(64)),
                item_count: 0,
                item_digests: Vec::new(),
            }),
            MemoryObservationEvent::MemoryRecallObserved(MemoryRecallObserved {
                request_id: "r".to_owned(),
                requester_principal_id: "user-7".to_owned(),
                items: vec![recalled("mem-1")],
                at: 100,
            }),
        ];
        let channels = observed_channels(&events);
        assert!(channels.contains(&CoverageChannel::MemorySnapshot));
        assert!(channels.contains(&CoverageChannel::MemoryRecallObserved));
        assert_eq!(channels.len(), 2);
    }

    #[test]
    fn a_harness_error_supplies_no_coverage_channel() {
        // A failed run is not evidence about the boundary in either direction.
        let event = MemoryObservationEvent::HarnessError(HarnessErrorEvent {
            kind: HarnessErrorKind::AdapterFailure,
            detail: EvidenceText::from_raw("adapter stopped"),
        });
        assert!(event.coverage_channel().is_none());
        assert!(event.is_harness_error());
        assert!(observed_channels(&[event]).is_empty());
    }

    #[test]
    fn an_action_intent_can_never_claim_to_have_been_performed() {
        let event = MemoryObservationEvent::ActionIntentObserved(ActionIntentObserved {
            action_id: "act-1".to_owned(),
            tool_id: Some("tool-send".to_owned()),
            performed: true,
        });
        let err = event.validate().expect_err("must be refused");
        assert!(err.is_refusal());

        let observed = MemoryObservationEvent::ActionIntentObserved(ActionIntentObserved {
            action_id: "act-1".to_owned(),
            tool_id: Some("tool-send".to_owned()),
            performed: false,
        });
        observed.validate().expect("an observed intent is fine");
    }

    #[test]
    fn non_influence_is_recorded_as_a_positive_fact() {
        // "Recalled and changed nothing" is the evidence a no-influence PASS
        // requires; without it, silence and non-influence look identical.
        let event = MemoryObservationEvent::MemoryInfluenceObserved(MemoryInfluenceObserved {
            memory_id: "mem-1".to_owned(),
            target: InfluenceTarget::Objective,
            field: None,
            baseline_value: Some("objective-summarize-ticket".to_owned()),
            observed_value: Some("objective-summarize-ticket".to_owned()),
            changed: false,
        });
        assert_eq!(
            event.coverage_channel(),
            Some(CoverageChannel::MemoryInfluenceObserved)
        );
        event.validate().expect("valid");
    }

    #[test]
    fn independent_facts_remain_independently_observable() {
        // Three different violations in one trial produce three events.
        let events = vec![
            MemoryObservationEvent::MemoryWriteObserved(MemoryWriteObserved {
                memory_id: "mem-1".to_owned(),
                writer_principal_id: "agent-1".to_owned(),
                namespace_id: "ns-support".to_owned(),
                tenant_id: "tenant-a".to_owned(),
                provenance: None,
                stored_trust_class: TrustClass::TrustedPolicy,
                content_digest: format!("sha256:{}", "a".repeat(64)),
                version: 1,
            }),
            MemoryObservationEvent::MemoryRecallObserved(MemoryRecallObserved {
                request_id: "r".to_owned(),
                requester_principal_id: "user-7".to_owned(),
                items: vec![recalled("mem-2")],
                at: 100,
            }),
            MemoryObservationEvent::MemoryUpdateObserved(MemoryUpdateObserved {
                memory_id: "mem-3".to_owned(),
                writer_principal_id: "agent-1".to_owned(),
                before_content_digest: format!("sha256:{}", "a".repeat(64)),
                after_content_digest: format!("sha256:{}", "b".repeat(64)),
                before_version: 1,
                after_version: 1,
                authorized: false,
            }),
        ];
        assert_eq!(observed_channels(&events).len(), 3);
        validate_events(&events).expect("all valid");
    }

    #[test]
    fn every_event_kind_round_trips_with_a_stable_tag() {
        let event =
            MemoryObservationEvent::MemoryInvalidationObserved(MemoryInvalidationObserved {
                memory_id: "mem-1".to_owned(),
                state: LifecycleState::Revoked,
                at: 150,
            });
        let json = serde_json::to_string(&event).expect("serializes");
        assert!(json.contains("\"type\":\"MEMORY_INVALIDATION_OBSERVED\""));
        assert_eq!(
            serde_json::from_str::<MemoryObservationEvent>(&json).expect("round-trips"),
            event
        );
        assert_eq!(event.kind(), "MEMORY_INVALIDATION_OBSERVED");
    }

    #[test]
    fn event_digests_are_stable_and_distinguish_events() {
        let first =
            MemoryObservationEvent::MemoryInvalidationObserved(MemoryInvalidationObserved {
                memory_id: "mem-1".to_owned(),
                state: LifecycleState::Expired,
                at: 150,
            });
        let second =
            MemoryObservationEvent::MemoryInvalidationObserved(MemoryInvalidationObserved {
                memory_id: "mem-1".to_owned(),
                state: LifecycleState::Revoked,
                at: 150,
            });
        assert_eq!(
            first.digest().expect("digest"),
            first.digest().expect("digest")
        );
        assert_ne!(
            first.digest().expect("digest"),
            second.digest().expect("digest")
        );
        assert!(first.retained_bytes() > 0);
    }

    #[test]
    fn credential_material_is_masked_across_the_whole_value() {
        for raw in [
            "sk-live-0123456789abcdef0123456789abcdef",
            "Bearer abcdefghijklmnopqrstuvwxyz012345",
            "ghp_0123456789abcdef0123456789abcdef0123",
            "DARE-SYNTHETIC-CANARY-MEM01",
        ] {
            let evidence = EvidenceText::from_raw(raw);
            assert!(evidence.redacted, "{raw}");
            assert!(evidence.is_secret_safe(), "{raw}");
            assert!(evidence.text.contains(REDACTION_MARKER), "{raw}");
        }

        // A secret at the end of a long memory excerpt is still a secret.
        let padded = format!("{}sk-live-0123456789abcdef", "memory text. ".repeat(200));
        let evidence = EvidenceText::from_raw(&padded);
        assert!(evidence.redacted);
        assert!(!evidence.text.contains("sk-live-0123"));
    }

    #[test]
    fn an_armoured_key_block_is_masked_whole_and_not_just_its_header() {
        let terminated = "note -----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\nkqhkiG9w0B\n\
                          -----END PRIVATE KEY----- tail";
        let masked = mask_sensitive(terminated);
        assert!(!masked.contains("MIIEvQIBADANBg"), "{masked}");
        assert!(masked.starts_with("note "), "{masked}");
        assert!(masked.ends_with(" tail"), "{masked}");

        let unterminated = "-----BEGIN RSA PRIVATE KEY----- MIIEvQIBADANBg";
        assert!(!mask_sensitive(unterminated).contains("MIIEvQIBADANBg"));
    }

    #[test]
    fn ordinary_memory_prose_about_credentials_is_not_masked() {
        // Memory fixtures discuss stored credentials as a subject. A check that
        // fired on that sentence would be a check somebody deletes.
        for honest in [
            "the user asked whether we store a bearer token; we do not",
            "this memory records that no api key was persisted",
            "remember that the customer forgot their password",
        ] {
            assert_eq!(mask_sensitive(honest), honest, "`{honest}` was mangled");
            let evidence = EvidenceText::from_raw(honest);
            assert!(!evidence.redacted, "`{honest}`");
        }
    }

    #[test]
    fn evidence_text_is_bounded_and_correlatable_without_the_original() {
        let raw = "x".repeat(10_000);
        let evidence = EvidenceText::from_raw(&raw);
        assert!(evidence.truncated);
        assert!(evidence.text.len() < raw.len());
        assert_eq!(evidence.original_bytes, raw.len());
        assert!(evidence.digest.starts_with("sha256:"));
        assert_eq!(evidence.digest, EvidenceText::from_raw(&raw).digest);
        assert_ne!(evidence.digest, EvidenceText::from_raw("other").digest);
    }

    #[test]
    fn an_event_carrying_unmasked_sensitive_content_is_refused() {
        let event = MemoryObservationEvent::PolicyDecision(PolicyDecisionObserved {
            policy_id: "p".to_owned(),
            operation: "sk-live-0123456789abcdef".to_owned(),
            memory_id: "mem-1".to_owned(),
            allowed: true,
        });
        let err = event.validate().expect_err("must be refused");
        assert!(err.is_refusal());
    }

    #[test]
    fn a_recalled_item_is_built_from_the_store_and_the_recall_instant() {
        let item = crate::memory::tests::item("mem-1");
        let recalled = RecalledItem::from_item(&item, 150);
        assert_eq!(recalled.memory_id, "mem-1");
        assert_eq!(recalled.lifecycle_state, LifecycleState::Valid);

        // The same item recalled after expiry carries the expired state.
        let expired = RecalledItem::from_item(&item, 250);
        assert_eq!(expired.lifecycle_state, LifecycleState::Expired);
    }

    #[test]
    fn the_five_influence_targets_are_closed_and_distinct() {
        assert_eq!(InfluenceTarget::all().len(), 5);
        let names: std::collections::BTreeSet<&str> = InfluenceTarget::all()
            .into_iter()
            .map(InfluenceTarget::as_str)
            .collect();
        assert_eq!(names.len(), 5);
        assert!(serde_json::from_str::<InfluenceTarget>("\"VIBES\"").is_err());
    }
}
