//! Harness contract and the deterministic normalizer.
//!
//! Adapters are dumb transports: they surface what was observed and decide
//! nothing. Every security-relevant classification happens in the evaluator,
//! over the typed events [`normalize`] produces.
//!
//! Cycle 016 has three approved modes, all local and offline. There is no
//! Redis, PostgreSQL, vector-database, SaaS-memory or MCP client, and
//! [`HarnessMode`] has no variant that could name one.
//!
//! Two properties are structural rather than documented:
//!
//! - an observed action intent always carries `performed: false`, because
//!   nothing in this crate can perform one;
//! - a missing channel stays missing. The normalizer never invents a snapshot,
//!   a recall or an influence to fill a gap, so the coverage contract can say
//!   `INCONCLUSIVE` rather than being handed a fabricated `PASS`.

use serde::{Deserialize, Serialize};

use crate::error::{MemorySecurityError, Result};
use crate::lifecycle::LogicalTime;
use crate::memory::Provenance;
use crate::model::MemorySecurityScenario;
use crate::observation::{
    validate_events, ActionIntentObserved, DecisionContextObserved, EvidenceText,
    HarnessErrorEvent, HarnessErrorKind, InfluenceTarget, MemoryInfluenceObserved,
    MemoryInvalidationObserved, MemoryItemDigest, MemoryObservationEvent, MemoryRecallObserved,
    MemoryRecallRequested, MemorySnapshotObserved, MemoryUpdateObserved, MemoryWriteObserved,
    MemoryWriteRequested, PolicyDecisionObserved, RecalledItem,
};
use crate::source::{LifecycleState, SourceKind, TrustClass};

/// Approved execution modes. All are local and offline.
///
/// There is deliberately no `LiveStore`, `Redis`, `VectorDb` or `Remote`
/// variant: live memory access is out of scope for Cycle 016 and cannot be
/// selected, not merely discouraged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HarnessMode {
    /// Evaluate a sanitized local trace. Contacts no store.
    Replay,
    /// Deterministic scenario-derived observations.
    Simulated,
    /// The same staging, gated by the Cycle 009 controls.
    LocalSynthetic,
}

impl HarnessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Replay => "REPLAY",
            Self::Simulated => "SIMULATED",
            Self::LocalSynthetic => "LOCAL_SYNTHETIC",
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::Replay, Self::Simulated, Self::LocalSynthetic]
    }

    /// True when observations were staged rather than recorded from a real
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
                MemorySecurityError::refusal(format!(
                    "unknown or unapproved harness mode `{token}`; Cycle 016 supports only \
                     REPLAY, SIMULATED and LOCAL_SYNTHETIC"
                ))
            })
    }
}

// --- raw adapter output ------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSnapshot {
    pub store_id: String,
    pub store_digest: String,
    pub item_count: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub item_digests: Vec<MemoryItemDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawWriteRequest {
    pub request_id: String,
    pub memory_id: String,
    pub writer_principal_id: String,
    pub namespace_id: String,
    pub tenant_id: String,
    pub source_kind: SourceKind,
    pub requested_trust_class: TrustClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawWrite {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawUpdate {
    pub memory_id: String,
    pub writer_principal_id: String,
    pub before_content_digest: String,
    pub after_content_digest: String,
    pub before_version: u32,
    pub after_version: u32,
    pub authorized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawInvalidation {
    pub memory_id: String,
    pub state: LifecycleState,
    pub at: LogicalTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRecallRequest {
    pub request_id: String,
    pub requester_principal_id: String,
    pub requested_namespace_id: String,
    pub requested_tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_owner_principal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_memory_ids: Vec<String>,
}

/// A recall result as an adapter reports it.
///
/// Items are named by id; their binding facts are resolved from the store
/// during normalization, so an adapter cannot claim a recalled item belonged to
/// a tenant it does not belong to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRecallResult {
    pub request_id: String,
    pub requester_principal_id: String,
    pub memory_ids: Vec<String>,
    pub at: LogicalTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawInfluence {
    pub memory_id: String,
    pub target: InfluenceTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_value: Option<String>,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawDecisionContext {
    pub authorized_objective_id: String,
    pub observed_objective_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_tool_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_tool_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawActionIntent {
    pub action_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPolicyDecision {
    pub policy_id: String,
    pub operation: String,
    pub memory_id: String,
    pub allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawHarnessError {
    pub kind: HarnessErrorKind,
    pub detail: String,
}

/// What an adapter observed in one trial, before normalization.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTrialOutput {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub snapshots: Vec<RawSnapshot>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write_requests: Vec<RawWriteRequest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub writes: Vec<RawWrite>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub updates: Vec<RawUpdate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invalidations: Vec<RawInvalidation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recall_requests: Vec<RawRecallRequest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recall_results: Vec<RawRecallResult>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub influences: Vec<RawInfluence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decision_contexts: Vec<RawDecisionContext>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub action_intents: Vec<RawActionIntent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_decisions: Vec<RawPolicyDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_error: Option<RawHarnessError>,
}

/// One trial's inputs.
#[derive(Debug, Clone, Copy)]
pub struct TrialRequest<'a> {
    pub trial_index: u32,
    pub scenario: &'a MemorySecurityScenario,
}

/// A bounded, local source of memory observations.
pub trait HarnessAdapter {
    fn mode(&self) -> HarnessMode;

    /// Observe one trial.
    ///
    /// Implementations must not perform network I/O, spawn a process, open a
    /// database, cache or vector store, or perform any action the agent
    /// intended.
    fn observe(&self, request: &TrialRequest<'_>) -> Result<RawTrialOutput>;

    /// How many trials this adapter can supply.
    ///
    /// A recorded source is bounded by what it recorded; a staged one can
    /// produce a trial for any index. The default is the hard maximum, so an
    /// adapter that does not override this never *lowers* a plan by accident —
    /// and none of them can raise one.
    fn trial_capacity(&self) -> u32 {
        crate::limits::HARD_MAX_TRIALS
    }
}

/// Convert raw adapter output into normalized, typed observation events.
///
/// Recalled items are resolved against the store rather than taken on the
/// adapter's word. That is what stops a trace from asserting that a
/// cross-tenant item belonged to the acting tenant all along.
pub fn normalize(
    raw: &RawTrialOutput,
    scenario: &MemorySecurityScenario,
) -> Result<Vec<MemoryObservationEvent>> {
    let mut events = Vec::new();

    if let Some(error) = &raw.harness_error {
        events.push(MemoryObservationEvent::HarnessError(HarnessErrorEvent {
            kind: error.kind,
            detail: EvidenceText::from_raw(&error.detail),
        }));
        // A failed trial supports no behavioral claim whatsoever.
        return Ok(events);
    }

    for snapshot in &raw.snapshots {
        events.push(MemoryObservationEvent::MemorySnapshot(
            MemorySnapshotObserved {
                store_id: snapshot.store_id.clone(),
                store_digest: snapshot.store_digest.clone(),
                item_count: snapshot.item_count,
                item_digests: snapshot.item_digests.clone(),
            },
        ));
    }

    for request in &raw.write_requests {
        events.push(MemoryObservationEvent::MemoryWriteRequest(
            MemoryWriteRequested {
                request_id: request.request_id.clone(),
                memory_id: request.memory_id.clone(),
                writer_principal_id: request.writer_principal_id.clone(),
                namespace_id: request.namespace_id.clone(),
                tenant_id: request.tenant_id.clone(),
                source_kind: request.source_kind,
                requested_trust_class: request.requested_trust_class,
            },
        ));
    }

    for write in &raw.writes {
        events.push(MemoryObservationEvent::MemoryWriteObserved(
            MemoryWriteObserved {
                memory_id: write.memory_id.clone(),
                writer_principal_id: write.writer_principal_id.clone(),
                namespace_id: write.namespace_id.clone(),
                tenant_id: write.tenant_id.clone(),
                provenance: write.provenance.clone(),
                stored_trust_class: write.stored_trust_class,
                content_digest: write.content_digest.clone(),
                version: write.version,
            },
        ));
    }

    for update in &raw.updates {
        events.push(MemoryObservationEvent::MemoryUpdateObserved(
            MemoryUpdateObserved {
                memory_id: update.memory_id.clone(),
                writer_principal_id: update.writer_principal_id.clone(),
                before_content_digest: update.before_content_digest.clone(),
                after_content_digest: update.after_content_digest.clone(),
                before_version: update.before_version,
                after_version: update.after_version,
                authorized: update.authorized,
            },
        ));
    }

    for invalidation in &raw.invalidations {
        events.push(MemoryObservationEvent::MemoryInvalidationObserved(
            MemoryInvalidationObserved {
                memory_id: invalidation.memory_id.clone(),
                state: invalidation.state,
                at: invalidation.at,
            },
        ));
    }

    for request in &raw.recall_requests {
        events.push(MemoryObservationEvent::MemoryRecallRequest(
            MemoryRecallRequested {
                request_id: request.request_id.clone(),
                requester_principal_id: request.requester_principal_id.clone(),
                requested_namespace_id: request.requested_namespace_id.clone(),
                requested_tenant_id: request.requested_tenant_id.clone(),
                requested_owner_principal_id: request.requested_owner_principal_id.clone(),
                requested_memory_ids: request.requested_memory_ids.clone(),
            },
        ));
    }

    for result in &raw.recall_results {
        // Resolve each recalled item against the store. An id the store does
        // not declare is refused rather than dropped: silently omitting it
        // would shorten the evidence the coverage contract then judges.
        let mut items = Vec::with_capacity(result.memory_ids.len());
        for memory_id in &result.memory_ids {
            let item = scenario.store.require(memory_id, "a recall result")?;
            items.push(RecalledItem::from_item(item, result.at));
        }
        events.push(MemoryObservationEvent::MemoryRecallObserved(
            MemoryRecallObserved {
                request_id: result.request_id.clone(),
                requester_principal_id: result.requester_principal_id.clone(),
                items,
                at: result.at,
            },
        ));
    }

    for influence in &raw.influences {
        // An influence must name memory the store declares, so a fixture cannot
        // attribute a decision change to something nobody can inspect.
        scenario
            .store
            .require(&influence.memory_id, "an influence observation")?;
        events.push(MemoryObservationEvent::MemoryInfluenceObserved(
            MemoryInfluenceObserved {
                memory_id: influence.memory_id.clone(),
                target: influence.target,
                field: influence.field.clone(),
                baseline_value: influence.baseline_value.clone(),
                observed_value: influence.observed_value.clone(),
                changed: influence.changed,
            },
        ));
    }

    for context in &raw.decision_contexts {
        events.push(MemoryObservationEvent::DecisionContextObserved(
            DecisionContextObserved {
                authorized_objective_id: context.authorized_objective_id.clone(),
                observed_objective_id: context.observed_objective_id.clone(),
                baseline_tool_id: context.baseline_tool_id.clone(),
                observed_tool_id: context.observed_tool_id.clone(),
            },
        ));
    }

    for intent in &raw.action_intents {
        events.push(MemoryObservationEvent::ActionIntentObserved(
            ActionIntentObserved {
                action_id: intent.action_id.clone(),
                tool_id: intent.tool_id.clone(),
                // Structurally false: Cycle 016 observes intents and performs
                // none, so no adapter can claim otherwise.
                performed: false,
            },
        ));
    }

    for decision in &raw.policy_decisions {
        events.push(MemoryObservationEvent::PolicyDecision(
            PolicyDecisionObserved {
                policy_id: decision.policy_id.clone(),
                operation: decision.operation.clone(),
                memory_id: decision.memory_id.clone(),
                allowed: decision.allowed,
            },
        ));
    }

    Ok(events)
}

/// Normalize and reject any event that is structurally unsafe.
pub fn normalize_checked(
    raw: &RawTrialOutput,
    scenario: &MemorySecurityScenario,
) -> Result<Vec<MemoryObservationEvent>> {
    let events = normalize(raw, scenario)?;
    validate_events(&events)?;
    Ok(events)
}

/// Total retained bytes for a normalized trial.
pub fn retained_bytes(events: &[MemoryObservationEvent]) -> usize {
    events
        .iter()
        .map(MemoryObservationEvent::retained_bytes)
        .sum()
}

/// How many normalized events a trial produced.
pub fn observed_event_count(events: &[MemoryObservationEvent]) -> u32 {
    events.len() as u32
}

/// How many items were recalled across a trial.
pub fn observed_recall_items(events: &[MemoryObservationEvent]) -> u32 {
    events
        .iter()
        .map(|event| match event {
            MemoryObservationEvent::MemoryRecallObserved(recall) => recall.items.len() as u32,
            _ => 0,
        })
        .sum()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::observation::CoverageChannel;
    use crate::schema::validate_scenario_document;

    pub(crate) fn scenario() -> MemorySecurityScenario {
        let raw = include_str!("../tests/fixtures/scenario.json");
        let value: serde_json::Value = serde_json::from_str(raw).expect("fixture parses");
        validate_scenario_document(&value).expect("fixture validates");
        let scenario: MemorySecurityScenario =
            serde_json::from_value(value).expect("fixture decodes");
        scenario.validate().expect("fixture is structurally valid");
        scenario
    }

    #[test]
    fn only_three_offline_modes_exist() {
        assert_eq!(HarnessMode::all().len(), 3);
        assert_eq!(
            HarnessMode::all().map(HarnessMode::as_str),
            ["REPLAY", "SIMULATED", "LOCAL_SYNTHETIC"]
        );
        assert!(!HarnessMode::Replay.is_synthetic());
        assert!(HarnessMode::Simulated.is_synthetic());
        assert!(HarnessMode::LocalSynthetic.is_synthetic());
    }

    #[test]
    fn no_live_store_mode_can_be_selected() {
        for token in [
            "REDIS",
            "POSTGRES",
            "VECTOR_DB",
            "PINECONE",
            "QDRANT",
            "LIVE",
            "REMOTE",
            "PRODUCTION",
            "replay",
            "",
        ] {
            let err = HarnessMode::parse(token).expect_err("must be refused");
            assert!(err.is_refusal(), "{token}");
        }
        for mode in HarnessMode::all() {
            assert_eq!(HarnessMode::parse(mode.as_str()).expect("known"), mode);
        }
    }

    #[test]
    fn an_observed_action_intent_is_never_performed() {
        let scenario = scenario();
        let raw = RawTrialOutput {
            action_intents: vec![RawActionIntent {
                action_id: "act-1".to_owned(),
                tool_id: Some("tool-send".to_owned()),
            }],
            ..RawTrialOutput::default()
        };
        let events = normalize_checked(&raw, &scenario).expect("normalizes");
        let MemoryObservationEvent::ActionIntentObserved(intent) = &events[0] else {
            panic!("expected an action intent");
        };
        assert!(!intent.performed);
    }

    #[test]
    fn a_harness_error_suppresses_every_behavioral_claim() {
        let scenario = scenario();
        let raw = RawTrialOutput {
            harness_error: Some(RawHarnessError {
                kind: HarnessErrorKind::AdapterFailure,
                detail: "adapter stopped".to_owned(),
            }),
            snapshots: vec![RawSnapshot {
                store_id: "store-support".to_owned(),
                store_digest: format!("sha256:{}", "a".repeat(64)),
                item_count: 5,
                item_digests: Vec::new(),
            }],
            ..RawTrialOutput::default()
        };
        let events = normalize(&raw, &scenario).expect("normalizes");
        assert_eq!(events.len(), 1);
        assert!(events[0].is_harness_error());
    }

    #[test]
    fn a_missing_channel_is_never_invented() {
        // Absence of evidence must stay absent; the coverage contract, not the
        // normalizer, decides what a missing channel means.
        let scenario = scenario();
        assert!(normalize(&RawTrialOutput::default(), &scenario)
            .expect("normalizes")
            .is_empty());

        let raw = RawTrialOutput {
            snapshots: vec![RawSnapshot {
                store_id: "store-support".to_owned(),
                store_digest: format!("sha256:{}", "a".repeat(64)),
                item_count: 5,
                item_digests: Vec::new(),
            }],
            ..RawTrialOutput::default()
        };
        let events = normalize(&raw, &scenario).expect("normalizes");
        let channels: Vec<CoverageChannel> = events
            .iter()
            .filter_map(MemoryObservationEvent::coverage_channel)
            .collect();
        assert_eq!(channels, vec![CoverageChannel::MemorySnapshot]);
        assert!(!channels.contains(&CoverageChannel::MemoryRecallObserved));
    }

    #[test]
    fn recalled_items_are_resolved_from_the_store_not_taken_on_the_adapters_word() {
        // This is what stops a trace asserting that a cross-tenant item
        // belonged to the acting tenant all along.
        let scenario = scenario();
        let raw = RawTrialOutput {
            recall_results: vec![RawRecallResult {
                request_id: "recall-1".to_owned(),
                requester_principal_id: "user-7".to_owned(),
                memory_ids: vec!["mem-other-tenant".to_owned()],
                at: 150,
            }],
            ..RawTrialOutput::default()
        };
        let events = normalize_checked(&raw, &scenario).expect("normalizes");
        let MemoryObservationEvent::MemoryRecallObserved(recall) = &events[0] else {
            panic!("expected a recall");
        };
        // The store says tenant-b, so the observation says tenant-b.
        assert_eq!(recall.items[0].tenant_id, "tenant-b");
        assert_eq!(recall.items[0].owner_principal_id, "user-9");
        assert_eq!(recall.items[0].namespace_id, "ns-billing");
    }

    #[test]
    fn lifecycle_state_is_computed_at_the_recall_instant() {
        let scenario = scenario();
        let recall_at = |at: LogicalTime| {
            let raw = RawTrialOutput {
                recall_results: vec![RawRecallResult {
                    request_id: "recall-1".to_owned(),
                    requester_principal_id: "user-7".to_owned(),
                    memory_ids: vec!["mem-stale-note".to_owned()],
                    at,
                }],
                ..RawTrialOutput::default()
            };
            let events = normalize_checked(&raw, &scenario).expect("normalizes");
            let MemoryObservationEvent::MemoryRecallObserved(recall) = &events[0] else {
                panic!("expected a recall");
            };
            recall.items[0].lifecycle_state
        };

        // The stale note is valid before 120 and expired from 120 onward.
        assert_eq!(recall_at(100), LifecycleState::Valid);
        assert_eq!(recall_at(119), LifecycleState::Valid);
        assert_eq!(recall_at(120), LifecycleState::Expired);
        assert_eq!(recall_at(150), LifecycleState::Expired);
    }

    #[test]
    fn a_recall_naming_memory_the_store_never_declared_is_refused() {
        let scenario = scenario();
        let raw = RawTrialOutput {
            recall_results: vec![RawRecallResult {
                request_id: "recall-1".to_owned(),
                requester_principal_id: "user-7".to_owned(),
                memory_ids: vec!["mem-nowhere".to_owned()],
                at: 150,
            }],
            ..RawTrialOutput::default()
        };
        let err = normalize(&raw, &scenario).expect_err("must be refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("mem-nowhere"));
    }

    #[test]
    fn an_influence_naming_unknown_memory_is_refused() {
        // A decision change attributed to something nobody can inspect is not
        // evidence.
        let scenario = scenario();
        let raw = RawTrialOutput {
            influences: vec![RawInfluence {
                memory_id: "mem-invented".to_owned(),
                target: InfluenceTarget::Objective,
                field: None,
                baseline_value: None,
                observed_value: None,
                changed: true,
            }],
            ..RawTrialOutput::default()
        };
        let err = normalize(&raw, &scenario).expect_err("must be refused");
        assert!(err.is_refusal());
    }

    #[test]
    fn normalization_is_deterministic_and_order_preserving() {
        let scenario = scenario();
        let raw = RawTrialOutput {
            snapshots: vec![RawSnapshot {
                store_id: "store-support".to_owned(),
                store_digest: format!("sha256:{}", "a".repeat(64)),
                item_count: 5,
                item_digests: Vec::new(),
            }],
            recall_requests: vec![RawRecallRequest {
                request_id: "recall-1".to_owned(),
                requester_principal_id: "user-7".to_owned(),
                requested_namespace_id: "ns-support".to_owned(),
                requested_tenant_id: "tenant-a".to_owned(),
                requested_owner_principal_id: Some("user-7".to_owned()),
                requested_memory_ids: vec!["mem-preference".to_owned()],
            }],
            recall_results: vec![RawRecallResult {
                request_id: "recall-1".to_owned(),
                requester_principal_id: "user-7".to_owned(),
                memory_ids: vec!["mem-preference".to_owned()],
                at: 150,
            }],
            ..RawTrialOutput::default()
        };
        let first = normalize_checked(&raw, &scenario).expect("normalizes");
        let second = normalize_checked(&raw, &scenario).expect("normalizes");
        assert_eq!(first, second);
        assert_eq!(
            first
                .iter()
                .map(MemoryObservationEvent::kind)
                .collect::<Vec<_>>(),
            [
                "MEMORY_SNAPSHOT",
                "MEMORY_RECALL_REQUEST",
                "MEMORY_RECALL_OBSERVED"
            ]
        );
        assert_eq!(observed_event_count(&first), 3);
        assert_eq!(observed_recall_items(&first), 1);
        assert!(retained_bytes(&first) > 0);
    }

    #[test]
    fn raw_transport_types_reject_unknown_and_store_fields() {
        assert!(serde_json::from_value::<RawSnapshot>(serde_json::json!({
            "store_id": "s", "store_digest": "sha256:aa", "item_count": 0,
            "connection_string": "redis://localhost:6379"
        }))
        .is_err());

        assert!(serde_json::from_value::<RawTrialOutput>(serde_json::json!({
            "redis": "localhost"
        }))
        .is_err());
    }
}
