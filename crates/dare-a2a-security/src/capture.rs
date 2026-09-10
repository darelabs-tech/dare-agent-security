//! The replay adapter: a previously captured exchange, re-evaluated locally.
//!
//! **`REPLAY` means re-evaluating a capture. It does not mean re-sending it**,
//! and nothing in this crate could: no HTTP client, no transport, no socket.
//!
//! # The thing a recording must not bring with it
//!
//! A capture records what an exchange *contained*. It must not also record what
//! was *approved* — the Cycle 017 lesson in this cycle's vocabulary.
//!
//! A captured bundle can carry a policy. If replay accepted it, whoever
//! produced the capture would be supplying both the evidence and the policy it
//! is judged against, and a recording could approve its own peers, skills,
//! tenants and callback destinations. Every invariant that compares observation
//! against approval would then be comparing a capture with itself.
//!
//! [`ReplayAdapter`] therefore **discards** the recorded policy and applies a
//! local one supplied beside it.

use serde::{Deserialize, Serialize};

use crate::budget::AdmissionLedger;
use crate::error::{A2aSecurityError, Result};
use crate::harness::A2aAdapter;
use crate::model::A2aScenario;
use crate::normalize::{A2aEvidence, EvidenceBuilder};
use crate::policy::A2aPolicy;
use crate::source::A2aMode;

/// A captured A2A exchange bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aCapture {
    pub schema_version: String,
    pub capture_id: String,
    /// The scenario the capture was taken under. Identity, never authority.
    pub scenario_id: String,
    /// Always `REPLAY`. A recording cannot ask to be run any other way.
    pub mode: A2aMode,
    /// Always `true`. A capture cannot claim to be production evidence.
    pub synthetic: bool,
    pub evidence: A2aEvidence,
}

impl A2aCapture {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != "1" {
            return Err(A2aSecurityError::schema(format!(
                "capture schema version `{}` is not supported",
                self.schema_version
            )));
        }
        if self.mode != A2aMode::Replay {
            return Err(A2aSecurityError::refusal(
                "a capture declared a mode other than REPLAY; a recording cannot ask to be run \
                 as something else"
                    .to_owned(),
            ));
        }
        if !self.synthetic {
            return Err(A2aSecurityError::refusal(
                "a capture declared itself non-synthetic; a recording is a recording, and a \
                 report must not present one as production evidence"
                    .to_owned(),
            ));
        }
        self.evidence.validate()
    }
}

/// Re-evaluate a captured bundle under a local policy.
pub struct ReplayAdapter {
    capture: A2aCapture,
    local_policy: A2aPolicy,
}

impl ReplayAdapter {
    /// The policy is a separate argument on purpose: it is the one input the
    /// capture may not supply.
    pub fn new(capture: A2aCapture, local_policy: A2aPolicy) -> Self {
        Self {
            capture,
            local_policy,
        }
    }
}

impl A2aAdapter for ReplayAdapter {
    fn mode(&self) -> A2aMode {
        A2aMode::Replay
    }

    fn collect(&self, scenario: &A2aScenario, ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
        scenario.validate()?;
        self.capture.validate()?;
        self.local_policy.validate()?;

        if self.capture.scenario_id != scenario.scenario_id {
            return Err(A2aSecurityError::BindingMismatch(format!(
                "the capture was taken under scenario `{}` and is being replayed under `{}`",
                self.capture.scenario_id, scenario.scenario_id
            )));
        }

        let recorded = &self.capture.evidence;

        // Semantic binding: the capture must describe peers the local policy is
        // about. A capture of a different deployment replayed under these
        // approvals would report on peers nobody here talks to.
        if !self.local_policy.approved_peers.is_empty() {
            let recorded_peers: std::collections::BTreeSet<&str> = recorded
                .peers
                .peers
                .iter()
                .map(|peer| peer.peer_id.as_str())
                .collect();
            let overlap = self
                .local_policy
                .approved_peers
                .iter()
                .any(|approved| recorded_peers.contains(approved.peer_id.as_str()));
            if !overlap && !recorded_peers.is_empty() {
                return Err(A2aSecurityError::BindingMismatch(
                    "the capture describes none of the peers the local policy approves, so it is \
                     a recording of a different system"
                        .to_owned(),
                ));
            }
        }

        // Re-admitted rather than trusted. A capture is a file like any other
        // and can have grown past a bound since it was taken.
        for _ in &recorded.peers.peers {
            ledger.admit_peer()?;
        }
        for _ in &recorded.exchanges.exchanges {
            ledger.admit_exchange()?;
        }

        let mut builder = EvidenceBuilder::new();
        for document in &recorded.documents {
            builder = builder.with_recorded_document(document.clone());
        }
        for card in &recorded.cards {
            builder = builder.with_card(card.clone());
        }
        for peer in &recorded.peers.peers {
            builder = builder.with_peer(peer.clone());
        }
        for exchange in &recorded.exchanges.exchanges {
            builder = builder.with_exchange(exchange.clone());
        }
        for record in &recorded.peer_authentication {
            builder = builder.with_peer_authentication(record.clone());
        }
        for record in &recorded.message_authentication {
            builder = builder.with_message_authentication(record.clone());
        }
        for chain in &recorded.delegation_chains {
            builder = builder.with_delegation_chain(chain.clone());
        }
        for config in &recorded.push_configs {
            builder = builder.with_push_config(config.clone());
        }

        // The recorded policy is discarded rather than merged. Merging would
        // let the capture add approvals the local policy never granted, which
        // is the same thing as the capture approving itself.
        builder
            .with_policy(self.local_policy.clone())
            .build(&mut AdmissionLedger::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invariant::evaluate;
    use crate::model::tests::scenario;
    use crate::model::A2aInvariant;
    use crate::normalize::tests::evidence;
    use crate::observation::project;
    use crate::policy::tests::policy;
    use dare_security_evidence::Verdict;

    fn capture_with(policy: A2aPolicy) -> A2aCapture {
        let mut recorded = evidence();
        recorded.policy = policy;
        A2aCapture {
            schema_version: "1".to_owned(),
            capture_id: "capture-1".to_owned(),
            scenario_id: "a2a-lab-replay".to_owned(),
            mode: A2aMode::Replay,
            synthetic: true,
            evidence: recorded,
        }
    }

    fn replay_scenario() -> A2aScenario {
        let mut scenario = scenario("a2a-lab-replay", A2aInvariant::TenantBoundaryPreserved);
        scenario.mode = A2aMode::Replay;
        scenario
    }

    #[test]
    fn a_capture_replays_under_the_local_policy() {
        let mut ledger = AdmissionLedger::new();
        let replayed = ReplayAdapter::new(capture_with(A2aPolicy::default()), policy())
            .collect(&replay_scenario(), &mut ledger)
            .expect("replays");
        assert_eq!(replayed.policy, policy());
    }

    #[test]
    fn a_recorded_policy_cannot_approve_its_own_exchange() {
        // The capture places `user-mallory` in the tenant it claimed; the local
        // policy does not. If the recorded policy survived, the crossing would
        // pass.
        let mut permissive = policy();
        permissive
            .tenant_policy
            .subject_tenants
            .insert("user-mallory".to_owned(), "tenant-b".to_owned());

        let mut capture = capture_with(permissive);
        capture.evidence.peers.peers[0].delegated_subject = Some("user-mallory".to_owned());
        capture.evidence.exchanges.exchanges[0].tenant_claim = Some("tenant-b".to_owned());

        let mut ledger = AdmissionLedger::new();
        let replayed = ReplayAdapter::new(capture, policy())
            .collect(&replay_scenario(), &mut ledger)
            .expect("replays");

        // The local policy knows nothing about `user-mallory`, so the tenant
        // question is undecidable rather than approved — which is the honest
        // answer, and the opposite of what the recorded policy would have said.
        let outcome = evaluate(A2aInvariant::TenantBoundaryPreserved, &project(&replayed));
        assert_ne!(outcome.verdict, Verdict::Pass, "a capture approved itself");
    }

    #[test]
    fn a_capture_of_another_scenario_is_refused() {
        let mut capture = capture_with(A2aPolicy::default());
        capture.scenario_id = "a2a-lab-elsewhere".to_owned();
        let mut ledger = AdmissionLedger::new();
        assert!(ReplayAdapter::new(capture, policy())
            .collect(&replay_scenario(), &mut ledger)
            .is_err());
    }

    #[test]
    fn a_capture_describing_a_different_system_is_refused() {
        // Semantic binding. The scenario id can match while the recording is of
        // something else entirely.
        let mut elsewhere = policy();
        elsewhere.approved_peers =
            std::collections::BTreeSet::from([crate::policy::ApprovedPeer {
                peer_id: "some-other-agent".to_owned(),
                expected_logical_agent: None,
                expected_provider: None,
                expected_card_digest: None,
                expected_audience: None,
                approved_interfaces: Default::default(),
                approved_scheme_kinds: Default::default(),
                approved_signers: Default::default(),
                requires_delegated_identity: false,
            }]);

        let mut ledger = AdmissionLedger::new();
        let error = ReplayAdapter::new(capture_with(A2aPolicy::default()), elsewhere)
            .collect(&replay_scenario(), &mut ledger)
            .expect_err("must be refused");
        assert!(error.to_string().contains("different system"));
    }

    #[test]
    fn a_capture_cannot_declare_itself_production_evidence() {
        let mut capture = capture_with(A2aPolicy::default());
        capture.synthetic = false;
        let mut ledger = AdmissionLedger::new();
        assert!(ReplayAdapter::new(capture, policy())
            .collect(&replay_scenario(), &mut ledger)
            .is_err());
    }

    #[test]
    fn a_capture_cannot_ask_to_be_run_in_another_mode() {
        let mut capture = capture_with(A2aPolicy::default());
        capture.mode = A2aMode::Static;
        let mut ledger = AdmissionLedger::new();
        assert!(ReplayAdapter::new(capture, policy())
            .collect(&replay_scenario(), &mut ledger)
            .is_err());
    }

    #[test]
    fn a_capture_cannot_carry_a_verdict() {
        let mut value =
            serde_json::to_value(capture_with(A2aPolicy::default())).expect("serializes");
        value
            .as_object_mut()
            .expect("an object")
            .insert("expected_verdict".to_owned(), serde_json::json!("PASS"));
        assert!(serde_json::from_value::<A2aCapture>(value).is_err());
    }

    #[test]
    fn replayed_evidence_is_still_synthetic() {
        // A replayed observation is a recording. A report must not present it
        // as something observed in production now.
        assert!(
            ReplayAdapter::new(capture_with(A2aPolicy::default()), policy())
                .evidence_is_synthetic()
        );
    }
}
