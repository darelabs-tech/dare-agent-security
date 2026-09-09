//! Local-synthetic collection, gated through the Cycle 009 controls.
//!
//! This adapter generates an Agent Card document locally and reads it back
//! through the **real importer path**, so the parsing a hostile card would
//! receive is the parsing a synthetic one receives. A simulated bundle
//! assembled directly in memory proves the evaluators work; only this proves
//! the document gate does.
//!
//! Nothing here reaches anything. What it "generates" is bytes in a `Vec<u8>`
//! that never leave the process: no file is written, no socket is opened, no
//! endpoint inside the generated card is resolved. The Cycle 009 budget pins
//! state changes, egress and bytes written to zero, and the snapshot records
//! that it did.
//!
//! # The kill switch
//!
//! A run approved for one scenario that is pointed at another stops rather than
//! collecting. Without it, an approved allocation could be redirected at
//! something nobody approved — and the allocation would still look correct in
//! every record, because the record names the scenario the run was *approved*
//! for.

use std::cell::Cell;

use dare_adversarial::model::ExecutionBudget;
use serde::{Deserialize, Serialize};

use crate::budget::AdmissionLedger;
use crate::error::{A2aSecurityError, Result};
use crate::harness::A2aAdapter;
use crate::limits;
use crate::model::A2aScenario;
use crate::normalize::{A2aEvidence, EvidenceBuilder};
use crate::source::{A2aMode, ReferenceBehavior};

/// The Cycle 009 budget a Cycle 020 synthetic run executes under.
pub fn synthetic_budget(documents: u32) -> ExecutionBudget {
    ExecutionBudget {
        schema_version: "1".to_owned(),
        id: "a2a-security-synthetic".to_owned(),
        max_operations: documents.max(1),
        max_duration_seconds: 30,
        max_state_changes: limits::MAX_STATE_CHANGES,
        max_bytes_read: limits::HARD_MAX_DOCUMENT_BYTES as u64,
        max_bytes_written: 0,
        max_external_egress_bytes: limits::EXTERNAL_EGRESS_BYTES,
        max_retries: 0,
        max_chain_depth: 1,
    }
}

/// What the controls allowed, recorded so a report can show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aControlSnapshot {
    pub target_scenario_id: String,
    pub max_documents: u32,
    pub state_changes: u32,
    pub external_egress_bytes: u64,
    pub bytes_written: u64,
    pub kill_switch_triggered: bool,
}

/// Generate a local Agent Card and read it back through the document gate.
#[derive(Debug)]
pub struct LocalSyntheticAdapter {
    target_scenario_id: String,
    kill_switch_triggered: Cell<bool>,
}

impl LocalSyntheticAdapter {
    pub fn new(target_scenario_id: impl Into<String>) -> Self {
        Self {
            target_scenario_id: target_scenario_id.into(),
            kill_switch_triggered: Cell::new(false),
        }
    }

    pub fn for_scenario(scenario: &A2aScenario) -> Self {
        Self::new(scenario.scenario_id.clone())
    }

    pub fn snapshot(&self) -> A2aControlSnapshot {
        let budget = synthetic_budget(1);
        A2aControlSnapshot {
            target_scenario_id: self.target_scenario_id.clone(),
            max_documents: budget.max_operations,
            state_changes: budget.max_state_changes,
            external_egress_bytes: budget.max_external_egress_bytes,
            bytes_written: budget.max_bytes_written,
            kill_switch_triggered: self.kill_switch_triggered.get(),
        }
    }
}

impl A2aAdapter for LocalSyntheticAdapter {
    fn mode(&self) -> A2aMode {
        A2aMode::LocalSynthetic
    }

    fn control_snapshot(&self) -> Option<A2aControlSnapshot> {
        Some(self.snapshot())
    }

    fn collect(&self, scenario: &A2aScenario, ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
        scenario.validate()?;
        if scenario.scenario_id != self.target_scenario_id {
            self.kill_switch_triggered.set(true);
            return Err(A2aSecurityError::refusal(format!(
                "the local-synthetic run was approved for `{}` and was pointed at another \
                 scenario",
                self.target_scenario_id
            )));
        }
        let behavior = scenario.reference_behavior.ok_or_else(|| {
            A2aSecurityError::invalid(format!(
                "scenario `{}` runs in LOCAL_SYNTHETIC mode without naming a reference \
                 behaviour, so there is no document to generate",
                scenario.scenario_id
            ))
        })?;

        // Generate, then read back through the same gate an imported document
        // passes: size, hostile sweep, typed decode, model validation.
        let document = generate_agent_card(behavior);
        ledger.admit_bytes(document.len(), "a generated Agent Card")?;
        crate::schema::enforce_document_size(&document, "a generated Agent Card")?;
        let value: serde_json::Value = serde_json::from_slice(&document)?;
        crate::schema::assert_no_hostile_fields(&value, "a generated Agent Card")?;
        let card: crate::agent_card::AgentCard = serde_json::from_value(value)?;
        card.validate()?;

        EvidenceBuilder::new()
            .with_document(&scenario.scenario_id, "AGENT_CARD", &document)
            .with_card(card)
            .build(ledger)
    }
}

/// Generate an Agent Card document for one behaviour.
///
/// Deterministic: the same behaviour always produces byte-identical output, so
/// a report's document digest is reproducible and a changed digest means a
/// changed generator rather than a changed run.
pub fn generate_agent_card(behavior: ReferenceBehavior) -> Vec<u8> {
    let mut card = serde_json::json!({
        "card_id": "planner",
        "name": "planner-agent",
        "provider": "acme",
        "interfaces": [{
            // A coordinate, and nothing more. Nothing in this crate resolves it.
            "url": "https://peer.example/a2a",
            "transport": "JSONRPC",
            "protocol_version": "1.0.0"
        }],
        "security_schemes": [{
            "scheme_id": "oauth-main",
            "kind": "OAUTH2_AUTHORIZATION_CODE",
            "issuer": "https://issuer.example",
            "token_endpoint": "https://issuer.example/token"
        }],
        "skills": [{
            "skill_id": "summarize",
            "security_requirements": ["oauth-main"]
        }],
        "signature": {
            "status": "VALID",
            "signer_key_id": "key-1",
            // A `jku`-shaped location, retained inert precisely so a test can
            // prove nothing follows it.
            "key_location": "https://peer.example/jwks",
            "recorded_by": "RECORDED_VERIFICATION"
        },
        "evidence_source": "AGENT_CARD"
    });

    match behavior {
        ReferenceBehavior::ProviderMismatch => {
            card["provider"] = serde_json::json!("attacker-corp");
        }
        ReferenceBehavior::CardSignatureInvalid => {
            card["signature"]["status"] = serde_json::json!("INVALID");
        }
        ReferenceBehavior::CardSignatureUnrecorded => {
            card.as_object_mut().expect("an object").remove("signature");
        }
        ReferenceBehavior::RequiredExtensionUnknown => {
            card["extensions"] = serde_json::json!([{
                "extension_id": "ext-mandatory-unknown",
                "required": true,
                "claims_authority": true
            }]);
        }
        _ => {}
    }

    serde_json::to_vec(&card).expect("a generated document serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::tests::scenario;
    use crate::model::A2aInvariant;

    fn synthetic_scenario(behavior: ReferenceBehavior) -> A2aScenario {
        let mut scenario = scenario("a2a-lab-synthetic", A2aInvariant::DiscoveryBindingPreserved);
        scenario.mode = A2aMode::LocalSynthetic;
        scenario.reference_behavior = Some(behavior);
        scenario
    }

    #[test]
    fn the_budget_pins_state_changes_egress_and_writes_to_zero() {
        let budget = synthetic_budget(3);
        assert_eq!(budget.max_state_changes, 0);
        assert_eq!(budget.max_external_egress_bytes, 0);
        assert_eq!(budget.max_bytes_written, 0);
    }

    #[test]
    fn a_generated_card_goes_through_the_real_document_gate() {
        // The point of this adapter. A bundle assembled in memory proves the
        // evaluators work; only a generated document proves the gate does.
        let scenario = synthetic_scenario(ReferenceBehavior::Compliant);
        let mut ledger = AdmissionLedger::new();
        let evidence = LocalSyntheticAdapter::for_scenario(&scenario)
            .collect(&scenario, &mut ledger)
            .expect("collects");

        assert_eq!(evidence.cards.len(), 1);
        assert_eq!(evidence.cards[0].card_id, "planner");
        assert_eq!(evidence.documents.len(), 1);
    }

    #[test]
    fn a_generated_substitution_is_seen_through_the_gate() {
        let scenario = synthetic_scenario(ReferenceBehavior::CardSignatureInvalid);
        let mut ledger = AdmissionLedger::new();
        let evidence = LocalSyntheticAdapter::for_scenario(&scenario)
            .collect(&scenario, &mut ledger)
            .expect("collects");
        assert_eq!(
            evidence.cards[0].signature.as_ref().unwrap().status,
            crate::source::VerificationStatus::Invalid
        );
    }

    #[test]
    fn pointing_an_approved_run_at_another_scenario_trips_the_kill_switch() {
        // The allocation would still look correct in every record, because the
        // record names the scenario the run was approved for.
        let adapter = LocalSyntheticAdapter::new("a2a-lab-elsewhere");
        let mut ledger = AdmissionLedger::new();
        let error = adapter
            .collect(
                &synthetic_scenario(ReferenceBehavior::Compliant),
                &mut ledger,
            )
            .expect_err("must refuse");
        assert!(error.is_refusal());
        assert!(adapter.snapshot().kill_switch_triggered);
    }

    #[test]
    fn generation_is_deterministic() {
        // A report's document digest is reproducible, so a changed digest means
        // a changed generator rather than a changed run.
        for behavior in ReferenceBehavior::all() {
            assert_eq!(
                generate_agent_card(behavior),
                generate_agent_card(behavior),
                "{behavior:?} generated two different documents"
            );
        }
    }

    #[test]
    fn no_generated_document_carries_a_hostile_field() {
        // The generator is inside the trust boundary, and one that emitted a
        // credential-shaped or fetch-shaped field would be teaching the corpus
        // that such fields are normal.
        for behavior in ReferenceBehavior::all() {
            let raw = generate_agent_card(behavior);
            let value: serde_json::Value = serde_json::from_slice(&raw).expect("parses");
            crate::schema::assert_no_hostile_fields(&value, "a generated card")
                .unwrap_or_else(|error| panic!("{behavior:?} generated {error}"));
        }
    }

    #[test]
    fn a_generated_card_carries_locations_and_nothing_resolves_them() {
        // Real cards carry interface URLs, a token endpoint and a `jku`.
        // Refusing them would refuse every real card; the boundary is that
        // nothing goes there.
        let raw = generate_agent_card(ReferenceBehavior::Compliant);
        let text = String::from_utf8(raw).expect("utf-8");
        assert!(text.contains("https://peer.example/a2a"));
        assert!(text.contains("https://issuer.example/token"));
        assert!(text.contains("https://peer.example/jwks"));
    }

    #[test]
    fn a_synthetic_scenario_without_a_behaviour_is_refused() {
        let mut plain = synthetic_scenario(ReferenceBehavior::Compliant);
        plain.reference_behavior = None;
        let mut ledger = AdmissionLedger::new();
        assert!(LocalSyntheticAdapter::for_scenario(&plain)
            .collect(&plain, &mut ledger)
            .is_err());
    }

    #[test]
    fn the_snapshot_records_what_the_controls_allowed() {
        let scenario = synthetic_scenario(ReferenceBehavior::Compliant);
        let snapshot = LocalSyntheticAdapter::for_scenario(&scenario).snapshot();
        assert_eq!(snapshot.state_changes, 0);
        assert_eq!(snapshot.external_egress_bytes, 0);
        assert_eq!(snapshot.bytes_written, 0);
        assert!(!snapshot.kill_switch_triggered);
        assert_eq!(snapshot.target_scenario_id, "a2a-lab-synthetic");
    }

    #[test]
    fn synthetic_evidence_is_marked_synthetic_and_exposes_its_controls() {
        let scenario = synthetic_scenario(ReferenceBehavior::Compliant);
        let adapter = LocalSyntheticAdapter::for_scenario(&scenario);
        assert!(adapter.evidence_is_synthetic());
        assert_eq!(adapter.mode(), A2aMode::LocalSynthetic);
        assert!(adapter.control_snapshot().is_some());
    }

    #[test]
    fn a_generated_bundle_carries_no_policy_of_its_own() {
        // A generator that also produced the policy would be approving the peer
        // it invented, and every synthetic run would agree with itself.
        let scenario = synthetic_scenario(ReferenceBehavior::Compliant);
        let mut ledger = AdmissionLedger::new();
        let evidence = LocalSyntheticAdapter::for_scenario(&scenario)
            .collect(&scenario, &mut ledger)
            .expect("collects");
        assert!(evidence.policy.is_empty());
    }
}
