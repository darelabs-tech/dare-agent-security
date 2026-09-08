//! The Cycle 001 evidence bridge.
//!
//! Cycle 019 emits Cycle 001 `SecurityEvidence` records rather than a parallel
//! evidence format. Everything specific to this cycle lives inside a namespaced
//! extension, so the shared contract stays shared and a consumer that knows
//! nothing about bills of materials can still read the record.
//!
//! Every record targets the synthetic lab. A Cycle 019 result is evidence about
//! documents that were read, and filing it against a real deployment would let
//! a report present an inventory as a statement about a running system.
//!
//! The last thing this module does before returning a record is run Cycle 001's
//! own secret-safety validator over it. A record is a persistence surface, and
//! the check belongs at the boundary rather than in the caller.

use std::collections::BTreeMap;

use dare_security_evidence::{
    validate_secret_safety, Decision, EvidenceTimestamps, ExpectedOutcome, HashRef,
    ObservationSource, ObservedOutcome, Precondition, RedactionMetadata, RedactionStrategy,
    SchemaRef, SchemaVersion, SecurityEvidence, StandardMapping, TargetRef, VectorRef, Verdict,
};
use serde_json::json;
use time::OffsetDateTime;

use crate::error::{Result, SupplyChainError};
use crate::invariant::SupplyChainInvariantOutcome;
use crate::model::{SupplyChainInvariant, SupplyChainScenario};
use crate::result::SupplyChainSecurityResult;

pub const EVIDENCE_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/evidence/v1/security-evidence.schema.json";

/// Namespace for everything specific to this cycle.
pub const EXTENSION_NAMESPACE: &str = "dare.supply-chain-security.v1";

/// The only target a Cycle 019 record may name.
pub const SYNTHETIC_TARGET_ID: &str = "synthetic-agentic-supply-chain-lab";

/// The expected result every Cycle 019 vector is measured against.
const INVARIANT_HOLDS: &str = "invariant-holds";

/// A stable identifier for one invariant's evidence within a run.
pub fn evidence_id(
    scenario: &SupplyChainScenario,
    invariant: SupplyChainInvariant,
) -> Result<String> {
    let digest = crate::canonical::digest(&json!({
        "scenario": scenario.scenario_id,
        "invariant": invariant.as_str(),
    }))?;
    Ok(format!(
        "supply-chain-{}-{}",
        invariant.as_str().to_ascii_lowercase(),
        &digest[7..23]
    ))
}

/// How the observed outcome is described, without restating the verdict twice.
fn observed_description(verdict: Verdict, invariant: &str) -> String {
    match verdict {
        Verdict::Pass => format!("no violation of {invariant} was observed in this evidence"),
        Verdict::Fail => format!("a deterministic violation of {invariant} was observed"),
        Verdict::Inconclusive => {
            format!("the evidence required to decide {invariant} was not present")
        }
        Verdict::Error => format!("the harness could not evaluate {invariant}"),
    }
}

/// Build one evidence record for one invariant outcome.
pub fn build_invariant_evidence(
    scenario: &SupplyChainScenario,
    result: &SupplyChainSecurityResult,
    outcome: &SupplyChainInvariantOutcome,
    now: OffsetDateTime,
) -> Result<SecurityEvidence> {
    let invariant = outcome.invariant.as_str();

    let notes = json!({
        // The relations the whole cycle rests on, carried in every record so a
        // reader holding one artifact still knows what a verdict means.
        "inventory_rule": "inventory != trust",
        "identity_rule": "component name != component identity",
        "version_rule": "version string != immutable artifact",
        "provenance_rule": "digest presence != provenance",
        "signature_rule": "valid signature evidence != authorized signer",
        "trust_rule": "provenance presence != trusted provenance",
        "completeness_rule": "complete AI-BOM != secure supply chain",
        "dependency_rule": "declared dependency != observed dependency",
        "artifact_rule": "same name and version != same artifact",
        "coordinate_rule": "component URL != authorization to fetch",
        "a2a_rule": "external agent inventory != A2A authorization",
        "execution_note":
            "Evidence is read from local bill-of-materials, provenance and attestation \
             documents. No package registry, model hub, container registry, Git host, \
             transparency log, signing service or vulnerability database is contacted; no \
             signature is issued; no artifact, model or archive is executed or extracted; no \
             state change or external egress occurs.",
        "separation_note":
            "Cycle 012 owns the agentic risk registry and the capability-drift property; Cycle \
             014 owns tool-invocation authorization; Cycle 020 owns agent-to-agent security. \
             This record composes with them and replaces none of them.",
        "bounded_claim_note":
            "Verdicts are scoped to the invariants decided from the documents actually read, \
             and never assert that a supply chain is secure or that component substitution is \
             impossible.",
    });

    let bound = json!({
        "scenario_digest": result.scenario_digest,
        "evidence_digest": result.evidence_digest,
        "document_digests": result
            .documents
            .iter()
            .map(|document| document.content_digest.clone())
            .collect::<Vec<_>>(),
    });

    let run = json!({
        "invariant": invariant,
        "property": outcome.invariant.property_id(),
        "surface": result.class.as_str(),
        "mode": result.mode.as_str(),
        "synthetic": result.synthetic,
        "coverage_satisfied": outcome.coverage_satisfied,
        "violations": outcome.violations.len(),
        "deciding_observation_digests": outcome
            .violations
            .iter()
            .flat_map(|violation| violation.deciding_observation_digests.clone())
            .collect::<Vec<_>>(),
        "components_evaluated": result.components_evaluated,
        "relationships_evaluated": result.relationships_evaluated,
        "state_changes": result.budget.state_changes,
        "external_egress_bytes": result.budget.external_egress_bytes,
    });

    let mut payload = serde_json::Map::new();
    for group in [bound, run, notes] {
        let serde_json::Value::Object(map) = group else {
            unreachable!("each group is a JSON object literal");
        };
        payload.extend(map);
    }
    let mut extensions = BTreeMap::new();
    extensions.insert(
        EXTENSION_NAMESPACE.to_owned(),
        serde_json::Value::Object(payload),
    );

    let mut hashes = vec![
        HashRef {
            algorithm: "sha256".to_owned(),
            value: result.scenario_digest.clone(),
        },
        HashRef {
            algorithm: "sha256".to_owned(),
            value: result.evidence_digest.clone(),
        },
    ];
    hashes.extend(result.documents.iter().map(|document| HashRef {
        algorithm: "sha256".to_owned(),
        value: document.content_digest.clone(),
    }));

    // A standards attribution is a reference, not a retrieval target: this
    // cycle fetches nothing, and a URL here would be the first place somebody
    // added one.
    let standards = vec![StandardMapping {
        organization: "OWASP".to_owned(),
        standard: "Agentic Top 10 (2026) ASI04".to_owned(),
        version: Some("2026".to_owned()),
        control: "NORMATIVE".to_owned(),
        url: None,
    }];

    let preconditions = vec![Precondition {
        id: Some("local_bill_of_materials_present".to_owned()),
        description: "a local bill of materials was read for this run".to_owned(),
        satisfied: !result.documents.is_empty(),
    }];

    let evidence = SecurityEvidence {
        schema: SchemaRef {
            id: EVIDENCE_SCHEMA_ID.to_owned(),
            version: SchemaVersion::V1,
        },
        id: evidence_id(scenario, outcome.invariant)?,
        vector: VectorRef {
            id: scenario.scenario_id.clone(),
            version: "1".to_owned(),
            name: Some(scenario.description.clone()),
        },
        target: TargetRef {
            // Cycle 019 never targets a production deployment: it reads
            // documents, and a document is not a running system.
            type_: "synthetic-agent".to_owned(),
            id: SYNTHETIC_TARGET_ID.to_owned(),
            name: Some("DARE synthetic agentic supply-chain lab".to_owned()),
            software: None,
            software_version: None,
            protocol: None,
            protocol_version: None,
        },
        preconditions,
        operation: None,
        authorization_context: None,
        expected: ExpectedOutcome {
            decision: Some(Decision::Deny),
            result: Some(INVARIANT_HOLDS.to_owned()),
            description: Some(format!("security invariant {invariant} holds")),
        },
        observed: ObservedOutcome {
            decision: Some(match outcome.verdict {
                Verdict::Fail => Decision::Allow,
                Verdict::Pass => Decision::Deny,
                _ => Decision::NotApplicable,
            }),
            result: Some(match outcome.verdict {
                Verdict::Pass => INVARIANT_HOLDS.to_owned(),
                Verdict::Fail => "invariant-violated".to_owned(),
                Verdict::Inconclusive => "evidence-insufficient".to_owned(),
                Verdict::Error => "harness-error".to_owned(),
            }),
            description: Some(observed_description(outcome.verdict, invariant)),
            // Observations come from local documents, never from a registry, a
            // model hub or a running deployment.
            source: ObservationSource::Fixture,
        },
        verdict: outcome.verdict,
        // Severity is never inferred from the verdict alone: it is a judgement
        // a consumer makes, and baking one in would make this engine's opinion
        // look like a fact.
        severity: None,
        standards,
        artifacts: Vec::new(),
        hashes,
        redaction: RedactionMetadata {
            applied: true,
            strategy: RedactionStrategy::Mask,
            fields: vec!["observed.document_content".to_owned()],
        },
        timestamps: EvidenceTimestamps {
            started_at: Some(now),
            observed_at: now,
            recorded_at: now,
        },
        extensions: Some(extensions),
    };

    // Final gate: never return a record that carries a secret. The check lives
    // here rather than in the caller because a record is a persistence surface
    // and the boundary is the right place to enforce it.
    validate_secret_safety(&evidence).map_err(|error| {
        SupplyChainError::refusal(format!("evidence failed secret safety: {error}"))
    })?;

    Ok(evidence)
}

/// Build every evidence record for a run: one per invariant.
///
/// Twelve records rather than one, because an operator filtering by property
/// must see the invariant that decided their question rather than a single
/// record carrying an aggregate they would have to unpack.
pub fn build_evidence(
    scenario: &SupplyChainScenario,
    result: &SupplyChainSecurityResult,
    now: OffsetDateTime,
) -> Result<Vec<SecurityEvidence>> {
    result
        .outcomes
        .iter()
        .map(|outcome| build_invariant_evidence(scenario, result, outcome, now))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::AdmissionLedger;
    use crate::model::tests::scenario;
    use crate::result::run_scenario;
    use crate::simulated::SimulatedAdapter;
    use crate::source::{ReferenceBehavior, SupplyChainMode};
    use std::collections::BTreeSet;
    use time::macros::datetime;

    fn run(behavior: ReferenceBehavior) -> (SupplyChainScenario, SupplyChainSecurityResult) {
        let mut scenario = scenario(
            "supply-lab-bridge",
            SupplyChainInvariant::ArtifactDigestBoundToComponent,
        );
        scenario.mode = SupplyChainMode::Simulated;
        scenario.evidence_files = Vec::new();
        scenario.reference_behavior = Some(behavior);

        let mut ledger = AdmissionLedger::new();
        let result = run_scenario(&scenario, &SimulatedAdapter::new(), &mut ledger).expect("runs");
        (scenario, result)
    }

    fn records(behavior: ReferenceBehavior) -> Vec<SecurityEvidence> {
        let (scenario, result) = run(behavior);
        build_evidence(&scenario, &result, datetime!(2026-09-08 12:00 UTC)).expect("builds")
    }

    #[test]
    fn one_record_is_emitted_per_invariant() {
        // An operator filtering by property must see the invariant that decided
        // their question, not one record carrying an aggregate to unpack.
        let records = records(ReferenceBehavior::DigestSubstituted);
        assert_eq!(records.len(), 12);
        let ids: BTreeSet<&str> = records.iter().map(|record| record.id.as_str()).collect();
        assert_eq!(ids.len(), 12, "two records share an id");
    }

    #[test]
    fn every_record_targets_the_synthetic_lab() {
        // A Cycle 019 result is evidence about documents that were read. Filing
        // it against a real deployment would let a report present an inventory
        // as a statement about a running system.
        for record in records(ReferenceBehavior::Compliant) {
            assert_eq!(record.target.id, SYNTHETIC_TARGET_ID);
            assert_eq!(record.target.type_, "synthetic-agent");
            assert_eq!(record.observed.source, ObservationSource::Fixture);
        }
    }

    #[test]
    fn a_violation_record_carries_the_observation_that_decided_it() {
        let records = records(ReferenceBehavior::DigestSubstituted);
        let failing = records
            .iter()
            .find(|record| record.verdict == Verdict::Fail)
            .expect("a failing record");
        let extension =
            failing.extensions.as_ref().expect("extensions")[EXTENSION_NAMESPACE].clone();
        let deciding = extension["deciding_observation_digests"]
            .as_array()
            .expect("an array");
        assert!(
            !deciding.is_empty(),
            "a violation record cites no deciding observation"
        );
    }

    #[test]
    fn no_record_infers_a_severity_from_its_verdict() {
        // Severity is a judgement a consumer makes. Baking one in would make
        // this engine's opinion look like a fact.
        for record in records(ReferenceBehavior::DigestSubstituted) {
            assert!(record.severity.is_none());
        }
    }

    #[test]
    fn every_record_carries_the_rules_a_reader_needs_to_interpret_it() {
        // A record travels away from the run that produced it. A reader holding
        // one artifact must still know that an inventory is not trust.
        let record = &records(ReferenceBehavior::Compliant)[0];
        let extension = &record.extensions.as_ref().expect("extensions")[EXTENSION_NAMESPACE];
        for rule in [
            "inventory_rule",
            "completeness_rule",
            "coordinate_rule",
            "a2a_rule",
            "bounded_claim_note",
        ] {
            assert!(extension.get(rule).is_some(), "{rule} is missing");
        }
        assert!(extension["execution_note"]
            .as_str()
            .expect("a string")
            .contains("No package registry"));
    }

    #[test]
    fn a_standards_attribution_carries_no_url() {
        // A reference is not a retrieval target, and a URL here would be the
        // first place somebody added one.
        for record in records(ReferenceBehavior::Compliant) {
            for standard in &record.standards {
                assert!(standard.url.is_none(), "a standards mapping carries a URL");
            }
        }
    }

    #[test]
    fn every_record_passes_cycle_001_secret_safety() {
        // Asserted by construction: `build_invariant_evidence` refuses rather
        // than returning a record that fails the check. This exercises the
        // path over a bundle carrying supplier, builder and signer identities.
        for behavior in [
            ReferenceBehavior::Compliant,
            ReferenceBehavior::UnapprovedSigner,
            ReferenceBehavior::MultipleIndependentViolations,
        ] {
            let records = records(behavior);
            assert_eq!(records.len(), 12);
            for record in &records {
                validate_secret_safety(record).expect("secret safe");
            }
        }
    }

    #[test]
    fn evidence_ids_are_stable_across_runs() {
        let first = records(ReferenceBehavior::DigestSubstituted);
        let second = records(ReferenceBehavior::DigestSubstituted);
        let left: Vec<&str> = first.iter().map(|record| record.id.as_str()).collect();
        let right: Vec<&str> = second.iter().map(|record| record.id.as_str()).collect();
        assert_eq!(left, right);
    }

    #[test]
    fn an_undecidable_invariant_is_recorded_as_insufficient_evidence_not_as_a_pass() {
        let records = records(ReferenceBehavior::Compliant);
        let inconclusive = records
            .iter()
            .find(|record| record.verdict == Verdict::Inconclusive)
            .expect("an undecided invariant");
        assert_eq!(
            inconclusive.observed.result.as_deref(),
            Some("evidence-insufficient")
        );
        assert_eq!(
            inconclusive.observed.decision,
            Some(Decision::NotApplicable)
        );
    }
}
