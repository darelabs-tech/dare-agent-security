//! Cycle 001 evidence bridge.
//!
//! Cycle 013 does not define a second evidence contract or a second verdict
//! vocabulary. It emits `dare_security_evidence::SecurityEvidence` records and
//! puts prompt-injection specifics in the namespaced `extensions` container,
//! which is exactly what that container exists for.
//!
//! Records are redacted before construction: the observation layer has already
//! masked canaries and credential shapes, and a final secret-safety check runs
//! before a record is returned.

use std::collections::BTreeMap;

use dare_security_evidence::{
    validate_secret_safety, Decision, EvidenceTimestamps, ExpectedOutcome, HashRef,
    ObservationSource, ObservedOutcome, Precondition, RedactionMetadata, RedactionStrategy,
    SchemaRef, SchemaVersion, SecurityEvidence, StandardMapping, TargetRef, VectorRef, Verdict,
};
use serde_json::json;
use time::OffsetDateTime;

use crate::canonical::{digest, IdentityBinding};
use crate::error::{PromptInjectionError, Result};
use crate::harness::HarnessMode;
use crate::model::{CorpusEntry, PromptInjectionScenario};
use crate::result::{PromptInjectionResult, TrialRecord};

pub const EVIDENCE_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/evidence/v1/evidence.schema.json";

/// Namespace for Cycle 013 evidence extensions.
pub const EXTENSION_NAMESPACE: &str = "dare.prompt-injection.v1";

/// Stable evidence identifier for one trial of one bound scenario.
///
/// Derived from the identity binding and the trial index, so the same run
/// produces the same identifiers and a substituted input produces different
/// ones.
pub fn evidence_id(binding: &IdentityBinding, trial_index: u32) -> Result<String> {
    let identity = digest(&json!({
        "scenario_digest": binding.scenario_digest,
        "corpus_digest": binding.corpus_digest,
        "objective_digest": binding.objective_digest,
        "trial_index": trial_index,
    }))?;
    let hex = identity.trim_start_matches("sha256:");
    Ok(format!("urn:dare:prompt-injection:evidence:{hex}"))
}

/// Evidence identifiers for every executed trial.
pub fn evidence_ids(binding: &IdentityBinding, trials: &[TrialRecord]) -> Result<Vec<String>> {
    trials
        .iter()
        .map(|trial| evidence_id(binding, trial.index))
        .collect()
}

/// Stable result token for an invariant that held.
const INVARIANT_HOLDS: &str = "INVARIANT_HOLDS";
/// Stable result token for an invariant that was violated.
const INVARIANT_VIOLATED: &str = "INVARIANT_VIOLATED";

/// Observed outcome expressed in the Cycle 001 decision vocabulary.
///
/// The expected decision is always DENY: injected content must not be granted
/// authority over the authorized objective. A held boundary is observed as
/// DENY; a crossed one as ALLOW. Undecidable trials carry no decision at all,
/// which is what keeps INCONCLUSIVE and ERROR from masquerading as either.
fn observed_decision(verdict: Verdict) -> (Option<Decision>, Option<String>) {
    match verdict {
        Verdict::Pass => (Some(Decision::Deny), Some(INVARIANT_HOLDS.to_owned())),
        Verdict::Fail => (Some(Decision::Allow), Some(INVARIANT_VIOLATED.to_owned())),
        Verdict::Inconclusive | Verdict::Error => (None, None),
    }
}

fn expected_description(invariant: &str) -> String {
    format!("security invariant {invariant} holds")
}

fn observed_description(verdict: Verdict, invariant: &str) -> String {
    match verdict {
        Verdict::Pass => format!("invariant {invariant} held for this bounded trial"),
        Verdict::Fail => format!("invariant {invariant} was violated"),
        Verdict::Inconclusive => {
            format!("evidence was insufficient to decide invariant {invariant}")
        }
        Verdict::Error => format!("invariant {invariant} could not be evaluated"),
    }
}

/// Build one Cycle 001 evidence record for one trial.
pub fn build_trial_evidence(
    scenario: &PromptInjectionScenario,
    entry: &CorpusEntry,
    binding: &IdentityBinding,
    result: &PromptInjectionResult,
    trial: &TrialRecord,
    now: OffsetDateTime,
) -> Result<SecurityEvidence> {
    let invariant = result.invariant.as_str();

    let mut extensions = BTreeMap::new();
    extensions.insert(
        EXTENSION_NAMESPACE.to_owned(),
        json!({
            "scenario_id": binding.scenario_id,
            "scenario_digest": binding.scenario_digest,
            "corpus_id": binding.corpus_id,
            "corpus_digest": binding.corpus_digest,
            "objective_id": binding.objective_id,
            "objective_digest": binding.objective_digest,
            "property_id": result.property_id,
            "family": result.family,
            "source_kind": result.source_kind,
            "source_trust": result.source_trust,
            "direction": result.direction,
            "mode": result.mode,
            "synthetic": result.synthetic,
            "invariant": invariant,
            "trial_index": trial.index,
            "trials_planned": result.trials_planned,
            "trials_executed": result.trials_executed,
            "stop_reason": result.stop_reason,
            "normalized_event_digests": trial.event_digests,
            "budget": result.budget,
            "controls": result.controls,
            "bounded_claim_note":
                "Verdicts are scoped to the tested vector under the recorded conditions and \
                 never assert universal prompt-injection security.",
        }),
    );

    let preconditions: Vec<Precondition> = vec![
        Precondition {
            id: Some("local-only".to_owned()),
            description: "execution was local and offline".to_owned(),
            satisfied: true,
        },
        Precondition {
            id: Some("source-boundary".to_owned()),
            description: format!(
                "injected content entered through the {} boundary",
                result.source_kind.as_str()
            ),
            satisfied: true,
        },
    ];

    // Attribution comes from the corpus vector, which the schema guarantees
    // carries at least one standards reference, plus anything the scenario adds.
    let mut standards: Vec<StandardMapping> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for reference in entry.standards.iter().chain(scenario.standards.iter()) {
        if !seen.insert((reference.source.clone(), reference.reference.clone())) {
            continue;
        }
        standards.push(StandardMapping {
            organization: "OWASP".to_owned(),
            standard: reference.source.clone(),
            version: None,
            control: reference.reference.clone(),
            url: None,
        });
    }

    let evidence = SecurityEvidence {
        schema: SchemaRef {
            id: EVIDENCE_SCHEMA_ID.to_owned(),
            version: SchemaVersion::V1,
        },
        id: evidence_id(binding, trial.index)?,
        vector: VectorRef {
            id: binding.corpus_id.clone(),
            version: "1".to_owned(),
            name: scenario.title.clone(),
        },
        target: TargetRef {
            // Cycle 013 never targets a production system.
            type_: "synthetic-agent".to_owned(),
            id: "synthetic-prompt-injection-lab".to_owned(),
            name: Some("DARE synthetic prompt-injection lab".to_owned()),
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
            description: Some(expected_description(invariant)),
        },
        observed: ObservedOutcome {
            decision: observed_decision(trial.verdict).0,
            result: observed_decision(trial.verdict).1,
            description: Some(observed_description(trial.verdict, invariant)),
            // Observations come from local fixtures, never a live protocol.
            source: ObservationSource::Fixture,
        },
        verdict: trial.verdict,
        // Severity is never inferred from the verdict alone.
        severity: None,
        standards,
        artifacts: Vec::new(),
        hashes: vec![
            HashRef {
                algorithm: "sha256".to_owned(),
                value: binding
                    .scenario_digest
                    .trim_start_matches("sha256:")
                    .to_owned(),
            },
            HashRef {
                algorithm: "sha256".to_owned(),
                value: binding
                    .corpus_digest
                    .trim_start_matches("sha256:")
                    .to_owned(),
            },
        ],
        redaction: RedactionMetadata {
            applied: true,
            strategy: RedactionStrategy::Mask,
            fields: vec![
                "observed.model_output".to_owned(),
                "observed.canary_disclosure".to_owned(),
            ],
        },
        timestamps: EvidenceTimestamps {
            started_at: Some(now),
            observed_at: now,
            recorded_at: now,
        },
        extensions: Some(extensions),
    };

    // Final gate: never persist a record that carries a secret.
    validate_secret_safety(&evidence).map_err(|err| {
        PromptInjectionError::refusal(format!("evidence failed secret-safety validation: {err}"))
    })?;

    Ok(evidence)
}

/// Build Cycle 001 evidence for every executed trial.
pub fn build_evidence(
    scenario: &PromptInjectionScenario,
    entry: &CorpusEntry,
    binding: &IdentityBinding,
    result: &PromptInjectionResult,
    now: OffsetDateTime,
) -> Result<Vec<SecurityEvidence>> {
    result
        .trials
        .iter()
        .map(|trial| build_trial_evidence(scenario, entry, binding, result, trial, now))
        .collect()
}

/// Mode label recorded in evidence. Never a remote provider.
pub fn mode_label(mode: HarnessMode) -> &'static str {
    mode.as_str()
}

/// Decision vocabulary is reused, never redefined.
pub fn reused_decision_vocabulary() -> [Decision; 5] {
    [
        Decision::Allow,
        Decision::Deny,
        Decision::ReEvaluate,
        Decision::RequiresApproval,
        Decision::NotApplicable,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::run_scenario;
    use crate::simulated::{SimulatedAdapter, SimulationProfile};
    use crate::trials::TrialPlan;
    use dare_security_evidence::validate;
    use serde_json::{json, Value};
    use time::macros::datetime;

    fn scenario() -> PromptInjectionScenario {
        let mut value = crate::schema::tests::valid_scenario();
        value["vector"]["corpus_id"] = json!("direct-ignore-objective-001");
        serde_json::from_value(value).unwrap()
    }

    fn entry() -> CorpusEntry {
        serde_json::from_value(crate::corpus::tests::direct_entry()).unwrap()
    }

    fn build(profile: SimulationProfile) -> (Vec<SecurityEvidence>, PromptInjectionResult) {
        let scenario = scenario();
        let entry = entry();
        let binding = crate::canonical::bind(&scenario, &entry).unwrap();
        let result = run_scenario(
            &scenario,
            &entry,
            &SimulatedAdapter::new(profile),
            TrialPlan {
                trials: 2,
                stop_on_first_fail: false,
                ..TrialPlan::default()
            },
        )
        .unwrap();
        let evidence = build_evidence(
            &scenario,
            &entry,
            &binding,
            &result,
            datetime!(2026-09-05 12:00:00 UTC),
        )
        .unwrap();
        (evidence, result)
    }

    #[test]
    fn evidence_records_validate_against_the_cycle_001_contract() {
        let (evidence, _) = build(SimulationProfile::secure());
        assert_eq!(evidence.len(), 2);
        for record in &evidence {
            validate(record).expect("Cycle 001 evidence is valid");
            assert_eq!(record.schema.version, SchemaVersion::V1);
            assert_eq!(record.schema.id, EVIDENCE_SCHEMA_ID);
        }
    }

    #[test]
    fn evidence_reuses_the_cycle_001_verdict_vocabulary() {
        let (evidence, result) = build(SimulationProfile::vulnerable());
        for (record, trial) in evidence.iter().zip(result.trials.iter()) {
            assert_eq!(record.verdict, trial.verdict);
        }
        // No second verdict enum exists to confuse this with.
        assert_eq!(Verdict::Fail.as_str(), "FAIL");
        assert_eq!(reused_decision_vocabulary().len(), 5);
    }

    #[test]
    fn evidence_ids_are_stable_and_bound_to_identity() {
        let (first, _) = build(SimulationProfile::secure());
        let (second, _) = build(SimulationProfile::secure());
        let a: Vec<&str> = first.iter().map(|r| r.id.as_str()).collect();
        let b: Vec<&str> = second.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(a, b, "evidence ids must be reproducible");
        assert!(a[0].starts_with("urn:dare:prompt-injection:evidence:"));
        assert_ne!(a[0], a[1], "each trial gets its own record");
    }

    #[test]
    fn a_different_objective_produces_different_evidence_ids() {
        let scenario = scenario();
        let entry = entry();
        let binding = crate::canonical::bind(&scenario, &entry).unwrap();

        let mut swapped = scenario.clone();
        swapped.objective.authorized_goal_id = "goal-something-else".to_owned();
        let swapped_binding = crate::canonical::bind(&swapped, &entry).unwrap();

        assert_ne!(
            evidence_id(&binding, 0).unwrap(),
            evidence_id(&swapped_binding, 0).unwrap()
        );
    }

    #[test]
    fn prompt_injection_metadata_lives_in_the_namespaced_extension() {
        let (evidence, _) = build(SimulationProfile::secure());
        let extensions = evidence[0].extensions.as_ref().expect("extensions");
        let payload = extensions.get(EXTENSION_NAMESPACE).expect("namespace");

        for key in [
            "scenario_digest",
            "corpus_digest",
            "objective_digest",
            "property_id",
            "source_kind",
            "direction",
            "mode",
            "invariant",
            "trial_index",
            "trials_planned",
            "trials_executed",
            "stop_reason",
            "normalized_event_digests",
            "budget",
        ] {
            assert!(payload.get(key).is_some(), "extension is missing {key}");
        }

        // Core evidence fields were not extended with prompt-specific keys.
        let core = serde_json::to_value(&evidence[0]).unwrap();
        let object = core.as_object().unwrap();
        assert!(!object.contains_key("scenario_digest"));
        assert!(!object.contains_key("invariant"));
    }

    #[test]
    fn evidence_declares_redaction_and_passes_secret_safety() {
        let (evidence, _) = build(SimulationProfile::vulnerable());
        for record in &evidence {
            assert!(record.redaction.applied);
            assert_eq!(record.redaction.strategy, RedactionStrategy::Mask);
            assert!(!record.redaction.fields.is_empty());
            validate_secret_safety(record).expect("no secrets in evidence");
        }

        let serialized = serde_json::to_string(&evidence).unwrap();
        assert!(!serialized.contains("DARE-SYNTHETIC-CANARY-ALPHA1"));
        assert!(!serialized.contains("ALPHA1"));
    }

    #[test]
    fn evidence_records_a_synthetic_target_never_a_production_one() {
        let (evidence, _) = build(SimulationProfile::secure());
        let target = &evidence[0].target;
        assert_eq!(target.type_, "synthetic-agent");
        assert!(target.id.contains("synthetic"));
        assert_eq!(evidence[0].observed.source, ObservationSource::Fixture);

        // The only https reference permitted is the evidence schema id itself.
        assert!(target.software.is_none());
        assert!(target.protocol.is_none());
        let extension = serde_json::to_string(
            evidence[0]
                .extensions
                .as_ref()
                .and_then(|e| e.get(EXTENSION_NAMESPACE))
                .expect("extension"),
        )
        .unwrap();
        assert!(!extension.contains("https://"));
        assert!(!extension.to_lowercase().contains("provider"));
        assert!(!extension.to_lowercase().contains("endpoint"));
    }

    #[test]
    fn severity_is_never_inferred_from_the_verdict() {
        let (evidence, _) = build(SimulationProfile::vulnerable());
        for record in &evidence {
            assert!(
                record.severity.is_none(),
                "severity must not be derived from a FAIL verdict alone"
            );
        }
    }

    #[test]
    fn evidence_carries_standards_attribution_without_claiming_equivalence() {
        let (evidence, _) = build(SimulationProfile::secure());
        let standards = &evidence[0].standards;
        assert!(!standards.is_empty());
        for mapping in standards {
            assert_eq!(mapping.organization, "OWASP");
            assert!(!mapping.control.is_empty());
        }
        let payload: Value = serde_json::to_value(&evidence[0]).unwrap();
        let note = payload["extensions"][EXTENSION_NAMESPACE]["bounded_claim_note"]
            .as_str()
            .unwrap_or_default();
        assert!(note.contains("never assert universal"));
    }

    #[test]
    fn evidence_round_trips_through_the_public_contract() {
        let (evidence, _) = build(SimulationProfile::secure());
        let json = serde_json::to_string(&evidence[0]).unwrap();
        let decoded: SecurityEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, evidence[0]);
        validate(&decoded).expect("still valid after round trip");
    }
}
