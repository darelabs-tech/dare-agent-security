//! Cycle 001 evidence bridge.
//!
//! Cycle 014 defines no second evidence contract and no second verdict
//! vocabulary. It emits `dare_security_evidence::SecurityEvidence` records and
//! puts tool-security specifics in the namespaced `extensions` container, which
//! is what that container exists for.
//!
//! Records are redacted before construction — the observation layer has already
//! masked canaries and credential shapes — and a final secret-safety check runs
//! before any record is returned.

use std::collections::{BTreeMap, BTreeSet};

use dare_security_evidence::{
    validate_secret_safety, Decision, EvidenceTimestamps, ExpectedOutcome, HashRef,
    ObservationSource, ObservedOutcome, Precondition, RedactionMetadata, RedactionStrategy,
    SchemaRef, SchemaVersion, SecurityEvidence, StandardMapping, TargetRef, VectorRef, Verdict,
};
use serde_json::json;
use time::OffsetDateTime;

use crate::canonical::{digest, ToolIdentityBinding};
use crate::error::{Result, ToolSecurityError};
use crate::harness::ToolHarnessMode;
use crate::model::{ToolCorpusEntry, ToolSecurityScenario};
use crate::result::{ToolSecurityResult, ToolTrialRecord};

pub const EVIDENCE_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/evidence/v1/evidence.schema.json";

/// Namespace for Cycle 014 evidence extensions.
pub const EXTENSION_NAMESPACE: &str = "dare.tool-security.v1";

/// The synthetic target Cycle 014 runs against. Never a production system.
pub const SYNTHETIC_TARGET_ID: &str = "synthetic-tool-security-lab";

/// Stable evidence identifier for one trial of one bound scenario.
///
/// Derived from every bound identity plus the trial index, so the same run
/// produces the same identifiers and any substitution produces different ones.
pub fn evidence_id(binding: &ToolIdentityBinding, trial_index: u32) -> Result<String> {
    let identity = digest(&json!({
        "scenario_digest": binding.scenario_digest,
        "objective_digest": binding.objective_digest,
        "policy_digest": binding.policy_digest,
        "surface_digest": binding.surface_digest,
        "trial_index": trial_index,
    }))?;
    let hex = identity.trim_start_matches("sha256:");
    Ok(format!("urn:dare:tool-security:evidence:{hex}"))
}

/// Evidence identifiers for every executed trial.
pub fn evidence_ids(
    binding: &ToolIdentityBinding,
    trials: &[ToolTrialRecord],
) -> Result<Vec<String>> {
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
/// The expected decision is always DENY: untrusted tool metadata and tool
/// output must not be granted authority over the approved policy. A held
/// boundary is observed as DENY, a crossed one as ALLOW. Undecidable trials
/// carry no decision at all, which is what keeps INCONCLUSIVE and ERROR from
/// masquerading as either.
fn observed_decision(verdict: Verdict) -> (Option<Decision>, Option<String>) {
    match verdict {
        Verdict::Pass => (Some(Decision::Deny), Some(INVARIANT_HOLDS.to_owned())),
        Verdict::Fail => (Some(Decision::Allow), Some(INVARIANT_VIOLATED.to_owned())),
        Verdict::Inconclusive | Verdict::Error => (None, None),
    }
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
    scenario: &ToolSecurityScenario,
    entry: Option<&ToolCorpusEntry>,
    binding: &ToolIdentityBinding,
    result: &ToolSecurityResult,
    trial: &ToolTrialRecord,
    now: OffsetDateTime,
) -> Result<SecurityEvidence> {
    let invariant = result.invariant.as_str();

    let mut extensions = BTreeMap::new();
    extensions.insert(
        EXTENSION_NAMESPACE.to_owned(),
        json!({
            "scenario_id": binding.scenario_id,
            "scenario_digest": binding.scenario_digest,
            "objective_id": binding.objective_id,
            "objective_digest": binding.objective_digest,
            "policy_id": binding.policy_id,
            "policy_digest": binding.policy_digest,
            "surface_id": binding.surface_id,
            "surface_digest": binding.surface_digest,
            "tool_digests": result.tool_digests,
            "corpus_id": result.corpus_id,
            "corpus_digest": result.corpus_digest,
            "property_id": result.property_id,
            "family": result.family,
            "class": result.class,
            "source_kind": result.source_kind,
            "source_trust": result.source_trust,
            "mode": result.mode,
            "synthetic": result.synthetic,
            "invariant": invariant,
            "trial_index": trial.index,
            "trials_planned": result.trials_planned,
            "trials_executed": result.trials_executed,
            "stop_reason": result.stop_reason,
            "tool_requests": trial.tool_requests,
            "chain_depth": trial.chain_depth,
            "coverage_satisfied": trial.coverage_satisfied,
            "violations": trial.violations,
            "normalized_events": trial.events,
            "normalized_event_digests": trial.event_digests,
            "budget": result.budget,
            "controls": result.controls,
            "redaction_state": result.redaction_state,
            "bounded_claim_note":
                "Verdicts are scoped to the tested vectors under the recorded conditions and \
                 never assert that the tools are secure, safe or immune.",
            "execution_note":
                "Tool requests are observed, never dispatched. No tool, MCP server, model, \
                 network endpoint or state change is involved.",
        }),
    );

    let preconditions: Vec<Precondition> = vec![
        Precondition {
            id: Some("local-only".to_owned()),
            description: "execution was local and offline".to_owned(),
            satisfied: true,
        },
        Precondition {
            id: Some("no-tool-dispatch".to_owned()),
            description: "structured tool requests were observed and never dispatched".to_owned(),
            satisfied: true,
        },
        Precondition {
            id: Some("tool-surface-bound".to_owned()),
            description: format!(
                "the tool surface was bound to the approved digest for {}",
                binding.surface_id
            ),
            satisfied: true,
        },
        Precondition {
            id: Some("source-boundary".to_owned()),
            description: format!(
                "untrusted tool data entered through the {} boundary",
                result.source_kind.as_str()
            ),
            satisfied: true,
        },
    ];

    // Attribution comes from the corpus vector when there is one, plus anything
    // the scenario declares. Duplicates collapse.
    let mut standards: Vec<StandardMapping> = Vec::new();
    let mut seen = BTreeSet::new();
    let entry_standards = entry.map(|entry| entry.standards.as_slice()).unwrap_or(&[]);
    for reference in entry_standards.iter().chain(scenario.standards.iter()) {
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

    let mut hashes = vec![
        HashRef {
            algorithm: "sha256".to_owned(),
            value: strip(&binding.scenario_digest),
        },
        HashRef {
            algorithm: "sha256".to_owned(),
            value: strip(&binding.policy_digest),
        },
        HashRef {
            algorithm: "sha256".to_owned(),
            value: strip(&binding.surface_digest),
        },
    ];
    if let Some(corpus_digest) = &result.corpus_digest {
        hashes.push(HashRef {
            algorithm: "sha256".to_owned(),
            value: strip(corpus_digest),
        });
    }

    let (decision, outcome_result) = observed_decision(trial.verdict);
    let evidence = SecurityEvidence {
        schema: SchemaRef {
            id: EVIDENCE_SCHEMA_ID.to_owned(),
            version: SchemaVersion::V1,
        },
        id: evidence_id(binding, trial.index)?,
        vector: VectorRef {
            id: result
                .corpus_id
                .clone()
                .unwrap_or_else(|| binding.scenario_id.clone()),
            version: "1".to_owned(),
            name: scenario.title.clone(),
        },
        target: TargetRef {
            // Cycle 014 never targets a production system.
            type_: "synthetic-agent".to_owned(),
            id: SYNTHETIC_TARGET_ID.to_owned(),
            name: Some("DARE synthetic tool-security lab".to_owned()),
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
            decision,
            result: outcome_result,
            description: Some(observed_description(trial.verdict, invariant)),
            // Observations come from local fixtures and traces, never a live
            // tool call or protocol exchange.
            source: ObservationSource::Fixture,
        },
        verdict: trial.verdict,
        // Severity is never inferred from the verdict alone.
        severity: None,
        standards,
        artifacts: Vec::new(),
        hashes,
        redaction: RedactionMetadata {
            applied: true,
            strategy: RedactionStrategy::Mask,
            fields: vec![
                "observed.tool_output".to_owned(),
                "observed.tool_arguments".to_owned(),
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
        ToolSecurityError::refusal(format!("evidence failed secret-safety validation: {err}"))
    })?;

    Ok(evidence)
}

fn strip(digest: &str) -> String {
    digest.trim_start_matches("sha256:").to_owned()
}

/// Build Cycle 001 evidence for every executed trial.
pub fn build_evidence(
    scenario: &ToolSecurityScenario,
    entry: Option<&ToolCorpusEntry>,
    binding: &ToolIdentityBinding,
    result: &ToolSecurityResult,
    now: OffsetDateTime,
) -> Result<Vec<SecurityEvidence>> {
    result
        .trials
        .iter()
        .map(|trial| build_trial_evidence(scenario, entry, binding, result, trial, now))
        .collect()
}

/// Mode label recorded in evidence. Never a remote provider.
pub fn mode_label(mode: ToolHarnessMode) -> &'static str {
    mode.as_str()
}

/// The Cycle 001 decision vocabulary, reused rather than redefined.
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
    use crate::canonical::bind;
    use crate::harness::tests::scenario;
    use crate::model::{ReferenceBehavior, ToolInvariantType, ToolLabSpec};
    use crate::result::run_scenario;
    use crate::simulated::ToolSimulatedAdapter;
    use crate::trials::ToolTrialPlan;
    use dare_security_evidence::validate;
    use serde_json::Value;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-09-05 12:00:00 UTC);

    fn lab(behavior: ReferenceBehavior) -> ToolLabSpec {
        ToolLabSpec {
            reference_behavior: behavior,
            per_trial: std::collections::BTreeMap::new(),
            output_filler_bytes: None,
        }
    }

    fn build(
        behavior: ReferenceBehavior,
        invariant: ToolInvariantType,
    ) -> (Vec<SecurityEvidence>, ToolSecurityResult) {
        let mut scenario = scenario();
        scenario.invariant.type_ = invariant;
        let binding = bind(&scenario).expect("binds");
        let result = run_scenario(
            &scenario,
            None,
            &ToolSimulatedAdapter::new(lab(behavior)),
            ToolTrialPlan::default(),
        )
        .expect("runs");
        let evidence =
            build_evidence(&scenario, None, &binding, &result, NOW).expect("evidence builds");
        (evidence, result)
    }

    #[test]
    fn the_cycle_001_verdict_vocabulary_is_reused_not_redefined() {
        assert_eq!(reused_decision_vocabulary().len(), 5);
        let (evidence, result) = build(
            ReferenceBehavior::Compliant,
            ToolInvariantType::ApprovedToolOnly,
        );
        for record in &evidence {
            assert_eq!(record.verdict, Verdict::Pass);
            assert_eq!(record.schema.version, SchemaVersion::V1);
            assert_eq!(record.schema.id, EVIDENCE_SCHEMA_ID);
        }
        assert_eq!(result.verdict, Verdict::Pass);
    }

    #[test]
    fn every_record_passes_the_cycle_001_validator() {
        for (behavior, invariant) in [
            (
                ReferenceBehavior::Compliant,
                ToolInvariantType::ApprovedToolOnly,
            ),
            (
                ReferenceBehavior::UnapprovedToolSelected,
                ToolInvariantType::ApprovedToolOnly,
            ),
            (
                ReferenceBehavior::NoRelevantObservation,
                ToolInvariantType::ApprovedToolOnly,
            ),
            (
                ReferenceBehavior::HarnessFailure,
                ToolInvariantType::ApprovedToolOnly,
            ),
        ] {
            let (evidence, _) = build(behavior, invariant);
            for record in &evidence {
                validate(record).unwrap_or_else(|err| {
                    panic!("{} produced invalid evidence: {err}", behavior.as_str())
                });
            }
        }
    }

    #[test]
    fn evidence_binds_every_identity_the_run_depended_on() {
        let (evidence, _) = build(
            ReferenceBehavior::Compliant,
            ToolInvariantType::ApprovedToolOnly,
        );
        let extension = &evidence[0].extensions.as_ref().expect("extensions")[EXTENSION_NAMESPACE];

        for key in [
            "scenario_digest",
            "objective_digest",
            "policy_digest",
            "surface_digest",
        ] {
            let value = extension[key].as_str().unwrap_or_default();
            assert!(value.starts_with("sha256:"), "{key} = {value}");
        }
        assert!(extension["tool_digests"].as_array().expect("tools").len() >= 2);

        // And the same digests appear as first-class hashes on the record.
        assert!(evidence[0].hashes.len() >= 3);
        for hash in &evidence[0].hashes {
            assert_eq!(hash.algorithm, "sha256");
            assert_eq!(hash.value.len(), 64, "digests are stored unprefixed");
        }
    }

    #[test]
    fn evidence_carries_observations_budget_and_redaction_state() {
        let (evidence, result) = build(
            ReferenceBehavior::Compliant,
            ToolInvariantType::ApprovedToolOnly,
        );
        let extension = &evidence[0].extensions.as_ref().expect("extensions")[EXTENSION_NAMESPACE];

        assert!(!extension["normalized_events"]
            .as_array()
            .expect("events")
            .is_empty());
        assert_eq!(
            extension["redaction_state"],
            Value::String("REDACTED".into())
        );
        assert_eq!(extension["budget"]["state_changes"], serde_json::json!(0));
        assert_eq!(
            extension["budget"]["external_egress_bytes"],
            serde_json::json!(0)
        );
        assert_eq!(
            extension["budget"]["max_total_tool_requests"],
            serde_json::json!(result.budget.max_total_tool_requests)
        );
        assert!(evidence[0].redaction.applied);
        assert_eq!(evidence[0].redaction.strategy, RedactionStrategy::Mask);
    }

    #[test]
    fn an_undecidable_trial_carries_no_decision_in_either_direction() {
        // This is where a lazy bridge would quietly become a false PASS.
        let (evidence, _) = build(
            ReferenceBehavior::NoRelevantObservation,
            ToolInvariantType::ApprovedToolOnly,
        );
        for record in &evidence {
            assert_eq!(record.verdict, Verdict::Inconclusive);
            assert_eq!(record.observed.decision, None);
            assert_eq!(record.observed.result, None);
        }

        let (evidence, _) = build(
            ReferenceBehavior::HarnessFailure,
            ToolInvariantType::ApprovedToolOnly,
        );
        for record in &evidence {
            assert_eq!(record.verdict, Verdict::Error);
            assert_eq!(record.observed.decision, None);
        }
    }

    #[test]
    fn a_violation_is_observed_as_allow_against_an_expected_deny() {
        let (evidence, _) = build(
            ReferenceBehavior::UnapprovedToolSelected,
            ToolInvariantType::ApprovedToolOnly,
        );
        let record = &evidence[0];
        assert_eq!(record.verdict, Verdict::Fail);
        assert_eq!(record.expected.decision, Some(Decision::Deny));
        assert_eq!(record.observed.decision, Some(Decision::Allow));
        assert_eq!(record.observed.result.as_deref(), Some(INVARIANT_VIOLATED));
        assert_eq!(record.severity, None, "severity is never inferred");
    }

    #[test]
    fn every_violation_in_a_trial_is_carried_into_evidence_not_just_the_first() {
        // One unapproved tool crosses the boundary twice — once when selected
        // and once when requested. Both events are independently true, so both
        // must appear; a first-match bridge would report one and lose the other.
        let (evidence, _) = build(
            ReferenceBehavior::UnapprovedToolSelected,
            ToolInvariantType::ApprovedToolOnly,
        );
        let extension = &evidence[0].extensions.as_ref().expect("extensions")[EXTENSION_NAMESPACE];
        let violations = extension["violations"].as_array().expect("violations");
        assert!(
            violations.len() >= 2,
            "one classification must never mask another"
        );
    }

    #[test]
    fn evidence_never_names_a_production_target_or_a_live_observation() {
        let (evidence, _) = build(
            ReferenceBehavior::Compliant,
            ToolInvariantType::ApprovedToolOnly,
        );
        for record in &evidence {
            assert_eq!(record.target.type_, "synthetic-agent");
            assert_eq!(record.target.id, SYNTHETIC_TARGET_ID);
            assert_eq!(record.observed.source, ObservationSource::Fixture);
        }
    }

    #[test]
    fn a_canary_never_reaches_evidence_verbatim() {
        let corpus = crate::corpus::builtin_corpus().expect("corpus");
        let entry = corpus
            .require("benign-redaction-hygiene")
            .expect("control present")
            .clone();

        // The scenario must agree with the vector it binds: property, family
        // and source boundary all have to line up, or bind_corpus refuses.
        let mut scenario = scenario();
        scenario.invariant.type_ = ToolInvariantType::ToolOutputNotReinterpretedAsAuthority;
        scenario.property = entry.property;
        scenario.family = entry.family;
        scenario.source.kind = entry.source_kind;
        scenario.source.trust = entry.trust;
        scenario.vector = Some(crate::model::ToolVectorRef {
            corpus_id: entry.id.clone(),
            corpus_digest: None,
        });
        let binding = bind(&scenario).expect("binds");

        let result = run_scenario(
            &scenario,
            Some(&entry),
            &ToolSimulatedAdapter::from_entry(&entry),
            ToolTrialPlan::default(),
        )
        .expect("runs");
        let evidence =
            build_evidence(&scenario, Some(&entry), &binding, &result, NOW).expect("builds");

        let encoded = serde_json::to_string(&evidence).expect("serializes");
        assert!(
            !encoded.contains("DARE-SYNTHETIC-CANARY-TOOL01"),
            "a canary must never reach evidence verbatim"
        );
        assert!(encoded.contains("[REDACTED]"));
        for record in &evidence {
            validate_secret_safety(record).expect("secret-safe");
        }
    }

    #[test]
    fn evidence_identifiers_are_stable_and_substitution_sensitive() {
        let scenario = scenario();
        let binding = bind(&scenario).expect("binds");
        let first = evidence_id(&binding, 0).expect("id");
        assert_eq!(first, evidence_id(&binding, 0).expect("id"));
        assert_ne!(first, evidence_id(&binding, 1).expect("id"));
        assert!(first.starts_with("urn:dare:tool-security:evidence:"));

        let mut substituted = scenario.clone();
        substituted.policy.forbidden_operation_classes.clear();
        let other = bind(&substituted).expect("binds");
        assert_ne!(
            first,
            evidence_id(&other, 0).expect("id"),
            "a substituted policy must not reuse an identifier"
        );
    }

    #[test]
    fn evidence_records_the_bounded_claim_and_the_no_dispatch_fact() {
        let (evidence, _) = build(
            ReferenceBehavior::Compliant,
            ToolInvariantType::ApprovedToolOnly,
        );
        let extension = &evidence[0].extensions.as_ref().expect("extensions")[EXTENSION_NAMESPACE];
        let note = extension["bounded_claim_note"].as_str().expect("note");
        assert!(note.contains("never assert that the tools are secure"));
        let execution = extension["execution_note"].as_str().expect("note");
        assert!(execution.contains("observed, never dispatched"));
    }
}
