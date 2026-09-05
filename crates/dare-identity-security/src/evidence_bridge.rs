//! Cycle 001 evidence bridge.
//!
//! Cycle 015 defines no second evidence contract and no second verdict
//! vocabulary. It emits `dare_security_evidence::SecurityEvidence` records and
//! puts identity-security specifics in the namespaced `extensions` container,
//! which is what that container exists for.
//!
//! Records are redacted before construction — the observation layer has already
//! masked canaries and credential shapes — and a final secret-safety check runs
//! before any record is returned. A record that would carry a secret is refused,
//! not trimmed.

use std::collections::{BTreeMap, BTreeSet};

use dare_security_evidence::{
    validate_secret_safety, Decision, EvidenceTimestamps, ExpectedOutcome, HashRef,
    ObservationSource, ObservedOutcome, Precondition, RedactionMetadata, RedactionStrategy,
    SchemaRef, SchemaVersion, SecurityEvidence, StandardMapping, TargetRef, VectorRef, Verdict,
};
use serde_json::json;
use time::OffsetDateTime;

use crate::canonical::{digest, IdentityBinding};
use crate::error::{IdentitySecurityError, Result};
use crate::harness::HarnessMode;
use crate::model::{IdentityCorpusEntry, IdentitySecurityScenario};
use crate::result::{IdentitySecurityResult, IdentityTrialRecord};

pub const EVIDENCE_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/evidence/v1/evidence.schema.json";

/// Namespace for Cycle 015 evidence extensions.
pub const EXTENSION_NAMESPACE: &str = "dare.identity-security.v1";

/// The synthetic target Cycle 015 runs against. Never a production system.
pub const SYNTHETIC_TARGET_ID: &str = "synthetic-identity-security-lab";

/// Stable evidence identifier for one trial of one bound scenario.
///
/// Derived from every bound identity plus the trial index, so the same run
/// produces the same identifiers and any substitution produces different ones.
pub fn evidence_id(binding: &IdentityBinding, trial_index: u32) -> Result<String> {
    let identity = digest(&json!({
        "scenario_digest": binding.scenario_digest,
        "principal_set_digest": binding.principal_set_digest,
        "authority_digests": binding.authority_digests,
        "delegation_chain_digest": binding.delegation_chain_digest,
        "resource_context_digest": binding.resource_context_digest,
        "policy_digest": binding.policy_digest,
        "trial_index": trial_index,
    }))?;
    let hex = identity.trim_start_matches("sha256:");
    Ok(format!("urn:dare:identity-security:evidence:{hex}"))
}

/// Evidence identifiers for every executed trial.
pub fn evidence_ids(
    binding: &IdentityBinding,
    trials: &[IdentityTrialRecord],
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
/// The expected decision is always DENY: authority that was never delegated
/// must not be exercised. A held boundary is observed as DENY, a crossed one as
/// ALLOW. Undecidable trials carry no decision at all, which is what keeps
/// INCONCLUSIVE and ERROR from masquerading as either.
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
    scenario: &IdentitySecurityScenario,
    entry: Option<&IdentityCorpusEntry>,
    binding: &IdentityBinding,
    result: &IdentitySecurityResult,
    trial: &IdentityTrialRecord,
    now: OffsetDateTime,
) -> Result<SecurityEvidence> {
    let invariant = result.invariant.as_str();

    // Built in groups and merged: one `json!` literal large enough to hold the
    // whole record exceeds the macro's recursion limit, and grouping also keeps
    // the identity facts, the run facts and the standing notes legible.
    let identity = json!({
        "scenario_id": binding.scenario_id,
        "scenario_digest": binding.scenario_digest,
        "objective_id": binding.objective_id,
        "principal_set_id": binding.principal_set_id,
        "principal_set_digest": binding.principal_set_digest,
        // The five roles stay explicitly distinct in the record; collapsing
        // them is the confusion the whole cycle is about.
        "initiating_principal_id": binding.initiating_principal_id,
        "effective_principal_id": binding.effective_principal_id,
        "agent_principal_id": binding.agent_principal_id,
        "delegated_subject_id": binding.delegated_subject_id,
        "resource_owner_id": binding.resource_owner_id,
        "authority_digests": result.authority_digests,
        "delegation_chain_id": binding.delegation_chain_id,
        "delegation_chain_digest": binding.delegation_chain_digest,
        "resource_context_digest": binding.resource_context_digest,
        "tenant_id": binding.tenant_id,
        "policy_id": binding.policy_id,
        "policy_digest": binding.policy_digest,
        "corpus_id": result.corpus_id,
        "corpus_digest": result.corpus_digest,
    });

    let run = json!({
        "property_id": result.property_id,
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
        "operations": trial.operations,
        "authorization_decisions": trial.authorization_decisions,
        "delegation_depth": trial.delegation_depth,
        "coverage_satisfied": trial.coverage_satisfied,
        "violations": trial.violations,
        "normalized_events": trial.events,
        "normalized_event_digests": trial.event_digests,
        "budget": result.budget,
        "controls": result.controls,
        "redaction_state": result.redaction_state,
    });

    let notes = json!({
        "authority_relation": "effective_authority <= delegated_or_source_authority_ceiling",
        "credential_rule":
            "The presence of a service, workload or technical credential is capability \
             availability and not delegated authority.",
        "bounded_claim_note":
            "Verdicts are scoped to the tested vectors under the recorded conditions and never \
             assert that identity, authorization or privilege handling is secure or immune.",
        "execution_note":
            "Operations are observed, never dispatched. No identity provider, OAuth server, \
             PDP, AuthZEN endpoint, MCP server, network endpoint or state change is involved, \
             and no token is parsed or validated.",
    });

    let mut payload = serde_json::Map::new();
    for group in [identity, run, notes] {
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

    let preconditions: Vec<Precondition> = vec![
        Precondition {
            id: Some("local-only".to_owned()),
            description: "execution was local and offline".to_owned(),
            satisfied: true,
        },
        Precondition {
            id: Some("no-operation-dispatch".to_owned()),
            description: "structured operations were observed and never dispatched".to_owned(),
            satisfied: true,
        },
        Precondition {
            id: Some("principal-set-bound".to_owned()),
            description: format!(
                "the principal set was bound to the approved digest for {}",
                binding.principal_set_id
            ),
            satisfied: true,
        },
        Precondition {
            id: Some("synthetic-identities".to_owned()),
            description: "every principal, tenant, resource and credential context was synthetic"
                .to_owned(),
            satisfied: true,
        },
        Precondition {
            id: Some("source-boundary".to_owned()),
            description: format!(
                "identity context entered through the {} boundary",
                result.source_kind.as_str()
            ),
            satisfied: true,
        },
    ];

    // Attribution comes from the corpus vector when there is one, plus anything
    // the scenario declares. Duplicates collapse. A draft or proposal keeps its
    // own status; nothing here turns one into a conformance claim.
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
            value: strip(&binding.principal_set_digest),
        },
    ];
    for optional in [
        binding.delegation_chain_digest.as_ref(),
        binding.resource_context_digest.as_ref(),
        binding.policy_digest.as_ref(),
        result.corpus_digest.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        hashes.push(HashRef {
            algorithm: "sha256".to_owned(),
            value: strip(optional),
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
            // Cycle 015 never targets a production system or a real identity.
            type_: "synthetic-agent".to_owned(),
            id: SYNTHETIC_TARGET_ID.to_owned(),
            name: Some("DARE synthetic identity-security lab".to_owned()),
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
            // identity provider, authorization server or protocol exchange.
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
                "observed.credential_context".to_owned(),
                "observed.evidence_text".to_owned(),
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
        IdentitySecurityError::refusal(format!("evidence failed secret-safety validation: {err}"))
    })?;

    Ok(evidence)
}

fn strip(digest: &str) -> String {
    digest.trim_start_matches("sha256:").to_owned()
}

/// Build Cycle 001 evidence for every executed trial.
pub fn build_evidence(
    scenario: &IdentitySecurityScenario,
    entry: Option<&IdentityCorpusEntry>,
    binding: &IdentityBinding,
    result: &IdentitySecurityResult,
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
    use crate::model::ReferenceBehavior;
    use crate::result::run_scenario;
    use crate::simulated::SimulatedAdapter;
    use crate::trials::TrialPlan;

    fn fixed_time() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_767_225_600).expect("valid timestamp")
    }

    fn run(behavior: ReferenceBehavior) -> (IdentitySecurityScenario, IdentitySecurityResult) {
        let mut scenario = scenario();
        scenario
            .lab
            .as_mut()
            .expect("the fixture declares a lab spec")
            .reference_behavior = behavior;
        let plan = TrialPlan::from_scenario(&scenario).expect("plan");
        let result = run_scenario(&scenario, None, &SimulatedAdapter::new(), plan).expect("runs");
        (scenario, result)
    }

    #[test]
    fn evidence_reuses_the_cycle_001_contract_and_vocabulary() {
        let (scenario, result) = run(ReferenceBehavior::Compliant);
        let binding = bind(&scenario).expect("binds");
        let records =
            build_evidence(&scenario, None, &binding, &result, fixed_time()).expect("evidence");

        assert_eq!(records.len(), result.trials.len());
        for record in &records {
            assert_eq!(record.schema.id, EVIDENCE_SCHEMA_ID);
            assert_eq!(record.schema.version, SchemaVersion::V1);
            assert_eq!(record.verdict, Verdict::Pass);
            assert_eq!(record.observed.source, ObservationSource::Fixture);
            assert!(record.redaction.applied);
            assert_eq!(record.target.id, SYNTHETIC_TARGET_ID);
            assert!(record
                .id
                .starts_with("urn:dare:identity-security:evidence:"));
        }
        assert_eq!(reused_decision_vocabulary().len(), 5);
    }

    #[test]
    fn evidence_carries_the_enumerated_identity_facts() {
        let (scenario, result) = run(ReferenceBehavior::Compliant);
        let binding = bind(&scenario).expect("binds");
        let records =
            build_evidence(&scenario, None, &binding, &result, fixed_time()).expect("evidence");
        let extension = records[0]
            .extensions
            .as_ref()
            .expect("extensions")
            .get(EXTENSION_NAMESPACE)
            .expect("namespace");

        for field in [
            "scenario_digest",
            "principal_set_digest",
            "initiating_principal_id",
            "effective_principal_id",
            "agent_principal_id",
            "delegated_subject_id",
            "resource_owner_id",
            "authority_digests",
            "delegation_chain_digest",
            "resource_context_digest",
            "policy_digest",
            "invariant",
            "mode",
            "synthetic",
            "budget",
            "redaction_state",
            "coverage_satisfied",
            "violations",
        ] {
            assert!(extension.get(field).is_some(), "{field} missing");
        }

        assert_eq!(
            extension["authority_relation"],
            "effective_authority <= delegated_or_source_authority_ceiling"
        );
        assert!(extension["credential_rule"]
            .as_str()
            .expect("string")
            .contains("not delegated authority"));
        assert_eq!(extension["synthetic"], true);
    }

    #[test]
    fn an_undecidable_trial_carries_no_decision_in_either_direction() {
        for behavior in [
            ReferenceBehavior::NoRelevantObservation,
            ReferenceBehavior::HarnessFailure,
        ] {
            let (scenario, result) = run(behavior);
            let binding = bind(&scenario).expect("binds");
            let records =
                build_evidence(&scenario, None, &binding, &result, fixed_time()).expect("evidence");
            for record in &records {
                assert!(record.observed.decision.is_none(), "{}", behavior.as_str());
                assert!(record.observed.result.is_none(), "{}", behavior.as_str());
                assert!(record.severity.is_none(), "{}", behavior.as_str());
            }
        }
    }

    #[test]
    fn a_violation_is_observed_as_allow_against_an_expected_deny() {
        let mut scenario = scenario();
        scenario.lab.as_mut().expect("lab spec").reference_behavior =
            ReferenceBehavior::AgentAuthoritySubstitutedForUser;
        scenario.invariant.type_ =
            crate::model::IdentityInvariantType::AgentAuthorityNotSubstitutedForUser;

        let plan = TrialPlan::from_scenario(&scenario).expect("plan");
        let result = run_scenario(&scenario, None, &SimulatedAdapter::new(), plan).expect("runs");
        let binding = bind(&scenario).expect("binds");
        let records =
            build_evidence(&scenario, None, &binding, &result, fixed_time()).expect("evidence");

        assert_eq!(records[0].verdict, Verdict::Fail);
        assert_eq!(records[0].expected.decision, Some(Decision::Deny));
        assert_eq!(records[0].observed.decision, Some(Decision::Allow));
        assert_eq!(
            records[0].observed.result.as_deref(),
            Some(INVARIANT_VIOLATED)
        );
    }

    #[test]
    fn evidence_ids_are_stable_and_change_when_a_binding_changes() {
        let (scenario, result) = run(ReferenceBehavior::Compliant);
        let binding = bind(&scenario).expect("binds");
        let first = evidence_ids(&binding, &result.trials).expect("ids");
        let second = evidence_ids(&binding, &result.trials).expect("ids");
        assert_eq!(first, second);

        let mut substituted = scenario.clone();
        substituted.principals.set_id = "principals-substituted".to_owned();
        let other = bind(&substituted).expect("binds");
        let changed = evidence_ids(&other, &result.trials).expect("ids");
        assert_ne!(first, changed);
    }

    #[test]
    fn no_evidence_record_names_a_provider_or_a_live_mode() {
        let (scenario, result) = run(ReferenceBehavior::Compliant);
        let binding = bind(&scenario).expect("binds");
        let records =
            build_evidence(&scenario, None, &binding, &result, fixed_time()).expect("evidence");
        let json = serde_json::to_string(&records).expect("serializes");

        // The only network URL a record may carry is the Cycle 001 schema
        // identifier; anything else would be a host this cycle cannot name.
        // Synthetic audience labels such as `api://support` are declarative
        // identifiers, not endpoints, and are left alone.
        let mut rest = json.as_str();
        while let Some(index) = rest.find("http") {
            let start = rest[..index].rfind('"').map(|quote| quote + 1).unwrap_or(0);
            let url = &rest[start..];
            let end = url.find('"').unwrap_or(url.len());
            let url = &url[..end];
            assert_eq!(
                url, EVIDENCE_SCHEMA_ID,
                "evidence names a host other than the Cycle 001 schema"
            );
            rest = &rest[index + "http".len()..];
        }

        for banned in [
            "LIVE_IDP",
            "REMOTE_PDP",
            "AUTHZEN_ENDPOINT",
            "jwks_uri",
            "issuer",
        ] {
            assert!(!json.contains(banned), "`{banned}` in the evidence");
        }
    }

    #[test]
    fn evidence_never_claims_conformance_with_a_draft() {
        let (scenario, result) = run(ReferenceBehavior::Compliant);
        let binding = bind(&scenario).expect("binds");
        let records =
            build_evidence(&scenario, None, &binding, &result, fixed_time()).expect("evidence");
        let json = serde_json::to_string(&records).expect("serializes");

        for banned in [
            "AuthZEN compliant",
            "COAZ compliant",
            "Identity Secure",
            "Fully Protected",
            "Immune",
        ] {
            assert!(!json.contains(banned), "`{banned}` in the evidence");
        }
    }
}
