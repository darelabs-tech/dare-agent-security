//! The deterministic invariant registry.
//!
//! Twelve evaluators, each a comparison of typed fields. No model, no
//! heuristic, no prose inference and no fixture-declared verdict appears here.

use serde::{Deserialize, Serialize};

use dare_security_evidence::Verdict;

use crate::coverage::assess_coverage;
use crate::model::SupplyChainInvariant;
use crate::observation::{ObservationSet, SupplyChainObservation};
use crate::source::ComponentType;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainViolation {
    pub invariant: SupplyChainInvariant,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deciding_observation_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component_id: Option<String>,
}

impl SupplyChainViolation {
    fn new(
        invariant: SupplyChainInvariant,
        component_id: Option<&str>,
        reason: impl Into<String>,
        deciding: &[&SupplyChainObservation],
    ) -> Self {
        Self {
            invariant,
            reason: reason.into(),
            deciding_observation_digests: deciding.iter().filter_map(|observation| observation.digest().ok()).collect(),
            component_id: component_id.map(ToOwned::to_owned),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainInvariantOutcome {
    pub invariant: SupplyChainInvariant,
    pub verdict: Verdict,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<SupplyChainViolation>,
    pub coverage_satisfied: bool,
    pub applicable: bool,
}

impl SupplyChainInvariantOutcome {
    fn pass(invariant: SupplyChainInvariant, reason: impl Into<String>) -> Self {
        Self { invariant, verdict: Verdict::Pass, reason: reason.into(), violations: Vec::new(), coverage_satisfied: true, applicable: true }
    }
    fn fail(invariant: SupplyChainInvariant, violations: Vec<SupplyChainViolation>) -> Self {
        let reason = match violations.len() {
            1 => violations[0].reason.clone(),
            count => format!("{count} independent violations of {} were observed", invariant.as_str()),
        };
        Self { invariant, verdict: Verdict::Fail, reason, violations, coverage_satisfied: true, applicable: true }
    }
    fn inconclusive(invariant: SupplyChainInvariant, reason: impl Into<String>, applicable: bool) -> Self {
        Self { invariant, verdict: Verdict::Inconclusive, reason: reason.into(), violations: Vec::new(), coverage_satisfied: false, applicable }
    }
    fn error(invariant: SupplyChainInvariant, reason: impl Into<String>) -> Self {
        Self { invariant, verdict: Verdict::Error, reason: reason.into(), violations: Vec::new(), coverage_satisfied: false, applicable: true }
    }
}

pub fn supported_invariants() -> [SupplyChainInvariant; 12] { SupplyChainInvariant::all() }

pub fn evaluate(invariant: SupplyChainInvariant, observations: &ObservationSet) -> SupplyChainInvariantOutcome {
    use SupplyChainInvariant as I;

    if let Some(SupplyChainObservation::HarnessError(context)) = observations.observations.iter()
        .find(|observation| matches!(observation, SupplyChainObservation::HarnessError(_)))
    {
        return SupplyChainInvariantOutcome::error(invariant, format!("the harness could not observe ({}): {}", context.kind.as_str(), context.reason));
    }

    let violations = match invariant {
        I::ComponentProvenanceSufficient => provenance_sufficient(observations),
        I::ExternalCapabilityDriftNotObserved => capability_drift(observations),
        I::ComponentIdentityUnambiguous => identity_unambiguous(observations),
        I::ArtifactDigestBoundToComponent => artifact_digest_bound(observations),
        I::MutableReferenceNotUsedAsImmutableIdentity => mutable_reference(observations),
        I::ComponentSourceTrustPreserved => source_trust(observations),
        I::ProvenanceSubjectAndBuilderBound => provenance_bound(observations),
        I::AttestationSubjectDigestPreserved => attestation_bound(observations),
        I::DependencyEdgeIntegrityPreserved => dependency_integrity(observations),
        I::ModelLineagePreserved => model_lineage(observations),
        I::DatasetProvenancePreserved => dataset_provenance(observations),
        I::BomRequiredEvidencePresent => bom_completeness(observations),
    };

    if !violations.is_empty() { return SupplyChainInvariantOutcome::fail(invariant, violations); }

    let coverage = assess_coverage(invariant, observations);
    if coverage.satisfied {
        return SupplyChainInvariantOutcome::pass(invariant, format!("{} held, and the evidence needed to decide it was present", invariant.as_str()));
    }

    if !applies_to(invariant, observations) {
        return SupplyChainInvariantOutcome::inconclusive(invariant, format!("{} has no subject in this evidence, so the question does not arise", invariant.as_str()), false);
    }

    SupplyChainInvariantOutcome::inconclusive(invariant, coverage.reason, true)
}

fn applies_to(invariant: SupplyChainInvariant, observations: &ObservationSet) -> bool {
    use crate::observation::ObservationChannel as C;
    use SupplyChainInvariant as I;

    match invariant {
        I::ComponentIdentityUnambiguous
        | I::MutableReferenceNotUsedAsImmutableIdentity
        | I::ArtifactDigestBoundToComponent
        | I::BomRequiredEvidencePresent
        | I::ComponentSourceTrustPreserved => observations.has_channel(C::ComponentContext),

        // Provenance sufficiency applies to artifact-like components even when
        // the provenance channel is completely absent. Missing evidence on an
        // applicable surface is INCONCLUSIVE, never NOT_APPLICABLE.
        I::ComponentProvenanceSufficient => observations.observations.iter().any(|o| {
            matches!(o, SupplyChainObservation::ComponentContext(context) if context.expects_immutable_artifact)
        }),
        I::ProvenanceSubjectAndBuilderBound => observations.has_channel(C::ProvenanceContext),
        I::AttestationSubjectDigestPreserved => observations.has_channel(C::AttestationContext),
        I::DependencyEdgeIntegrityPreserved => observations.has_channel(C::RelationshipContext),
        I::ExternalCapabilityDriftNotObserved => observations.has_channel(C::CapabilityContext),
        I::ModelLineagePreserved => observations.has_channel(C::ModelLineageContext),
        I::DatasetProvenancePreserved => observations.has_channel(C::DatasetProvenanceContext),
    }
}

pub fn evaluate_all(observations: &ObservationSet) -> Vec<SupplyChainInvariantOutcome> {
    supported_invariants().iter().map(|invariant| evaluate(*invariant, observations)).collect()
}

pub fn collect_observed_violations(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    evaluate_all(observations).into_iter().filter(|outcome| outcome.verdict == Verdict::Fail)
        .flat_map(|outcome| outcome.violations).collect()
}

pub fn aggregate(outcomes: &[SupplyChainInvariantOutcome]) -> Verdict {
    let applicable: Vec<&SupplyChainInvariantOutcome> = outcomes.iter().filter(|outcome| outcome.applicable).collect();
    if applicable.is_empty() { return Verdict::Inconclusive; }
    for verdict in [Verdict::Fail, Verdict::Error, Verdict::Inconclusive] {
        if applicable.iter().any(|outcome| outcome.verdict == verdict) { return verdict; }
    }
    Verdict::Pass
}

fn provenance_sufficient(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::ProvenanceContext(context) = observation else { continue; };
        let component_id = context.assessment.component_id.as_str();
        let Some(component) = component_context(observations, component_id) else { continue; };
        if !component.expects_immutable_artifact { continue; }
        if !context.assessment.has_provenance() {
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::ComponentProvenanceSufficient,
                Some(component_id),
                format!("provenance evidence was read and none of it names `{component_id}`, an artifact whose class requires it"),
                &[observation],
            ));
        }
    }
    violations
}

fn capability_drift(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::CapabilityContext(context) = observation else { continue; };
        if context.assessment.drifted() == Some(true) {
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::ExternalCapabilityDriftNotObserved,
                Some(&context.assessment.component_id),
                format!("`{}` was observed with capabilities nobody approved: {}", context.assessment.component_id, context.assessment.introduced.join(", ")),
                &[observation],
            ));
        }
    }
    violations
}

fn identity_unambiguous(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let contexts: Vec<(&SupplyChainObservation, &crate::observation::ComponentContext)> = observations.observations.iter()
        .filter_map(|observation| match observation { SupplyChainObservation::ComponentContext(context) => Some((observation, context)), _ => None }).collect();
    let mut violations = Vec::new();
    for (index, (observation, context)) in contexts.iter().enumerate() {
        for (earlier_observation, earlier) in contexts.iter().take(index) {
            let same_id_different_semantics = earlier.component_id == context.component_id && earlier.semantic_key != context.semantic_key;
            let same_semantics_different_id = earlier.semantic_key == context.semantic_key && earlier.component_id != context.component_id;
            if same_id_different_semantics || same_semantics_different_id {
                violations.push(SupplyChainViolation::new(
                    SupplyChainInvariant::ComponentIdentityUnambiguous,
                    Some(&context.component_id),
                    format!("`{}` and `{}` cannot be treated as one unambiguous component identity; their id/semantic binding conflicts", earlier.component_id, context.component_id),
                    &[earlier_observation, observation],
                ));
            }
        }
    }
    violations
}

fn artifact_digest_bound(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::ComponentDigestContext(context) = observation else { continue; };
        if context.approved_digest_bound == Some(false) {
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::ArtifactDigestBoundToComponent,
                Some(&context.component_id),
                format!("the artifact observed for `{}` is not the one the manifest approved; the digests do not match", context.component_id),
                &[observation],
            ));
        }
    }
    violations
}

fn mutable_reference(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::ComponentContext(context) = observation else { continue; };
        if !context.expects_immutable_artifact || !context.uses_mutable_reference { continue; }
        if context.identity_strength.is_immutable() { continue; }
        if observations.for_component(&context.component_id).any(|other| matches!(other, SupplyChainObservation::ComponentDigestContext(_))) { continue; }
        violations.push(SupplyChainViolation::new(
            SupplyChainInvariant::MutableReferenceNotUsedAsImmutableIdentity,
            Some(&context.component_id),
            format!("`{}` is identified only by `{}`, a reference that can move under it, and no digest pins which artifact was meant", context.component_id, context.version.as_deref().unwrap_or("a mutable reference")),
            &[observation],
        ));
    }
    violations
}

fn source_trust(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::DeclaredObservedComponentContext(context) = observation else { continue; };
        if !context.comparable { continue; }
        for component_id in &context.observed_only_ids {
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::ComponentSourceTrustPreserved,
                Some(component_id),
                format!("`{component_id}` was observed in the system and the deployment never declared it, so nothing approves its presence"),
                &[observation],
            ));
        }
    }
    for observation in &observations.observations {
        let SupplyChainObservation::SourceTrustContext(context) = observation else { continue; };
        if !context.policy_present { continue; }
        if context.policy_approves_origin == Some(false) {
            let origin = context.source_id.as_deref().or(context.supplier_id.as_deref()).or(context.publisher_id.as_deref()).unwrap_or("an unnamed origin");
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::ComponentSourceTrustPreserved,
                Some(&context.component_id),
                format!("`{}` carries an origin claim including `{origin}` that local policy does not approve", context.component_id),
                &[observation],
            ));
        }
    }
    violations
}

fn provenance_bound(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::ProvenanceContext(context) = observation else { continue; };
        if !context.assessment.has_provenance() { continue; }
        let component_id = context.assessment.component_id.as_str();
        if context.assessment.digest_bound == Some(false) {
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::ProvenanceSubjectAndBuilderBound,
                Some(component_id),
                format!("provenance record(s) {} for `{component_id}` describe a different artifact than the one observed", context.assessment.misbound_provenance_ids.join(", ")),
                &[observation],
            ));
        }
        if !context.unapproved_builder_ids.is_empty() {
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::ProvenanceSubjectAndBuilderBound,
                Some(component_id),
                format!("the provenance for `{component_id}` names unapproved builder(s): {}", context.unapproved_builder_ids.iter().cloned().collect::<Vec<_>>().join(", ")),
                &[observation],
            ));
        }
    }
    violations
}

fn attestation_bound(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::AttestationContext(context) = observation else { continue; };
        let component_id = context.assessment.component_id.as_str();
        if !context.assessment.misbound_attestation_ids.is_empty() {
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::AttestationSubjectDigestPreserved,
                Some(component_id),
                format!("attestation(s) {} name `{component_id}` while binding a different artifact's digest", context.assessment.misbound_attestation_ids.join(", ")),
                &[observation],
            ));
        }
        if !context.assessment.invalid_verification_ids.is_empty() {
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::AttestationSubjectDigestPreserved,
                Some(component_id),
                format!("attestation(s) {} for `{component_id}` carry a recorded INVALID verification and cannot support trust", context.assessment.invalid_verification_ids.join(", ")),
                &[observation],
            ));
        }
        if !context.unapproved_signer_ids.is_empty() {
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::AttestationSubjectDigestPreserved,
                Some(component_id),
                format!("the attestation for `{component_id}` was signed by {}, which local policy does not approve; a valid signature is not an approved signer", context.unapproved_signer_ids.iter().cloned().collect::<Vec<_>>().join(", ")),
                &[observation],
            ));
        }
    }
    violations
}

fn dependency_integrity(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::RelationshipContext(context) = observation else { continue; };
        if !context.comparable { continue; }
        if !context.undeclared_edge_keys.is_empty() {
            violations.push(SupplyChainViolation::new(SupplyChainInvariant::DependencyEdgeIntegrityPreserved, None,
                format!("dependency edges were observed that nothing declared: {}", context.undeclared_edge_keys.join(", ")), &[observation]));
        }
        if !context.unobserved_edge_keys.is_empty() {
            violations.push(SupplyChainViolation::new(SupplyChainInvariant::DependencyEdgeIntegrityPreserved, None,
                format!("dependency edges were declared that nothing observed: {}", context.unobserved_edge_keys.join(", ")), &[observation]));
        }
    }
    violations
}

fn model_lineage(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::ModelLineageContext(context) = observation else { continue; };
        let assessment = &context.assessment;
        let component_id = assessment.component_id.as_str();
        if assessment.base_matches() == Some(false) {
            violations.push(SupplyChainViolation::new(SupplyChainInvariant::ModelLineagePreserved, Some(component_id),
                format!("`{component_id}` derives from {} and not from `{}`, the base the manifest approved", assessment.observed_base_ids.join(", "), assessment.expected_base_id.as_deref().unwrap_or("nothing")), &[observation]));
        } else if assessment.base_digest_bound == Some(false) {
            violations.push(SupplyChainViolation::new(SupplyChainInvariant::ModelLineagePreserved, Some(component_id),
                format!("`{component_id}` derives from a build of `{}` that is not the one approved", assessment.expected_base_id.as_deref().unwrap_or("its base")), &[observation]));
        }
    }
    violations
}

fn dataset_provenance(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::DatasetProvenanceContext(context) = observation else { continue; };
        let assessment = &context.assessment;
        if assessment.digest_bound == Some(false) {
            let consumers = if assessment.consuming_model_ids.is_empty() { "no model records training on it".to_owned() } else { format!("the models trained on it were {}", assessment.consuming_model_ids.join(", ")) };
            violations.push(SupplyChainViolation::new(SupplyChainInvariant::DatasetProvenancePreserved, Some(&assessment.component_id),
                format!("the dataset observed for `{}` is not the one the manifest approved, and {consumers}", assessment.component_id), &[observation]));
        }
    }
    violations
}

fn bom_completeness(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::ComponentContext(context) = observation else { continue; };
        let mut missing = Vec::new();
        if context.expects_immutable_artifact && !observations.for_component(&context.component_id)
            .any(|other| matches!(other, SupplyChainObservation::ComponentDigestContext(_))) { missing.push("an artifact digest"); }
        if context.component_type.expects_lineage() && !observations.for_component(&context.component_id)
            .any(|other| matches!(other, SupplyChainObservation::ModelLineageContext(_))) { missing.push("model lineage evidence"); }
        if context.component_type == ComponentType::Dataset && !observations.for_component(&context.component_id)
            .any(|other| matches!(other, SupplyChainObservation::DatasetProvenanceContext(_))) { missing.push("dataset provenance evidence"); }
        if !missing.is_empty() {
            violations.push(SupplyChainViolation::new(SupplyChainInvariant::BomRequiredEvidencePresent, Some(&context.component_id),
                format!("the bill of materials describes `{}` as a {} without {}", context.component_id, context.component_type.as_str(), missing.join(" or ")), &[observation]));
        }
    }
    violations
}

fn component_context<'a>(observations: &'a ObservationSet, component_id: &str) -> Option<&'a crate::observation::ComponentContext> {
    observations.observations.iter().find_map(|observation| match observation {
        SupplyChainObservation::ComponentContext(context) if context.component_id == component_id => Some(context),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::tests::attestation;
    use crate::budget::AdmissionLedger;
    use crate::component::tests::{component, digest};
    use crate::manifest::{ApprovedComponent, DareManifest, TrustPolicy};
    use crate::normalize::EvidenceBuilder;
    use crate::observation::project;
    use crate::provenance::tests::record;
    use crate::relationship::RelationshipGraph;
    use crate::source::{ComponentType, VerificationStatus};
    use std::collections::BTreeSet;

    fn approved_manifest() -> DareManifest {
        DareManifest {
            schema_version: "1".to_owned(),
            trust_policy: TrustPolicy {
                approved_suppliers: BTreeSet::from(["acme".to_owned()]),
                approved_builders: BTreeSet::from(["builder-ci".to_owned()]),
                approved_signers: BTreeSet::from(["signer-release".to_owned()]),
                ..Default::default()
            },
            approved_components: BTreeSet::from([ApprovedComponent {
                component_id: "react".to_owned(), name: None, version: None,
                digests: BTreeSet::from([digest("a")]),
            }]),
            declared_component_ids: BTreeSet::from(["react".to_owned()]),
            ..Default::default()
        }
    }

    fn compliant() -> crate::normalize::SupplyChainEvidence {
        let mut package = component("react", ComponentType::Package);
        package.supplier.supplier_id = Some("acme".to_owned());
        let mut ledger = AdmissionLedger::new();
        EvidenceBuilder::new().with_document("bom", crate::normalize::BomFormat::CycloneDx, b"{}")
            .with_import(vec![package], RelationshipGraph::new())
            .with_provenance(vec![record("prov-1", "react")])
            .with_attestations(vec![attestation("att-1", "react")])
            .with_manifest(approved_manifest()).build(&mut ledger).expect("builds")
    }

    #[test]
    fn compliant_bundle_passes_its_decidable_security_boundaries() {
        let observations = project(&compliant());
        for invariant in [
            SupplyChainInvariant::ComponentProvenanceSufficient,
            SupplyChainInvariant::ComponentIdentityUnambiguous,
            SupplyChainInvariant::ArtifactDigestBoundToComponent,
            SupplyChainInvariant::ComponentSourceTrustPreserved,
            SupplyChainInvariant::ProvenanceSubjectAndBuilderBound,
            SupplyChainInvariant::AttestationSubjectDigestPreserved,
        ] {
            assert_eq!(evaluate(invariant, &observations).verdict, Verdict::Pass, "{}", invariant.as_str());
        }
    }

    #[test]
    fn missing_provenance_on_an_artifact_is_applicable_and_inconclusive() {
        let mut evidence = compliant();
        evidence.provenance.clear();
        let observations = project(&evidence);
        let outcome = evaluate(SupplyChainInvariant::ComponentProvenanceSufficient, &observations);
        assert_eq!(outcome.verdict, Verdict::Inconclusive);
        assert!(outcome.applicable);
        assert_eq!(aggregate(&evaluate_all(&observations)), Verdict::Inconclusive);
    }

    #[test]
    fn missing_source_claim_on_a_component_is_applicable_and_inconclusive() {
        let mut evidence = compliant();
        evidence.components[0].supplier = Default::default();
        let observations = project(&evidence);
        let outcome = evaluate(SupplyChainInvariant::ComponentSourceTrustPreserved, &observations);
        assert_eq!(outcome.verdict, Verdict::Inconclusive);
        assert!(outcome.applicable);
    }

    #[test]
    fn same_component_id_with_conflicting_digest_fails_identity_and_integrity() {
        let first = component("react", ComponentType::Package);
        let mut second = component("react", ComponentType::Package);
        second.digests = BTreeSet::from([digest("b")]);
        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new().with_import(vec![first], RelationshipGraph::new())
            .with_import(vec![second], RelationshipGraph::new()).with_manifest(approved_manifest())
            .build(&mut ledger).expect("builds");
        let observations = project(&evidence);
        assert_eq!(evaluate(SupplyChainInvariant::ComponentIdentityUnambiguous, &observations).verdict, Verdict::Fail);
        assert_eq!(evaluate(SupplyChainInvariant::ArtifactDigestBoundToComponent, &observations).verdict, Verdict::Fail);
    }

    #[test]
    fn conflicting_provenance_cannot_be_hidden_by_good_provenance() {
        let mut evidence = compliant();
        let mut bad = record("prov-bad", "react");
        bad.subject_digests = BTreeSet::from([digest("b")]);
        bad.builder_id = Some("builder-evil".to_owned());
        evidence.provenance.push(bad);
        let outcome = evaluate(SupplyChainInvariant::ProvenanceSubjectAndBuilderBound, &project(&evidence));
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations.len() >= 2);
    }

    #[test]
    fn invalid_attestation_verification_fails_even_beside_a_valid_one() {
        let mut evidence = compliant();
        let mut invalid = attestation("att-invalid", "react");
        invalid.verification_status = VerificationStatus::Invalid;
        evidence.attestations.push(invalid);
        let outcome = evaluate(SupplyChainInvariant::AttestationSubjectDigestPreserved, &project(&evidence));
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations.iter().any(|v| v.reason.contains("INVALID")));
    }

    #[test]
    fn indeterminate_attestation_verification_is_inconclusive_not_pass() {
        let mut evidence = compliant();
        evidence.attestations[0].verification_status = VerificationStatus::Indeterminate;
        let outcome = evaluate(SupplyChainInvariant::AttestationSubjectDigestPreserved, &project(&evidence));
        assert_eq!(outcome.verdict, Verdict::Inconclusive);
        assert!(outcome.applicable);
    }

    #[test]
    fn an_approved_supplier_does_not_mask_an_unapproved_source() {
        let mut evidence = compliant();
        evidence.components[0].supplier.source_id = Some("registry-evil".to_owned());
        let outcome = evaluate(SupplyChainInvariant::ComponentSourceTrustPreserved, &project(&evidence));
        assert_eq!(outcome.verdict, Verdict::Fail);
    }

    #[test]
    fn empty_run_is_inconclusive() {
        assert_eq!(aggregate(&evaluate_all(&ObservationSet::default())), Verdict::Inconclusive);
    }

    #[test]
    fn registry_still_contains_exactly_twelve_evaluators() {
        assert_eq!(supported_invariants().len(), 12);
    }
}
